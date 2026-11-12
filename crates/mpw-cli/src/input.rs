//! Reading the full name, site name and master password.
//!
//! * Non-secret lines are read from stdin **unbuffered** (one byte at a time
//!   through a `dup` of fd 0), so that no input beyond the current line is
//!   consumed and no copy lingers in a process-wide buffer.
//! * The master password is read
//!   - from the `-m fd` descriptor (exact bytes, like the reference), else
//!   - from the terminal with echo off (`rpassword`, via `/dev/tty`) when stdin
//!     is a terminal, else
//!   - as one line from stdin.
//!
//! Secret buffers are `Zeroizing` and grown by explicit copy (never by
//! `Vec` reallocation), so no stale copy is left behind on the heap.
//!
//! `MPW_ASKPASS` is intentionally not supported: running an arbitrary helper
//! named by the environment is an injection risk and needs process plumbing
//! the stateless CLI does not need.

use crate::log::{wrn, Fatal};
use crate::{EX_DATAERR, EX_USAGE};
use std::fs::File;
use std::io::{ErrorKind, IsTerminal, Read, Write};
use zeroize::Zeroizing;

/// Upper bound for anything we read; guards against unbounded input.
const MAX_INPUT: usize = 64 * 1024;

/// Reads `fd` until EOF (or `stop` byte, which is consumed but not kept) into
/// a zeroizing buffer.  Returns `None` on immediate EOF.
fn read_secret_bytes(
    reader: &mut impl Read,
    stop: Option<u8>,
) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut buf = Zeroizing::new(Vec::with_capacity(256));
    let mut got_any = false;
    let mut chunk = Zeroizing::new([0u8; 1]);
    loop {
        match reader.read(chunk.as_mut_slice()) {
            Ok(0) => break,
            Ok(_) => {
                got_any = true;
                if Some(chunk[0]) == stop {
                    break;
                }
                if buf.len() == buf.capacity() {
                    if buf.len() >= MAX_INPUT {
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "input too long",
                        ));
                    }
                    // Grow by copying into a fresh buffer; the old one is
                    // wiped when it drops.
                    let mut bigger = Zeroizing::new(Vec::with_capacity(buf.capacity() * 2));
                    bigger.extend_from_slice(&buf);
                    buf = bigger;
                }
                buf.push(chunk[0]);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(got_any.then_some(buf))
}

fn into_secret_string(bytes: Zeroizing<Vec<u8>>, what: &str) -> Result<Zeroizing<String>, Fatal> {
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Fatal::new(EX_DATAERR, format!("The {what} is not valid UTF-8.")))?;
    let mut s = Zeroizing::new(String::with_capacity(text.len()));
    s.push_str(text);
    Ok(s)
}

/// Strip a trailing `\r` (the `\n` itself is consumed by the line reader).
fn chomp(bytes: &mut Zeroizing<Vec<u8>>) {
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
}

/// An unbuffered handle on stdin: a `dup` of fd 0, sharing its offset.
fn stdin_raw() -> Option<File> {
    use std::os::fd::AsFd;
    std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .ok()
        .map(File::from)
}

/// Prompt on stderr and read one line from stdin.  `None` on EOF or error.
pub fn getline(prompt: &str) -> Option<String> {
    eprint!("{prompt} ");
    let _ = std::io::stderr().flush();
    let mut stdin = stdin_raw()?;
    let mut line = read_secret_bytes(&mut stdin, Some(b'\n')).ok()??;
    chomp(&mut line);
    std::str::from_utf8(&line).ok().map(str::to_owned)
}

/// Prompt for the master password.  `None` on EOF.
pub fn getpass(prompt: &str) -> Result<Option<Zeroizing<String>>, Fatal> {
    if std::io::stdin().is_terminal() {
        return match rpassword::prompt_password(prompt) {
            Ok(password) => Ok(Some(Zeroizing::new(password))),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(Fatal::new(
                EX_DATAERR,
                format!("Couldn't read the master password from the terminal: {e}"),
            )),
        };
    }

    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let Some(mut stdin) = stdin_raw() else {
        return Ok(None);
    };
    match read_secret_bytes(&mut stdin, Some(b'\n')) {
        Ok(Some(mut line)) => {
            chomp(&mut line);
            into_secret_string(line, "master password").map(Some)
        }
        Ok(None) => Ok(None),
        Err(e) => Err(Fatal::new(
            EX_DATAERR,
            format!("Couldn't read the master password: {e}"),
        )),
    }
}

/// Prompt for a value to store for a stateful result type (a personal
/// password, login name or answer), so it never has to go on the command line.
///
/// On a terminal: echo off, asked twice, must match.  Otherwise: one line from
/// stdin.  Empty input or EOF is an error.
pub fn get_secret_value(what: &str) -> Result<Zeroizing<String>, Fatal> {
    let missing = || Fatal::new(EX_DATAERR, format!("Missing {what}."));
    if !std::io::stdin().is_terminal() {
        return getpass(&format!("Your {what}: "))?
            .filter(|v| !v.is_empty())
            .ok_or_else(missing);
    }
    for _ in 0..3 {
        let Some(first) = getpass(&format!("Your {what}: "))?.filter(|v| !v.is_empty()) else {
            return Err(missing());
        };
        let second = getpass(&format!("Your {what} (again): "))?.ok_or_else(missing)?;
        if *first == *second {
            return Ok(first);
        }
        eprintln!("The two entries do not match; try again.");
    }
    Err(Fatal::new(
        EX_DATAERR,
        format!("The {what} entries did not match."),
    ))
}

/// Read the master password from file descriptor `fd` (the `-m` option).
///
/// Compatibility: the whole content is used verbatim, including any trailing
/// newline (the reference documents "use printf, not echo").  Returns `None`
/// when the descriptor is empty or unreadable, after a warning, so the caller
/// falls back to prompting like the reference.
pub fn read_fd(fd: &str) -> Result<Option<Zeroizing<String>>, Fatal> {
    read_fd_secret(fd, "master password")
}

/// Read a secret (`what`, for messages) from file descriptor `fd`: the whole
/// content, up to EOF.  `None` (after a warning) when empty or unreadable.
pub fn read_fd_secret(fd: &str, what: &str) -> Result<Option<Zeroizing<String>>, Fatal> {
    let fd: u32 = fd
        .trim()
        .parse()
        .map_err(|_| Fatal::new(EX_USAGE, format!("Invalid file descriptor: {fd}")))?;
    let mut file = match File::open(format!("/dev/fd/{fd}")) {
        Ok(f) => f,
        Err(e) => {
            wrn!("Error reading the {what} from FD {fd}: {e}");
            return Ok(None);
        }
    };
    match read_secret_bytes(&mut file, None) {
        Ok(Some(bytes)) => into_secret_string(bytes, what).map(Some),
        Ok(None) => Ok(None),
        Err(e) => {
            wrn!("Error reading the {what} from FD {fd}: {e}");
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_lines_and_grows_without_losing_bytes() {
        let long = "x".repeat(1000);
        let input = format!("first\r\n{long}\nlast");
        let mut r = input.as_bytes();
        let mut a = read_secret_bytes(&mut r, Some(b'\n')).unwrap().unwrap();
        chomp(&mut a);
        assert_eq!(&a[..], b"first");
        let b = read_secret_bytes(&mut r, Some(b'\n')).unwrap().unwrap();
        assert_eq!(&b[..], long.as_bytes());
        let c = read_secret_bytes(&mut r, Some(b'\n')).unwrap().unwrap();
        assert_eq!(&c[..], b"last");
        assert!(read_secret_bytes(&mut r, Some(b'\n')).unwrap().is_none());
    }

    #[test]
    fn empty_line_is_some_empty() {
        let mut r: &[u8] = b"\n";
        let line = read_secret_bytes(&mut r, Some(b'\n')).unwrap().unwrap();
        assert!(line.is_empty());
    }

    #[test]
    fn caps_input() {
        let big = vec![b'a'; MAX_INPUT * 2];
        assert!(read_secret_bytes(&mut big.as_slice(), None).is_err());
    }
}
