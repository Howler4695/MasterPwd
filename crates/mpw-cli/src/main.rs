//! `mpw`: the Master Password command-line client.
//!
//! Option- and environment-compatible with the reference `mpw-cli.c`,
//! including its user files in `~/.mpw.d`.  The result is the only thing
//! written to stdout; prompts, the identicon and diagnostics go to stderr.
//! See `args.rs`, `input.rs`, `store.rs` and `operation.rs` for the
//! deliberate deviations from the reference.

#![forbid(unsafe_code)]

mod args;
mod input;
mod log;
mod operation;
mod second_factor;
mod store;

use log::{dbg_log, Fatal};
use mpw_core::{identicon, AlgorithmVersion, Counter, Identicon, KeyPurpose, ResultType};
use std::io::{IsTerminal, Write};
use zeroize::Zeroizing;

// sysexits.h
pub const EX_OK: i32 = 0;
pub const EX_USAGE: i32 = 64;
pub const EX_DATAERR: i32 = 65;
pub const EX_SOFTWARE: i32 = 70;
pub const EX_CANTCREAT: i32 = 73;
pub const EX_IOERR: i32 = 74;

/// The reference re-prompts forever on empty answers; we give up eventually
/// (an EOF on a terminal can look like an empty answer).
const MAX_EMPTY_ANSWERS: usize = 5;

const ENV_FULL_NAME: &str = "MPW_FULLNAME";
const ENV_ALGORITHM: &str = "MPW_ALGORITHM";
const ENV_FORMAT: &str = "MPW_FORMAT";
const ENV_ASKPASS: &str = "MPW_ASKPASS";

fn main() {
    let code = match run() {
        Ok(()) => EX_OK,
        Err(fatal) => {
            fatal.report();
            fatal.code
        }
    };
    std::process::exit(code);
}

fn run() -> Result<(), Fatal> {
    let mut args = args::parse(std::env::args_os().skip(1))?;
    log::set_verbosity(args.verbosity);
    if args.help {
        usage();
        return Ok(());
    }

    // Environment defaults (command-line options win).
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    if args.full_name.is_none() {
        args.full_name = env(ENV_FULL_NAME);
    }
    if args.algorithm_version.is_none() {
        args.algorithm_version = env(ENV_ALGORITHM);
    }
    if args.sites_format.is_none() {
        args.sites_format = env(ENV_FORMAT);
    }
    if std::env::var_os(ENV_ASKPASS).is_some() {
        dbg_log!("{ENV_ASKPASS} is not supported and is ignored; prompting on the terminal.");
    }

    // Parameters not sourced from the user file (same order as the reference).
    let full_name = full_name(&args)?;
    let master_password = master_password(&args)?;
    let site_name = site_name(&args)?;
    let files = store::Options::parse(
        args.sites_format.as_deref(),
        args.sites_format_fixed,
        args.sites_redacted.as_deref(),
    )?;
    let purpose = match &args.key_purpose {
        None => KeyPurpose::Authentication,
        Some(p) => KeyPurpose::from_name(p)
            .ok_or_else(|| Fatal::new(EX_DATAERR, format!("Invalid purpose: {p}")))?,
    };
    let key_context = args.key_context.clone();

    // Command-line overrides, validated before any expensive work.
    let result_type = match &args.result_type {
        None => None,
        Some(t) => Some(
            ResultType::from_name(t)
                .ok_or_else(|| Fatal::new(EX_USAGE, format!("Invalid type: {t}")))?,
        ),
    };
    let counter = match &args.site_counter {
        None => None,
        Some(c) => Some(
            parse_counter(c)
                .ok_or_else(|| Fatal::new(EX_USAGE, format!("Invalid site counter: {c}")))?,
        ),
    };
    let algorithm = match &args.algorithm_version {
        None => None,
        Some(a) => Some(
            a.trim()
                .parse::<u32>()
                .ok()
                .and_then(AlgorithmVersion::from_u32)
                .ok_or_else(|| Fatal::new(EX_USAGE, format!("Invalid algorithm version: {a}")))?,
        ),
    };

    let identicon = identicon(&full_name, &master_password);

    let request = operation::Request {
        full_name: full_name.clone(),
        site_name: site_name.clone(),
        purpose,
        key_context,
        result_type,
        counter,
        algorithm,
        result_param: args.result_param.take().map(Zeroizing::new),
        allow_password_update: args.allow_password_update,
        recovery_code_fd: args.recovery_code_fd.take(),
        files,
    };
    operation::run(request, master_password, |outcome| {
        if log::enabled(log::LEVEL_INFO) {
            eprint!(
                "{full_name}'s {} for {site_name}:\n[ {} ]: ",
                outcome.purpose_result,
                render_identicon(&identicon)
            );
            let _ = std::io::stderr().flush();
        }
        write_result(&outcome.result)
    })
}

fn full_name(args: &args::Arguments) -> Result<String, Fatal> {
    if let Some(name) = &args.full_name {
        return Ok(name.clone());
    }
    for _ in 0..MAX_EMPTY_ANSWERS {
        match input::getline("Your full name:") {
            Some(name) if !name.is_empty() => return Ok(name),
            Some(_) => continue,
            None => break,
        }
    }
    Err(Fatal::new(EX_DATAERR, "Missing full name."))
}

fn master_password(args: &args::Arguments) -> Result<Zeroizing<String>, Fatal> {
    if let Some(fd) = &args.master_password_fd {
        if let Some(password) = input::read_fd(fd)?.filter(|p| !p.is_empty()) {
            return Ok(password);
        }
    }
    for _ in 0..MAX_EMPTY_ANSWERS {
        match input::getpass("Your master password: ")? {
            Some(password) if !password.is_empty() => return Ok(password),
            Some(_) => continue,
            None => break,
        }
    }
    Err(Fatal::new(EX_DATAERR, "Missing master password."))
}

fn site_name(args: &args::Arguments) -> Result<String, Fatal> {
    if let Some(site) = &args.site_name {
        return Ok(site.clone());
    }
    input::getline("Site name:")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Fatal::new(EX_DATAERR, "Missing site name."))
}

/// `strtoll(value, NULL, 0)` for the accepted range, but strict: the whole
/// string must be a number (decimal, `0x` hex or `0` octal, like the
/// reference); garbage is rejected instead of silently becoming 0 (= TOTP).
fn parse_counter(value: &str) -> Option<Counter> {
    let v = value.trim();
    let v = v.strip_prefix('+').unwrap_or(v);
    let (digits, radix) = if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        (hex, 16)
    } else if v.len() > 1 && v.starts_with('0') {
        (&v[1..], 8)
    } else {
        (v, 10)
    };
    if digits.is_empty() || digits.starts_with(['+', '-']) {
        return None;
    }
    u32::from_str_radix(digits, radix).ok()
}

/// The identicon, coloured with ANSI `setaf` when stderr is a terminal.
fn render_identicon(identicon: &Identicon) -> String {
    if std::io::stderr().is_terminal() {
        format!(
            "\x1b[3{}m{}\x1b[0m",
            identicon.color as u8,
            identicon.text()
        )
    } else {
        identicon.text()
    }
}

/// Write the result to stdout through an unbuffered handle, so no copy of it
/// stays in Rust's global stdout buffer.
fn write_result(result: &str) -> Result<(), Fatal> {
    use std::os::fd::AsFd;
    let io_err =
        |e: std::io::Error| Fatal::new(EX_IOERR, format!("Couldn't write the result: {e}"));
    let stdout = std::io::stdout();
    let mut out = std::fs::File::from(stdout.as_fd().try_clone_to_owned().map_err(io_err)?);
    let mut line = Zeroizing::new(String::with_capacity(result.len() + 1));
    line.push_str(result);
    line.push('\n');
    out.write_all(line.as_bytes()).map_err(io_err)?;
    out.flush().map_err(io_err)
}

fn usage() {
    eprintln!(
        "  Master Password v{version} - CLI
--------------------------------------------------------------------------------
      https://masterpassword.app

USAGE

  mpw [-u|-U full-name] [-m fd] [-k fd] [-t pw-type] [-P value] [-c counter]
      [-a version] [-p purpose] [-C context] [-f|F format] [-R 0|1]
      [-v|-q]* [-h] [site-name]

  -u full-name Specify the full name of the user.
               -u checks the master password against the config,
               -U allows updating to a new master password (the old one is
               asked for, stored values are re-encrypted).
               Defaults to {ENV_FULL_NAME} in env or prompts.

  -m fd        Read the master password of the user from a file descriptor.
               The whole content is used, including any trailing newline:
               use printf, not echo.  Without -m, the password is prompted for
               on the terminal (no echo), or read as one line from stdin when
               stdin is not a terminal.
               (The reference's -M is not supported: never put a master
               password on the command line.)

  -k fd        Read the recovery code of a user with a second factor from a
               file descriptor (whole content; spaces, dashes and newlines
               are ignored).  See SECOND FACTOR below.

  -t pw-type   Specify the password's template.
               Defaults to 'long' (-p a), 'name' (-p i) or 'phrase' (-p r).
                   x, maximum  | 20 characters, contains symbols.
                   l, long     | Copy-friendly, 14 characters, symbols.
                   m, medium   | Copy-friendly, 8 characters, symbols.
                   b, basic    | 8 characters, no symbols.
                   s, short    | Copy-friendly, 4 characters, no symbols.
                   i, pin      | 4 numbers.
                   n, name     | 9 letter name.
                   p, phrase   | 20 character sentence.
                   K, key      | encryption key (512 bit or -P bits).
                   P, personal | saved personal password (asked for, see -P).

  -P value     The parameter value.
                   -p i        | The login name for the site.
                   -t K        | The bit size of the key to generate (eg. 256).
                   -t P        | The personal password to encrypt.
               For -t P (and personal login names / answers), prefer omitting
               -P: the value is then asked for with echo off (twice), or read
               as one line from stdin when stdin is not a terminal.  A value
               given with -P is visible to other users (ps) and in shell
               history.  -P - also asks for it (to change a stored value).

  -c counter   The value of the counter.
               Defaults to 1.  0 means a time-based (TOTP) counter.

  -a version   The algorithm version to use, {first} - {last}.
               Defaults to env var {ENV_ALGORITHM} or {current}.

  -p purpose   The purpose of the generated token.
               Defaults to 'auth'.
                   a, auth     | An authentication token such as a password.
                   i, ident    | An identification token such as a username.
                   r, rec      | A recovery token such as a security answer.

  -C context   A purpose-specific context.
               Defaults to empty.
                   -p a        | -
                   -p i        | -
                   -p r        | Most significant word in security question.

  -f|F format  The file format to use for reading/writing user state.
               -f reads the given format, allows fall-back & writes the default format (json).
               -F reads & writes only the given format.
               Defaults to env var {ENV_FORMAT} or the default format (json).
                   n, none     | No file
                   f, flat     | ~/.mpw.d/Full Name.mpsites
                   j, json     | ~/.mpw.d/Full Name.mpjson
               Files are written atomically, mode 0600, in a 0700 directory.
               '/' and a leading '.' in the name become '_'.

  -R redacted  Whether to save the user file in redacted format or not.
               Redaction omits or encrypts any secrets, making the file safe
               for saving on or transmitting via untrusted media.
               Defaults to 1, redacted: a clear-text file is only written
               when -R 0 is given explicitly.

  -v           Increase output verbosity (can be repeated).
  -q           Decrease output verbosity (can be repeated).

  -h           Show this help output instead of performing any operation.

  site-name    Name of the site for which to generate a token.

SECOND FACTOR

  A user can enable a second factor (e.g. a CAC/PIV smart card) in the
  MasterPwd app; enabling, disabling, rotating it and enrolling cards is
  done in the app only.  Such a user's master password is effectively
  `password RECOVERY-CODE` (the code shown once when it was enabled).  This
  command has no card support; it unlocks such a user with the recovery
  code, given with -k fd, typed at the prompt (on a terminal), or appended
  to the master password after one space.  The code is checked before
  anything else, so a mistyped code is reported as such.  -U keeps the
  second factor.  These users cannot be saved in the flat format.

EXIT STATUS

  0 success; 64 usage error; 65 bad input or wrong master password;
  66 recovery code needed but not given; 67 recovery code mistyped;
  77 recovery code valid but not this user's; 70 internal error;
  73 user file could not be written; 74 I/O error.

ENVIRONMENT

  {ENV_FULL_NAME:<12} The full name of the user (see -u).
  {ENV_ALGORITHM:<12} The default algorithm version (see -a).
  {ENV_FORMAT:<12} The default mpsites format (see -f).
  ({ENV_ASKPASS} is not supported.)",
        version = env!("CARGO_PKG_VERSION"),
        first = AlgorithmVersion::FIRST.as_u32(),
        last = AlgorithmVersion::LAST.as_u32(),
        current = AlgorithmVersion::CURRENT.as_u32(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters() {
        assert_eq!(parse_counter("1"), Some(1));
        assert_eq!(parse_counter("0"), Some(0));
        assert_eq!(parse_counter("4294967295"), Some(u32::MAX));
        assert_eq!(parse_counter("0x10"), Some(16));
        assert_eq!(parse_counter("010"), Some(8));
        assert_eq!(parse_counter("4294967296"), None);
        assert_eq!(parse_counter("-1"), None);
        assert_eq!(parse_counter("abc"), None);
        assert_eq!(parse_counter("1x"), None);
        assert_eq!(parse_counter("0x"), None);
        assert_eq!(parse_counter("0x-1"), None);
    }
}
