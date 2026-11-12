//! `mpw`: the Master Password command-line client.
//!
//! Option- and environment-compatible with the reference `mpw-cli.c` for the
//! stateless path.  The result is the only thing written to stdout; prompts,
//! the identicon and diagnostics go to stderr.  See `args.rs`, `input.rs` and
//! `store.rs` for the deliberate deviations from the reference.

#![forbid(unsafe_code)]

mod args;
mod input;
mod log;
mod store;

use log::{dbg_log, inf, wrn, Fatal};
use mpw_core::{
    identicon, AlgorithmVersion, Counter, Identicon, KeyPurpose, MasterKey, ResultType,
    COUNTER_DEFAULT, COUNTER_INITIAL,
};
use std::io::{IsTerminal, Write};
use zeroize::Zeroizing;

// sysexits.h
pub const EX_OK: i32 = 0;
pub const EX_USAGE: i32 = 64;
pub const EX_DATAERR: i32 = 65;
pub const EX_SOFTWARE: i32 = 70;
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

    // SEAM (cli_user/cli_site/cli_question/cli_operation): stored defaults.
    let stored = store::load(&files, &full_name, &site_name).unwrap_or_default();
    let (purpose_result, default_type) = match purpose {
        KeyPurpose::Authentication => ("password", ResultType::DEFAULT),
        KeyPurpose::Identification => ("login", ResultType::DEFAULT_LOGIN),
        KeyPurpose::Recovery => ("answer", ResultType::DEFAULT_ANSWER),
    };
    let mut result_type = stored.result_type.unwrap_or(default_type);
    let mut counter = match purpose {
        KeyPurpose::Authentication => stored.counter.unwrap_or(COUNTER_DEFAULT),
        // The reference always uses the initial counter for logins and answers.
        KeyPurpose::Identification | KeyPurpose::Recovery => COUNTER_INITIAL,
    };
    let mut algorithm = stored.algorithm.unwrap_or(AlgorithmVersion::CURRENT);
    let mut result_state = stored.state;

    // Command-line overrides.
    if let Some(t) = &args.result_type {
        result_type = ResultType::from_name(t)
            .ok_or_else(|| Fatal::new(EX_USAGE, format!("Invalid type: {t}")))?;
    }
    if let Some(c) = &args.site_counter {
        let value = parse_counter(c)
            .ok_or_else(|| Fatal::new(EX_USAGE, format!("Invalid site counter: {c}")))?;
        match purpose {
            KeyPurpose::Authentication => counter = value,
            _ => wrn!(
                "The counter is ignored for {} (like the reference, it is always 1).",
                purpose
            ),
        }
    }
    if let Some(a) = &args.algorithm_version {
        algorithm = a
            .trim()
            .parse::<u32>()
            .ok()
            .and_then(AlgorithmVersion::from_u32)
            .ok_or_else(|| Fatal::new(EX_USAGE, format!("Invalid algorithm version: {a}")))?;
    }
    let mut result_param = args.result_param.take().map(Zeroizing::new);

    dbg_log!("-----------------");
    dbg_log!("fullName         : {full_name}");
    dbg_log!("siteName         : {site_name}");
    dbg_log!("siteCounter      : {counter}");
    dbg_log!(
        "resultType       : {} ({})",
        result_type.short_name(),
        result_type.as_u32()
    );
    dbg_log!(
        "resultParam      : {}",
        if result_param.is_some() {
            "(given)"
        } else {
            "(none)"
        }
    );
    dbg_log!("keyPurpose       : {} ({})", purpose, purpose as u8);
    dbg_log!(
        "keyContext       : {}",
        key_context.as_deref().unwrap_or("(none)")
    );
    dbg_log!("algorithmVersion : {}", algorithm.as_u32());
    dbg_log!(
        "sitesFormat      : {:?}{}",
        files.format,
        if files.format_fixed { " (fixed)" } else { "" }
    );
    dbg_log!("-----------------");

    // cli_mpw
    let identicon = identicon(&full_name, &master_password);
    if log::enabled(log::LEVEL_INFO) {
        eprint!(
            "{full_name}'s {purpose_result} for {site_name}:\n[ {} ]: ",
            render_identicon(&identicon)
        );
        let _ = std::io::stderr().flush();
    }

    // SEAM: with a user file, derive the key for the *user's* algorithm first
    // and compare its key ID with the stored one (constant time) before going on.
    let master_key = MasterKey::derive(&full_name, &master_password, algorithm)
        .map_err(|e| Fatal::new(EX_SOFTWARE, format!("Couldn't derive master key: {e}")))?;
    drop(master_password);

    // Stateful types: -P is the value to encrypt; the state then feeds the result.
    let mut new_state = None;
    if let Some(param) = result_param.as_ref().filter(|_| result_type.is_stateful()) {
        let state = master_key
            .site_state(
                &site_name,
                counter,
                purpose,
                key_context.as_deref(),
                result_type,
                param,
            )
            .map_err(|e| Fatal::new(EX_SOFTWARE, format!("Couldn't encrypt site result: {e}")))?;
        inf!("(state) {state} => ");
        result_state = Some(state.clone());
        new_state = Some(state);
        result_param = None;
    }
    if result_param.is_none() {
        result_param = result_state.map(Zeroizing::new);
    }

    let result = master_key
        .site_result(
            &site_name,
            counter,
            purpose,
            key_context.as_deref(),
            result_type,
            result_param.as_ref().map(|p| p.as_str()),
        )
        .map_err(|e| Fatal::new(EX_SOFTWARE, format!("Couldn't generate site result: {e}")))?;
    drop(master_key);
    write_result(&result)?;

    // SEAM (cli_save).
    store::save(&files, &full_name, &site_name, new_state.as_deref());
    Ok(())
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

  mpw [-u|-U full-name] [-m fd] [-t pw-type] [-P value] [-c counter]
      [-a version] [-p purpose] [-C context] [-f|F format] [-R 0|1]
      [-v|-q]* [-h] [site-name]

  -u full-name Specify the full name of the user.
               -u checks the master password against the config,
               -U allows updating to a new master password.
               Defaults to {ENV_FULL_NAME} in env or prompts.

  -m fd        Read the master password of the user from a file descriptor.
               The whole content is used, including any trailing newline:
               use printf, not echo.  Without -m, the password is prompted for
               on the terminal (no echo), or read as one line from stdin when
               stdin is not a terminal.
               (The reference's -M is not supported: never put a master
               password on the command line.)

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
                   P, personal | saved personal password (save with -P pw).

  -P value     The parameter value.
                   -p i        | The login name for the site.
                   -t K        | The bit size of the key to generate (eg. 256).
                   -t P        | The personal password to encrypt.

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
               (Not supported by this build yet: it works statelessly.)
                   n, none     | No file
                   f, flat     | ~/.mpw.d/Full Name.mpsites
                   j, json     | ~/.mpw.d/Full Name.mpjson

  -R redacted  Whether to save the mpsites in redacted format or not.
               (Not supported by this build yet.)

  -v           Increase output verbosity (can be repeated).
  -q           Decrease output verbosity (can be repeated).

  -h           Show this help output instead of performing any operation.

  site-name    Name of the site for which to generate a token.

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
