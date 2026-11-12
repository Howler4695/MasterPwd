//! Unlocking a user that has the opt-in second factor (see
//! `mpw_model::second_factor`): the CLI has no smart-card support and never
//! will; it is the *recovery* path, using the printed recovery code.
//!
//! The effective master password is `typed password + " " + recovery code`.
//! The code is obtained, in this order:
//!
//! 1. `-k fd`: read from that file descriptor (never from argv or the
//!    environment); the typed master password is then the password alone;
//! 2. the combined form: the typed master password already ends with
//!    `" " + code` (what worked before this support existed);
//! 3. on a terminal: prompted for with echo off.
//!
//! The code is checked (format, checksum, and that it is this user's) before
//! any key derivation, so a mistyped or foreign code is reported as such and
//! not as a wrong master password.

use crate::input;
use crate::log::{inf, wrn, Fatal};
use mpw_model::{SecondFactorStatus, SecondSecret};
use std::io::IsTerminal;
use zeroize::Zeroizing;

/// Exit status: the user has a second factor but no recovery code was given.
pub const EX_CODE_MISSING: i32 = 66; // EX_NOINPUT
/// Exit status: the recovery code is malformed or fails its checksum.
pub const EX_CODE_MISTYPED: i32 = 67;
/// Exit status: a well-formed recovery code that is not this user's.
pub const EX_CODE_FOREIGN: i32 = 77; // EX_NOPERM

/// How to supply the code, for error messages.
pub const HOW: &str = "give the recovery code with -k fd or at the prompt (on a terminal), \
                       or type the master password as `password RECOVERY-CODE`";

/// The unlock material of a second-factor user (build the key holder with
/// `UserKeys::from_password_and_secret(name, &typed, &secret)`).
pub struct Unlock {
    /// The typed master password without the code.
    pub typed: Zeroizing<String>,
    pub secret: SecondSecret,
}

/// Get and pre-check the recovery code.
pub fn unlock(
    typed: &Zeroizing<String>,
    status: &SecondFactorStatus,
    code_fd: Option<&str>,
) -> Result<Unlock, Fatal> {
    inf!("This user has a second factor (e.g. a smart card).  Without the card, it is unlocked with the recovery code.");
    if matches!(status, SecondFactorStatus::Unreadable) {
        wrn!("Its second-factor data is from a newer version or damaged; it is kept unchanged, and the recovery code cannot be checked before unlocking.");
    }

    let (typed, secret) = if let Some(fd) = code_fd {
        let code = input::read_fd_secret(fd, "recovery code")?
            .filter(|c| !c.trim().is_empty())
            .ok_or_else(|| missing(&format!("nothing could be read from FD {}", fd.trim())))?;
        (typed.clone(), check(status, &code)?)
    } else if let Some((prefix, secret)) = combined(status, typed)? {
        (prefix, secret)
    } else if std::io::stdin().is_terminal() {
        let code = input::getpass("Recovery code: ")?
            .filter(|c| !c.trim().is_empty())
            .ok_or_else(|| missing("none was entered"))?;
        (typed.clone(), check(status, &code)?)
    } else {
        return Err(missing("stdin is not a terminal and -k was not given"));
    };

    Ok(Unlock { typed, secret })
}

fn missing(why: &str) -> Fatal {
    Fatal::new(
        EX_CODE_MISSING,
        format!("This user has a second factor, so the recovery code is needed ({why}): {HOW}."),
    )
}

/// Parse and pre-check a typed code (no key derivation).
fn check(status: &SecondFactorStatus, code: &str) -> Result<SecondSecret, Fatal> {
    let secret = SecondSecret::parse_recovery_code(code)
        .map_err(|e| Fatal::new(EX_CODE_MISTYPED, format!("Recovery code rejected: {e}.")))?;
    if let SecondFactorStatus::Enabled(sf) = status {
        if !sf.matches(&secret) {
            return Err(foreign());
        }
    }
    Ok(secret)
}

fn foreign() -> Fatal {
    Fatal::new(
        EX_CODE_FOREIGN,
        "This recovery code is valid but does not belong to this user (an old code from before the second factor was replaced?).",
    )
}

/// The combined form `password CODE`: split off a trailing code.  A trailing
/// word that is not code-shaped is not treated as a code; a code-shaped one
/// that fails its checksum or is not this user's is an error.
fn combined(
    status: &SecondFactorStatus,
    typed: &str,
) -> Result<Option<(Zeroizing<String>, SecondSecret)>, Fatal> {
    let Some((prefix, tail)) = typed.rsplit_once(' ') else {
        return Ok(None);
    };
    match SecondSecret::parse_recovery_code(tail) {
        Ok(secret) => {
            if let SecondFactorStatus::Enabled(sf) = status {
                if !sf.matches(&secret) {
                    return Err(foreign());
                }
            }
            Ok(Some((Zeroizing::new(prefix.to_owned()), secret)))
        }
        Err(mpw_model::RecoveryCodeError::ChecksumMismatch) => Err(Fatal::new(
            EX_CODE_MISTYPED,
            "Recovery code rejected: the code at the end of the master password is mistyped (its checksum does not match).",
        )),
        Err(_) => Ok(None),
    }
}
