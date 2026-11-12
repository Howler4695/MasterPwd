//! ======================================================================
//! SEAM: user-file persistence (`-f`, `-F`, `-R`, `MPW_FORMAT`, `~/.mpw.d`).
//! ======================================================================
//!
//! The reference CLI loads `~/.mpw.d/<Full Name>.mpjson` (or `.mpsites`),
//! checks the master key ID against it, takes the site's counter, type,
//! algorithm and stored state from it, and writes it back afterwards.
//!
//! This build is stateless: [`load`] never finds a user and [`save`] does
//! nothing.  When `mpw-model` lands, implement these two functions (and fill
//! in [`SiteDefaults`]) — `main.rs` already calls them at the same points as
//! the reference (`cli_user`/`cli_site`/`cli_question`/`cli_operation`, and
//! `cli_save`).  Keep in mind when wiring it:
//! * check the stored key ID with `KeyId`'s constant-time `==`;
//! * write files 0600 in a 0700 directory, atomically (temp file + rename);
//! * the user's own algorithm (for the key-ID check) may differ from the
//!   site's algorithm (for the result).

use crate::log::{wrn, Fatal};
use crate::EX_DATAERR;
use mpw_core::{AlgorithmVersion, Counter, ResultType};

/// User-file format, as named by `-f`/`-F`/`MPW_FORMAT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    None,
    Flat,
    Json,
}

impl Format {
    pub const DEFAULT: Self = Self::Json;

    /// Case-insensitive prefix match, like `mpw_format_named`.
    pub fn named(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        [
            ("none", Self::None),
            ("flat", Self::Flat),
            ("json", Self::Json),
        ]
        .into_iter()
        .find(|(n, _)| n.starts_with(&lower))
        .map(|(_, f)| f)
    }
}

/// File options from the command line / environment.
#[derive(Debug)]
pub struct Options {
    pub format: Format,
    pub format_fixed: bool,
    pub redacted: Option<bool>,
}

impl Options {
    pub fn parse(format: Option<&str>, fixed: bool, redacted: Option<&str>) -> Result<Self, Fatal> {
        let format = match format {
            None => Format::DEFAULT,
            Some(name) => Format::named(name)
                .ok_or_else(|| Fatal::new(EX_DATAERR, format!("Invalid sites format: {name}")))?,
        };
        // `mpw_get_bool`: starts with 'y' or 't', or is a positive number.
        let redacted = redacted
            .map(|r| r.starts_with(['y', 't']) || r.trim().parse::<i64>().is_ok_and(|n| n > 0));
        let options = Self {
            format,
            format_fixed: fixed,
            redacted,
        };
        let asked_for_file = (fixed && format != Format::None) || options.redacted.is_some();
        if asked_for_file {
            wrn!("User files (-f/-F/-R, ~/.mpw.d) are not supported by this build yet; working statelessly.");
        }
        Ok(options)
    }
}

/// What a stored user/site would contribute to the operation.
#[derive(Debug, Default)]
pub struct SiteDefaults {
    pub result_type: Option<ResultType>,
    pub counter: Option<Counter>,
    pub algorithm: Option<AlgorithmVersion>,
    /// The stored (encrypted) state for stateful result types.
    pub state: Option<String>,
}

/// SEAM: load the user file and the matching site/question.
/// Stateless build: there is never a stored user.
pub fn load(_options: &Options, _full_name: &str, _site_name: &str) -> Option<SiteDefaults> {
    None
}

/// SEAM: persist the (possibly updated) user file.  Stateless build: no-op.
pub fn save(_options: &Options, _full_name: &str, _site_name: &str, _new_state: Option<&str>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_names() {
        assert_eq!(Format::named("n"), Some(Format::None));
        assert_eq!(Format::named("FLAT"), Some(Format::Flat));
        assert_eq!(Format::named("j"), Some(Format::Json));
        assert_eq!(Format::named("xml"), None);
    }
}
