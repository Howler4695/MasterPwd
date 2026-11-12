//! Error types.  Messages never contain passwords, keys or stored state, and
//! parse errors never echo values read from the (untrusted) input.

use mpw_core::{AlgorithmVersion, ResultType};
use std::path::PathBuf;
use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong in this crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The master password does not match the user's stored key ID.
    #[error("incorrect master password")]
    WrongMasterPassword,
    /// The key holder was created for a different full name than the user's.
    #[error("the master key belongs to a different user")]
    UserMismatch,
    /// An operation needs a key holder that was authenticated against this user
    /// (see [`crate::User::authenticate`]).
    #[error("the user has not been unlocked with this master key")]
    NotAuthenticated,
    /// The key holder has no master password and no cached key for this version.
    #[error("no master key is available for algorithm {0}")]
    KeyUnavailable(AlgorithmVersion),
    /// The algorithm failed (bad parameters, undecryptable state, ...).
    #[error("algorithm error: {0}")]
    Algorithm(#[from] mpw_core::Error),

    #[error("the full name is not valid: {0}")]
    InvalidFullName(&'static str),
    #[error("the site name is not valid: {0}")]
    InvalidSiteName(&'static str),
    #[error("the user has no site with that name")]
    NoSuchSite,
    #[error("the user already has a site with that name")]
    SiteExists,
    #[error("the site already has a question with that keyword")]
    QuestionExists,
    /// A stateful result type is selected but no value has been stored yet.
    #[error("no value has been stored for this {0}")]
    NoStoredValue(&'static str),
    /// A value can only be stored for a stateful result type.
    #[error("result type {0} does not store a value")]
    NotStateful(ResultType),

    /// The input could not be parsed.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The data cannot be expressed in the requested format (e.g. a tab in a
    /// site name in the flat format).
    #[error("{what} cannot be written in the flat format ({why})")]
    NotRepresentable { what: &'static str, why: &'static str },
    /// A revealed (clear-text) export needs the master key to be imported.
    #[error("this export contains clear-text passwords; the master password is needed to import it")]
    RevealedNeedsKey,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("a user with this full name already exists in the store")]
    UserExists,
    #[error("no user with this full name exists in the store")]
    UserNotFound,
    /// The store file for this name holds a different user (name-hash collision
    /// or a hand-edited file); nothing was overwritten.
    #[error("the user file {0:?} belongs to a different user; refusing to overwrite it")]
    NameCollision(PathBuf),
    /// A path in the store is a symlink or not a regular file.
    #[error("refusing to use {0:?}: not a regular file inside the store")]
    UnsafePath(PathBuf),
    /// `$HOME` is not set, so there is no default store directory.
    #[error("cannot determine the home directory")]
    NoHomeDirectory,
}

/// What went wrong while parsing, and where.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind}{}", location_suffix(*line, location))]
pub struct ParseError {
    /// 1-based line number in the input, when known.
    pub line: Option<usize>,
    /// Which field, e.g. `user.key_id` or `site #3 counter`.  Never a value.
    pub location: String,
    pub kind: ParseErrorKind,
}

fn location_suffix(line: Option<usize>, location: &str) -> String {
    match (line, location.is_empty()) {
        (Some(l), false) => format!(" (line {l}, {location})"),
        (Some(l), true) => format!(" (line {l})"),
        (None, false) => format!(" ({location})"),
        (None, true) => String::new(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ParseErrorKind {
    #[error("the file is larger than the {max}-byte limit")]
    TooLarge { max: usize },
    #[error("the file is not valid UTF-8 (at byte {offset})")]
    InvalidUtf8 { offset: usize },
    #[error("not a Master Password export file")]
    UnknownFormat,
    #[error("unsupported flat format version {0}")]
    UnsupportedFlatFormat(u64),
    #[error("malformed JSON ({0})")]
    Json(String),
    #[error("a required value is missing")]
    Missing,
    #[error("invalid value")]
    InvalidValue,
    #[error("unsupported algorithm version")]
    InvalidAlgorithm,
    #[error("unknown result type {0}")]
    InvalidResultType(u64),
    #[error("too many {what} (limit {limit})")]
    TooMany { what: &'static str, limit: usize },
    #[error("value is too long (limit {limit} bytes)")]
    TooLong { limit: usize },
    /// No longer produced: files with both `sites` and `services` are merged
    /// like Spectre does.  Kept for API stability.
    #[error("the file has both a \"sites\" and a \"services\" section")]
    AmbiguousSites,
}

impl ParseError {
    pub(crate) fn new(kind: ParseErrorKind, line: Option<usize>, location: impl Into<String>) -> Self {
        Self { line, location: location.into(), kind }
    }
}
