use thiserror::Error;

/// Errors produced by the algorithm.  Messages never contain secret material.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("the full name must not be empty")]
    EmptyFullName,
    #[error("the master password must not be empty")]
    EmptyMasterPassword,
    #[error("the site name must not be empty")]
    EmptySiteName,
    #[error("result type {0} is not supported for this operation")]
    UnsupportedResultType(u32),
    #[error("a result parameter is required for this result type")]
    MissingResultParam,
    #[error("the stored state could not be decrypted with this master key")]
    InvalidState,
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("internal error: {0}")]
    Internal(String),
}
