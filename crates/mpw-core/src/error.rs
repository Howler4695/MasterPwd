use thiserror::Error;

/// Errors produced by the algorithm.  Messages never contain secret material.
///
/// Non-exhaustive: match with a wildcard arm, new variants may be added.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The result parameter is not valid for the result type, e.g. a
    /// [`crate::ResultType::DeriveKey`] size that is not 128-512 bits in
    /// multiples of 8.
    #[error("the result parameter is not valid for this result type: {0}")]
    InvalidResultParam(&'static str),
    #[error("the stored state could not be decrypted with this master key")]
    InvalidState,
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("internal error: {0}")]
    Internal(String),
}
