//! The Master Password algorithm.
//!
//! ```text
//! master-key    = SCRYPT( user-name, master-password )
//! site-key      = HMAC-SHA-256( site-name . site-counter, master-key )
//! site-password = PW-TEMPLATE( site-key, site-template )
//! ```
//!
//! This crate is a clean-room Rust port of the reference C implementation
//! (`mpw-algorithm_v0..v3.c`).  All four algorithm versions are supported and
//! must stay bit-for-bit compatible with the reference, *including* the
//! historical quirks that define v0, v1 and v2 — those are compatibility
//! requirements, not bugs to fix.
//!
//! Nothing in this crate performs I/O.  Secrets are wiped from memory on drop.

#![forbid(unsafe_code)]

mod algorithm;
mod error;
mod types;

pub use algorithm::{identicon, MasterKey, MASTER_KEY_SIZE};
pub use error::Error;
pub use types::{
    AlgorithmVersion, Counter, Identicon, IdenticonColor, KeyId, KeyPurpose, ResultType,
    COUNTER_DEFAULT, COUNTER_INITIAL, COUNTER_TOTP,
};

/// Re-exported so dependants hold secrets in the same wrapper types we return.
pub use zeroize::{Zeroize, Zeroizing};
