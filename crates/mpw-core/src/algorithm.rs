//! Key derivation and result encoding.
//!
//! SCAFFOLD: the signatures below are the contract the rest of the workspace
//! is written against.  The bodies are placeholders to be implemented.

use crate::{AlgorithmVersion, Counter, Error, Identicon, KeyId, KeyPurpose, ResultType};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Size of a master key in bytes.
pub const MASTER_KEY_SIZE: usize = 64;

/// A user's master key for one algorithm version.
///
/// The key is wiped from memory when dropped.  It deliberately implements
/// neither `Debug` (beyond a redacted form), `Display` nor `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; MASTER_KEY_SIZE],
    #[zeroize(skip)]
    algorithm: AlgorithmVersion,
}

impl MasterKey {
    /// Derive the master key from the user's full name and master password.
    ///
    /// This is deliberately slow (scrypt N=32768, r=8, p=2); call it off the
    /// UI thread.
    pub fn derive(
        full_name: &str,
        master_password: &str,
        algorithm: AlgorithmVersion,
    ) -> Result<Self, Error> {
        let _ = (full_name, master_password, algorithm);
        todo!("mpw-core: MasterKey::derive")
    }

    /// Rebuild a key from raw bytes, e.g. when restoring it from the keychain.
    pub fn from_bytes(bytes: [u8; MASTER_KEY_SIZE], algorithm: AlgorithmVersion) -> Self {
        Self { bytes, algorithm }
    }

    /// The raw key material.  Handle with care.
    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_SIZE] {
        &self.bytes
    }

    /// The algorithm version this key was derived with.  Site results must be
    /// requested from a key of the site's own algorithm version.
    pub fn algorithm(&self) -> AlgorithmVersion {
        self.algorithm
    }

    /// The key's fingerprint.
    pub fn key_id(&self) -> KeyId {
        todo!("mpw-core: MasterKey::key_id")
    }

    /// Compute a site result: a generated password, login name or answer for
    /// template types, the decrypted stored value for stateful types (pass the
    /// stored state as `result_param`), or a derived key for
    /// [`ResultType::DeriveKey`].
    ///
    /// `context` is the security-question keyword for recovery results.
    pub fn site_result(
        &self,
        site_name: &str,
        counter: Counter,
        purpose: KeyPurpose,
        context: Option<&str>,
        result_type: ResultType,
        result_param: Option<&str>,
    ) -> Result<Zeroizing<String>, Error> {
        let _ = (site_name, counter, purpose, context, result_type, result_param);
        todo!("mpw-core: MasterKey::site_result")
    }

    /// Encrypt a user-chosen value into the state to store for a stateful
    /// result type.  Feed the returned state back to [`MasterKey::site_result`]
    /// as `result_param` to recover `plaintext`.
    pub fn site_state(
        &self,
        site_name: &str,
        counter: Counter,
        purpose: KeyPurpose,
        context: Option<&str>,
        result_type: ResultType,
        plaintext: &str,
    ) -> Result<String, Error> {
        let _ = (site_name, counter, purpose, context, result_type, plaintext);
        todo!("mpw-core: MasterKey::site_state")
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey({}, <redacted>)", self.algorithm)
    }
}

/// Compute the identicon for a full name and master password.
pub fn identicon(full_name: &str, master_password: &str) -> Identicon {
    let _ = (full_name, master_password);
    todo!("mpw-core: identicon")
}
