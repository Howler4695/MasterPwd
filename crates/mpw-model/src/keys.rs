//! The master-key holder.

use crate::error::{Error, Result};
use mpw_core::{AlgorithmVersion, Identicon, KeyId, MasterKey};
use std::fmt;
use zeroize::Zeroizing;

/// Holds a user's master keys: one per algorithm version, derived lazily from
/// the master password and cached, or supplied directly as key bytes (e.g.
/// restored from the macOS Keychain).
///
/// A `UserKeys` belongs to one full name.  It must be authenticated against a
/// [`crate::User`] with [`crate::User::authenticate`] before that user's
/// passwords can be computed with it.
///
/// The master password and all keys are wiped from memory on drop.  There is
/// deliberately no `Clone`, and `Debug` prints nothing secret.
pub struct UserKeys {
    full_name: String,
    password: Option<Zeroizing<String>>,
    keys: [Option<MasterKey>; 4],
    /// The key ID this holder was last successfully authenticated as.
    authenticated: Option<KeyId>,
}

impl UserKeys {
    /// A holder that derives keys from the master password on demand.
    ///
    /// Nothing is derived yet; the first [`UserKeys::key`] call (or the first
    /// authentication) runs scrypt, which is deliberately slow.
    pub fn from_password(full_name: &str, master_password: &str) -> Self {
        Self {
            full_name: full_name.to_owned(),
            password: Some(Zeroizing::new(master_password.to_owned())),
            keys: Default::default(),
            authenticated: None,
        }
    }

    /// A holder for an already-derived key.  More versions can be added with
    /// [`UserKeys::insert_key`]; versions that are neither supplied nor
    /// derivable yield [`Error::KeyUnavailable`].
    pub fn from_key(full_name: &str, key: MasterKey) -> Self {
        let mut keys = Self {
            full_name: full_name.to_owned(),
            password: None,
            keys: Default::default(),
            authenticated: None,
        };
        keys.insert_key(key);
        keys
    }

    /// Add (or replace) the cached key for `key.algorithm()`.
    ///
    /// Replacing a key invalidates any earlier authentication.
    pub fn insert_key(&mut self, key: MasterKey) {
        let slot = &mut self.keys[slot(key.algorithm())];
        if slot.is_some() {
            self.authenticated = None;
        }
        *slot = Some(key);
    }

    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    /// Whether this holder can derive keys itself (it holds a master password).
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// The identicon for the full name and master password, if the password is known.
    pub fn identicon(&self) -> Option<Identicon> {
        self.password
            .as_ref()
            .map(|pw| mpw_core::identicon(&self.full_name, pw))
    }

    /// The master key for `algorithm`, deriving and caching it if needed.
    pub fn key(&mut self, algorithm: AlgorithmVersion) -> Result<&MasterKey> {
        let i = slot(algorithm);
        if self.keys[i].is_none() {
            let key = self.produce(algorithm)?;
            self.keys[i] = Some(key);
        }
        self.keys[i].as_ref().ok_or(Error::KeyUnavailable(algorithm))
    }

    /// Export a key's raw bytes, e.g. to store it in the Keychain.
    pub fn key_bytes(
        &mut self,
        algorithm: AlgorithmVersion,
    ) -> Result<Zeroizing<[u8; mpw_core::MASTER_KEY_SIZE]>> {
        Ok(Zeroizing::new(*self.key(algorithm)?.as_bytes()))
    }

    fn produce(&self, algorithm: AlgorithmVersion) -> Result<MasterKey> {
        // Algorithms v0-v2 salt scrypt with the full name's length in
        // characters, v3 with its length in bytes; everything else is equal.
        // For an ASCII name the master keys of all four versions are therefore
        // bit-identical, so reuse any cached one instead of running scrypt again.
        if self.full_name.is_ascii() {
            if let Some(existing) = self.keys.iter().flatten().next() {
                return Ok(MasterKey::from_bytes(*existing.as_bytes(), algorithm));
            }
        }
        match &self.password {
            Some(pw) => Ok(MasterKey::derive(&self.full_name, pw, algorithm)?),
            None => Err(Error::KeyUnavailable(algorithm)),
        }
    }

    pub(crate) fn mark_authenticated(&mut self, id: KeyId) {
        self.authenticated = Some(id);
    }

    pub(crate) fn authenticated_id(&self) -> Option<&KeyId> {
        self.authenticated.as_ref()
    }
}

fn slot(algorithm: AlgorithmVersion) -> usize {
    algorithm.as_u32() as usize
}

impl fmt::Debug for UserKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cached: Vec<_> = AlgorithmVersion::ALL
            .into_iter()
            .filter(|v| self.keys[slot(*v)].is_some())
            .collect();
        f.debug_struct("UserKeys")
            .field("full_name", &self.full_name)
            .field("has_password", &self.password.is_some())
            .field("cached", &cached)
            .field("authenticated", &self.authenticated.is_some())
            .finish()
    }
}
