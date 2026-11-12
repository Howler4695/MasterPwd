//! Master-key derivation off the main thread, and the saved-key vault seam.
//!
//! A [`DeriveJob`] runs scrypt on a background thread and returns a
//! *password-less* [`UserKeys`]: the master keys for every algorithm version,
//! plus the identicon.  The master password itself is wiped as soon as the
//! keys exist; it is never kept for the session.

use std::fmt;
use std::panic::AssertUnwindSafe;

use mpw_core::{identicon, AlgorithmVersion, Identicon, MasterKey, Zeroizing};
use mpw_model::UserKeys;

/// What a derivation is for; the core routes the outcome by it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivePurpose {
    Unlock,
    CreateUser,
    /// A flow step (import, export, replace); `step` is flow-defined.
    Flow { flow: u64, step: u32 },
}

/// A key derivation to run off the main thread.  `Send`; the password is
/// wiped on drop and redacted from `Debug`.
pub struct DeriveJob {
    pub id: u64,
    pub purpose: DerivePurpose,
    pub full_name: String,
    master_password: Zeroizing<String>,
}

/// The result of a [`DeriveJob`].
pub struct Derived {
    pub id: u64,
    pub purpose: DerivePurpose,
    pub full_name: String,
    pub result: Result<(UserKeys, Identicon), String>,
}

impl fmt::Debug for DeriveJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeriveJob(#{}, {:?}, <redacted>)", self.id, self.purpose)
    }
}

impl fmt::Debug for Derived {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Derived(#{}, {:?}, ok: {})", self.id, self.purpose, self.result.is_ok())
    }
}

impl DeriveJob {
    pub fn new(id: u64, purpose: DerivePurpose, full_name: &str, master_password: Zeroizing<String>) -> Self {
        Self { id, purpose, full_name: full_name.to_owned(), master_password }
    }

    /// The slow part.  Never call this on the main thread.
    pub fn run(self) -> Derived {
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| derive_all(&self.full_name, &self.master_password)))
            .unwrap_or_else(|_| Err("key derivation failed unexpectedly".into()));
        Derived { id: self.id, purpose: self.purpose, full_name: self.full_name, result }
    }
}

/// Derive the keys of all four algorithm versions without keeping the
/// password.  Versions 0–2 salt scrypt with the name's length in characters,
/// v3 in bytes; the rest is identical (this is the reference algorithm, which
/// `mpw-model` relies on too).  So one scrypt suffices for an ASCII name and
/// two for any other.
pub fn derive_all(full_name: &str, master_password: &str) -> Result<(UserKeys, Identicon), String> {
    let v3 = MasterKey::derive(full_name, master_password, AlgorithmVersion::V3).map_err(|e| e.to_string())?;
    let legacy = if full_name.chars().count() == full_name.len() {
        MasterKey::from_bytes(*v3.as_bytes(), AlgorithmVersion::V0)
    } else {
        MasterKey::derive(full_name, master_password, AlgorithmVersion::V0).map_err(|e| e.to_string())?
    };
    let mut keys = UserKeys::from_key(full_name, v3);
    for v in [AlgorithmVersion::V1, AlgorithmVersion::V2] {
        keys.insert_key(MasterKey::from_bytes(*legacy.as_bytes(), v));
    }
    keys.insert_key(legacy);
    Ok((keys, identicon(full_name, master_password)))
}

/// Copy a key holder (e.g. to use the session's keys for both sides of a
/// merge).  Only versions present are copied; the copy is not authenticated.
pub fn copy_keys(full_name: &str, keys: &mut UserKeys) -> Option<UserKeys> {
    let mut out: Option<UserKeys> = None;
    for v in AlgorithmVersion::ALL {
        if let Ok(bytes) = keys.key_bytes(v) {
            let key = MasterKey::from_bytes(*bytes, v);
            match &mut out {
                Some(o) => o.insert_key(key),
                None => out = Some(UserKeys::from_key(full_name, key)),
            }
        }
    }
    out
}

/// Where "Save Password" keeps derived master keys (the Keychain in the app).
pub trait KeyVault {
    /// Save every version of `keys` for `full_name`.  Returns a description of
    /// where they went (for the UI).
    fn store_all(&self, full_name: &str, keys: &mut UserKeys) -> Result<String, String>;
    /// Load whatever versions are saved; `None` if nothing is.
    fn load_all(&self, full_name: &str) -> Result<Option<UserKeys>, String>;
    /// Remove every saved version.  Not finding any is not an error.
    fn delete_all(&self, full_name: &str) -> Result<(), String>;
}

/// An in-memory vault (tests).
#[derive(Default)]
pub struct MemoryVault {
    pub keys: std::cell::RefCell<std::collections::BTreeMap<(String, u32), [u8; 64]>>,
}

impl KeyVault for MemoryVault {
    fn store_all(&self, full_name: &str, keys: &mut UserKeys) -> Result<String, String> {
        for v in AlgorithmVersion::ALL {
            let bytes = keys.key_bytes(v).map_err(|e| e.to_string())?;
            self.keys.borrow_mut().insert((full_name.to_owned(), v.as_u32()), *bytes);
        }
        Ok("memory".into())
    }

    fn load_all(&self, full_name: &str) -> Result<Option<UserKeys>, String> {
        let stored = self.keys.borrow();
        let mut out: Option<UserKeys> = None;
        for v in AlgorithmVersion::ALL {
            if let Some(bytes) = stored.get(&(full_name.to_owned(), v.as_u32())) {
                let key = MasterKey::from_bytes(*bytes, v);
                match &mut out {
                    Some(o) => o.insert_key(key),
                    None => out = Some(UserKeys::from_key(full_name, key)),
                }
            }
        }
        Ok(out)
    }

    fn delete_all(&self, full_name: &str) -> Result<(), String> {
        self.keys.borrow_mut().retain(|(n, _), _| n != full_name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpw_model::User;

    #[test]
    fn derived_keys_match_password_keys_for_every_version() {
        for name in ["Robert Lee Mitchell", "Zoë Ångström"] {
            let (mut derived, icon) = derive_all(name, "pw").unwrap();
            let mut reference = UserKeys::from_password(name, "pw");
            for v in AlgorithmVersion::ALL {
                assert_eq!(*derived.key_bytes(v).unwrap(), *reference.key_bytes(v).unwrap(), "{name} {v}");
            }
            assert!(!derived.has_password(), "the password is not kept");
            assert_eq!(icon, identicon(name, "pw"));
        }
    }

    #[test]
    fn job_reports_and_redacts() {
        let job = DeriveJob::new(7, DerivePurpose::Unlock, "A", Zeroizing::new("secret".into()));
        assert!(!format!("{job:?}").contains("secret"));
        let out = job.run();
        assert_eq!(out.id, 7);
        assert!(out.result.is_ok());
    }

    #[test]
    fn vault_round_trip_authenticates() {
        let mut user = User::new("V").unwrap();
        let (mut keys, _) = derive_all("V", "pw").unwrap();
        user.authenticate(&mut keys).unwrap();
        let vault = MemoryVault::default();
        vault.store_all("V", &mut keys).unwrap();
        let mut loaded = vault.load_all("V").unwrap().unwrap();
        assert!(user.authenticate(&mut loaded).is_ok());
        vault.delete_all("V").unwrap();
        assert!(vault.load_all("V").unwrap().is_none());
        let mut copy = copy_keys("V", &mut keys).unwrap();
        assert!(user.authenticate(&mut copy).is_ok());
    }
}

/// Live-test helper: prints the v3 long password for `$MPW_NAME`, `$MPW_PASSWORD`,
/// `$MPW_SITE` (`cargo test -p masterpwd-app -- --ignored print_site_password --nocapture`).
#[cfg(test)]
#[test]
#[ignore]
fn print_site_password() {
    let get = |k: &str| std::env::var(k).unwrap_or_default();
    let key = MasterKey::derive(&get("MPW_NAME"), &get("MPW_PASSWORD"), AlgorithmVersion::V3).unwrap();
    let pw = key
        .site_result(&get("MPW_SITE"), 1, mpw_core::KeyPurpose::Authentication, None, mpw_core::ResultType::DEFAULT, None)
        .unwrap();
    println!("EXPECTED={}", pw.as_str());
}
