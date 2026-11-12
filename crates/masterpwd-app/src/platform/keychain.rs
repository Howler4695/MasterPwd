//! Keychain storage for derived master keys (for "Save Password" / Touch ID,
//! wired up next round).
//!
//! Stores the 64-byte *derived* master key per (user, algorithm version) as a
//! generic password, never the master password itself.  Items are
//! `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and never synchronizable.
//!
//! The data-protection keychain is tried first.  It requires a
//! keychain-access-groups / application-identifier entitlement, which an
//! ad-hoc-signed app (and `cargo test`) cannot have, so on
//! `errSecMissingEntitlement` we fall back to the login (file-based) keychain,
//! still non-synchronizable (the file keychain has no accessibility classes:
//! its items are readable while the login keychain is unlocked, by the apps on
//! the item's ACL).  [`Backend`] reports which one was used.

use mpw_core::{AlgorithmVersion, MasterKey, Zeroize, Zeroizing, MASTER_KEY_SIZE};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{
    delete_generic_password_options, generic_password, set_generic_password_options, PasswordOptions,
};

/// The keychain service of the app's saved keys.
pub const APP_SERVICE: &str = "com.github.howler4695.masterpwd.master-key";

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;
const ERR_SEC_PARAM: i32 = -50;

/// Which keychain holds an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    DataProtection,
    /// The login keychain (macOS file keychain).
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainError {
    /// An OSStatus from Security.framework, with its message.
    Os { code: i32, message: String },
    /// The stored item is not a 64-byte key.
    Corrupt,
}

impl std::fmt::Display for KeychainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Os { code, message } => write!(f, "keychain error {code}: {message}"),
            Self::Corrupt => f.write_str("the saved key in the keychain is damaged"),
        }
    }
}

impl std::error::Error for KeychainError {}

impl From<security_framework::base::Error> for KeychainError {
    fn from(e: security_framework::base::Error) -> Self {
        Self::Os { code: e.code(), message: e.to_string() }
    }
}

fn code(e: &security_framework::base::Error) -> i32 {
    e.code()
}

/// Saved master keys under one keychain service.
#[derive(Debug, Clone)]
pub struct Keychain {
    service: String,
}

impl Keychain {
    /// The app's real service.
    pub fn app() -> Self {
        Self::with_service(APP_SERVICE)
    }

    pub fn with_service(service: &str) -> Self {
        Self { service: service.to_owned() }
    }

    fn account(user: &str, algorithm: AlgorithmVersion) -> String {
        format!("{algorithm}:{user}")
    }

    fn options(&self, user: &str, algorithm: AlgorithmVersion, backend: Backend, access_control: bool) -> Result<PasswordOptions, KeychainError> {
        let mut options = PasswordOptions::new_generic_password(&self.service, &Self::account(user, algorithm));
        options.set_access_synchronized(Some(false));
        if backend == Backend::DataProtection {
            options.use_protected_keychain();
        }
        if access_control {
            let ac = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                0,
            )?;
            options.set_access_control(ac);
        }
        Ok(options)
    }

    /// Save (or replace) the key for `user`.
    pub fn store(&self, user: &str, key: &MasterKey) -> Result<Backend, KeychainError> {
        let algorithm = key.algorithm();
        let _ = self.delete(user, algorithm);
        let label_opts = |backend, ac| -> Result<PasswordOptions, KeychainError> {
            let mut o = self.options(user, algorithm, backend, ac)?;
            o.set_label("Master Password key");
            o.set_description("Derived master key (not the master password)");
            Ok(o)
        };
        match set_generic_password_options(key.as_bytes(), label_opts(Backend::DataProtection, true)?) {
            Ok(()) => return Ok(Backend::DataProtection),
            Err(e) if code(&e) == ERR_SEC_MISSING_ENTITLEMENT => {}
            Err(e) => return Err(e.into()),
        }
        match set_generic_password_options(key.as_bytes(), label_opts(Backend::File, true)?) {
            Ok(()) => Ok(Backend::File),
            // The file keychain rejects access-control objects (they imply
            // the data-protection keychain): store without one.  The login
            // keychain has no accessibility classes; its items are readable
            // only while it is unlocked, by apps on the item's ACL.
            Err(e) if code(&e) == ERR_SEC_PARAM || code(&e) == ERR_SEC_MISSING_ENTITLEMENT => {
                set_generic_password_options(key.as_bytes(), label_opts(Backend::File, false)?)?;
                Ok(Backend::File)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Load the key for `user`, if saved.
    pub fn load(&self, user: &str, algorithm: AlgorithmVersion) -> Result<Option<MasterKey>, KeychainError> {
        for backend in [Backend::DataProtection, Backend::File] {
            match generic_password(self.options(user, algorithm, backend, false)?) {
                Ok(bytes) => {
                    let bytes = Zeroizing::new(bytes);
                    let mut raw: [u8; MASTER_KEY_SIZE] =
                        bytes.as_slice().try_into().map_err(|_| KeychainError::Corrupt)?;
                    let key = MasterKey::from_bytes(raw, algorithm);
                    raw.zeroize();
                    return Ok(Some(key));
                }
                Err(e) if code(&e) == ERR_SEC_ITEM_NOT_FOUND || code(&e) == ERR_SEC_MISSING_ENTITLEMENT => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(None)
    }

    /// Delete the key for `user` from both keychains.  Returns whether
    /// anything was deleted.
    pub fn delete(&self, user: &str, algorithm: AlgorithmVersion) -> Result<bool, KeychainError> {
        let mut deleted = false;
        for backend in [Backend::DataProtection, Backend::File] {
            loop {
                match delete_generic_password_options(self.options(user, algorithm, backend, false)?) {
                    Ok(()) => deleted = true,
                    Err(e) if code(&e) == ERR_SEC_ITEM_NOT_FOUND || code(&e) == ERR_SEC_MISSING_ENTITLEMENT => break,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(deleted)
    }
}

impl crate::keys::KeyVault for Keychain {
    fn store_all(&self, full_name: &str, keys: &mut mpw_model::UserKeys) -> Result<String, String> {
        let mut backend = Backend::File;
        for v in AlgorithmVersion::ALL {
            let bytes = keys.key_bytes(v).map_err(|e| e.to_string())?;
            let key = MasterKey::from_bytes(*bytes, v);
            backend = self.store(full_name, &key).map_err(|e| {
                let _ = self.delete_all_versions(full_name);
                e.to_string()
            })?;
        }
        Ok(match backend {
            Backend::DataProtection => "data-protection Keychain".into(),
            Backend::File => "login Keychain".into(),
        })
    }

    fn load_all(&self, full_name: &str) -> Result<Option<mpw_model::UserKeys>, String> {
        let mut out: Option<mpw_model::UserKeys> = None;
        for v in AlgorithmVersion::ALL {
            if let Some(key) = self.load(full_name, v).map_err(|e| e.to_string())? {
                match &mut out {
                    Some(o) => o.insert_key(key),
                    None => out = Some(mpw_model::UserKeys::from_key(full_name, key)),
                }
            }
        }
        Ok(out)
    }

    fn delete_all(&self, full_name: &str) -> Result<(), String> {
        self.delete_all_versions(full_name).map_err(|e| e.to_string())
    }
}

impl Keychain {
    /// Delete the keys of every algorithm version.
    pub fn delete_all_versions(&self, user: &str) -> Result<(), KeychainError> {
        for v in AlgorithmVersion::ALL {
            self.delete(user, v)?;
        }
        Ok(())
    }

    /// Whether anything is stored for `user` (smoke test).
    pub fn has_any(&self, user: &str) -> bool {
        AlgorithmVersion::ALL.into_iter().any(|v| matches!(self.load(user, v), Ok(Some(_))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway service, deleted again by [`Cleanup`].
    fn service() -> String {
        format!("com.github.howler4695.masterpwd.TEST-THROWAWAY-{}", std::process::id())
    }

    struct Cleanup(Keychain, Vec<(&'static str, AlgorithmVersion)>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for (user, v) in &self.1 {
                let _ = self.0.delete(user, *v);
            }
        }
    }

    #[test]
    fn store_load_replace_delete() {
        let kc = Keychain::with_service(&service());
        let _cleanup = Cleanup(kc.clone(), vec![("Test User", AlgorithmVersion::V3), ("Test User", AlgorithmVersion::V2)]);

        assert!(kc.load("Test User", AlgorithmVersion::V3).unwrap().is_none());
        assert!(!kc.delete("Test User", AlgorithmVersion::V3).unwrap());

        let backend = kc.store("Test User", &MasterKey::from_bytes([7; 64], AlgorithmVersion::V3)).unwrap();
        eprintln!("keychain backend used by tests: {backend:?}");
        let loaded = kc.load("Test User", AlgorithmVersion::V3).unwrap().expect("stored key");
        assert_eq!(loaded.as_bytes(), &[7; 64]);
        assert_eq!(loaded.algorithm(), AlgorithmVersion::V3);
        // Other versions are separate items.
        assert!(kc.load("Test User", AlgorithmVersion::V2).unwrap().is_none());

        // Replacing works (no duplicate-item error).
        kc.store("Test User", &MasterKey::from_bytes([9; 64], AlgorithmVersion::V3)).unwrap();
        assert_eq!(kc.load("Test User", AlgorithmVersion::V3).unwrap().unwrap().as_bytes(), &[9; 64]);

        assert!(kc.delete("Test User", AlgorithmVersion::V3).unwrap());
        assert!(kc.load("Test User", AlgorithmVersion::V3).unwrap().is_none());
    }
}
