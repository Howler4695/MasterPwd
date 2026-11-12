//! Shared test helpers.  scrypt is slow, so each (name, password) key is
//! derived once per test binary and handed out as key bytes.
#![allow(dead_code)]

use mpw_model::{AlgorithmVersion, MasterKey, UserKeys};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub const NAME: &str = "Robert Lee Mitchell";
pub const PASSWORD: &str = "banana colored duckling";
pub const OTHER_PASSWORD: &str = "⛄";
pub const KEY_ID: &str = "98EEF4D1DF46D849574A82A03C3177056B15DFFCA29BB3899DE4628453675302";
pub const OTHER_KEY_ID: &str = "351432B8528A5ABECAB768CA95015097DE76FE14C41E10AF36C67DCFB8917E08";

/// Known results for NAME/PASSWORD (from the reference test vectors).
pub const MPA: &str = "masterpasswordapp.com";
pub const MPA_V3_LONG: &str = "Jejr5[RepuSosp";
pub const MPA_V0_LONG: &str = "Feji5@ReduWosh";
pub const MPA_LOGIN: &str = "wohzaqage";
pub const MPA_ANSWER: &str = "xin diyjiqoja hubu";
pub const MPA_ANSWER_QUESTION: &str = "xogx tem cegyiva jab";

/// "my personal pw" for personal.example, encrypted with NAME/PASSWORD.
pub const PERSONAL_STATE: &str = "S3thn+F0DS7pzWY1CqfxEw==";
pub const PERSONAL_PW: &str = "my personal pw";
pub const PERSONAL_LOGIN_STATE: &str = "HcMPU+4PpHX9mGQbbL7wySZmXHVfyEApIZ4x6wGQPu8=";
pub const PERSONAL_LOGIN: &str = "robert@example.com";
/// "Smith" for the "mother" question of masterpasswordapp.com.
pub const MOTHER_STATE: &str = "M/XcwqE2IMc0PJcRob4Gkg==";

type KeyCache = Mutex<HashMap<(String, String), [u8; 64]>>;

fn cache() -> &'static KeyCache {
    static CACHE: OnceLock<KeyCache> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// A key holder for an ASCII full name, derived once (v3) and reused.
pub fn keys(name: &str, password: &str) -> UserKeys {
    assert!(name.is_ascii(), "the cache only works for ASCII names");
    let bytes = {
        let mut cache = cache().lock().unwrap();
        *cache.entry((name.into(), password.into())).or_insert_with(|| {
            *MasterKey::derive(name, password, AlgorithmVersion::V3).unwrap().as_bytes()
        })
    };
    UserKeys::from_key(name, MasterKey::from_bytes(bytes, AlgorithmVersion::V3))
}

pub fn robert() -> UserKeys {
    keys(NAME, PASSWORD)
}

pub fn robert_other() -> UserKeys {
    keys(NAME, OTHER_PASSWORD)
}

pub fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"))
}

pub fn fixture_str(name: &str) -> String {
    String::from_utf8(fixture(name)).unwrap()
}

/// A fresh, uniquely named directory under the system temp dir; removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let dir = std::env::temp_dir().join(format!(
            "mpw-model-test-{tag}-{}-{}-{nanos}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Restore permissions a test may have removed, then clean up.
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Replace the `Date` header / `export.date` so outputs can be compared.
pub fn without_date(s: &str) -> String {
    s.lines()
        .map(|l| {
            if l.starts_with("# Date: ") {
                "# Date: <date>".to_owned()
            } else if l.trim_start().starts_with("\"date\": ") {
                "\"date\": <date>".to_owned()
            } else {
                l.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
