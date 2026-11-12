//! User preferences.  Non-secret values only; stored in `NSUserDefaults` by
//! the platform layer (`platform::defaults`), in memory in tests.

use std::collections::HashMap;
use std::time::Duration;

/// Key-value backing store for preferences.
pub trait PrefsStore {
    fn get_bool(&self, key: &str) -> Option<bool>;
    fn set_bool(&mut self, key: &str, value: bool);
    fn get_int(&self, key: &str) -> Option<i64>;
    fn set_int(&mut self, key: &str, value: i64);
    fn get_string(&self, key: &str) -> Option<String>;
    fn set_string(&mut self, key: &str, value: Option<&str>);
}

pub const KEY_HIDE_PASSWORDS: &str = "hidePasswords";
pub const KEY_REMEMBER_PASSWORD: &str = "rememberPassword";
pub const KEY_CLIPBOARD_CLEAR_SECONDS: &str = "clipboardClearSeconds";
pub const KEY_IDLE_LOCK_MINUTES: &str = "idleLockMinutes";
pub const KEY_WELCOME_SHOWN: &str = "welcomeShown";
pub const KEY_LAST_FULL_NAME: &str = "lastFullName";

/// Choices offered in the menu.  0 = never.
pub const CLIPBOARD_CLEAR_CHOICES: [u32; 5] = [15, 30, 60, 120, 0];
pub const IDLE_LOCK_CHOICES: [u32; 6] = [1, 5, 15, 30, 60, 0];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preferences {
    /// Mask generated passwords; hold ⌥ to reveal.
    pub hide_passwords: bool,
    /// Keep the master key while the app runs.  Off: lock whenever the sites
    /// window closes (the original's default).
    pub remember_password: bool,
    /// Clear a copied password after this many seconds (0 = never).
    pub clipboard_clear_seconds: u32,
    /// Lock after this many minutes without interaction (0 = never).
    pub idle_lock_minutes: u32,
    pub welcome_shown: bool,
    /// Pre-filled in the sites window.  Not secret (the original stored it too).
    pub last_full_name: Option<String>,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            hide_passwords: false,
            remember_password: false,
            clipboard_clear_seconds: 60,
            idle_lock_minutes: 15,
            welcome_shown: false,
            last_full_name: None,
        }
    }
}

fn clamp_u32(v: i64, max: u32) -> u32 {
    v.clamp(0, i64::from(max)) as u32
}

impl Preferences {
    pub fn load(store: &dyn PrefsStore) -> Self {
        let d = Self::default();
        Self {
            hide_passwords: store.get_bool(KEY_HIDE_PASSWORDS).unwrap_or(d.hide_passwords),
            remember_password: store.get_bool(KEY_REMEMBER_PASSWORD).unwrap_or(d.remember_password),
            // Garbage written with `defaults write` is clamped, never trusted.
            clipboard_clear_seconds: store
                .get_int(KEY_CLIPBOARD_CLEAR_SECONDS)
                .map_or(d.clipboard_clear_seconds, |v| clamp_u32(v, 24 * 3600)),
            idle_lock_minutes: store
                .get_int(KEY_IDLE_LOCK_MINUTES)
                .map_or(d.idle_lock_minutes, |v| clamp_u32(v, 24 * 60)),
            welcome_shown: store.get_bool(KEY_WELCOME_SHOWN).unwrap_or(d.welcome_shown),
            last_full_name: store
                .get_string(KEY_LAST_FULL_NAME)
                .filter(|s| !s.trim().is_empty() && s.len() < 1024),
        }
    }

    pub fn save(&self, store: &mut dyn PrefsStore) {
        store.set_bool(KEY_HIDE_PASSWORDS, self.hide_passwords);
        store.set_bool(KEY_REMEMBER_PASSWORD, self.remember_password);
        store.set_int(KEY_CLIPBOARD_CLEAR_SECONDS, i64::from(self.clipboard_clear_seconds));
        store.set_int(KEY_IDLE_LOCK_MINUTES, i64::from(self.idle_lock_minutes));
        store.set_bool(KEY_WELCOME_SHOWN, self.welcome_shown);
        store.set_string(KEY_LAST_FULL_NAME, self.last_full_name.as_deref());
    }

    pub fn clipboard_timeout(&self) -> Option<Duration> {
        (self.clipboard_clear_seconds > 0).then(|| Duration::from_secs(self.clipboard_clear_seconds.into()))
    }

    pub fn idle_timeout(&self) -> Option<Duration> {
        (self.idle_lock_minutes > 0).then(|| Duration::from_secs(u64::from(self.idle_lock_minutes) * 60))
    }
}

/// A [`PrefsStore`] in memory, for tests and the smoke test.
#[derive(Debug, Default, Clone)]
pub struct MemoryPrefs {
    bools: HashMap<String, bool>,
    ints: HashMap<String, i64>,
    strings: HashMap<String, String>,
}

impl PrefsStore for MemoryPrefs {
    fn get_bool(&self, key: &str) -> Option<bool> {
        self.bools.get(key).copied()
    }
    fn set_bool(&mut self, key: &str, value: bool) {
        self.bools.insert(key.into(), value);
    }
    fn get_int(&self, key: &str) -> Option<i64> {
        self.ints.get(key).copied()
    }
    fn set_int(&mut self, key: &str, value: i64) {
        self.ints.insert(key.into(), value);
    }
    fn get_string(&self, key: &str) -> Option<String> {
        self.strings.get(key).cloned()
    }
    fn set_string(&mut self, key: &str, value: Option<&str>) {
        match value {
            Some(v) => self.strings.insert(key.into(), v.into()),
            None => self.strings.remove(key),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_empty() {
        let p = Preferences::load(&MemoryPrefs::default());
        assert_eq!(p, Preferences::default());
        assert_eq!(p.clipboard_timeout(), Some(Duration::from_secs(60)));
        assert_eq!(p.idle_timeout(), Some(Duration::from_secs(15 * 60)));
        assert!(!p.remember_password);
    }

    #[test]
    fn round_trips() {
        let mut store = MemoryPrefs::default();
        let p = Preferences {
            hide_passwords: true,
            remember_password: true,
            clipboard_clear_seconds: 0,
            idle_lock_minutes: 0,
            welcome_shown: true,
            last_full_name: Some("Robert Lee Mitchell".into()),
        };
        p.save(&mut store);
        let loaded = Preferences::load(&store);
        assert_eq!(loaded, p);
        assert_eq!(loaded.clipboard_timeout(), None);
        assert_eq!(loaded.idle_timeout(), None);
    }

    #[test]
    fn hostile_values_are_clamped() {
        let mut store = MemoryPrefs::default();
        store.set_int(KEY_CLIPBOARD_CLEAR_SECONDS, -5);
        store.set_int(KEY_IDLE_LOCK_MINUTES, i64::MAX);
        store.set_string(KEY_LAST_FULL_NAME, Some("   "));
        let p = Preferences::load(&store);
        assert_eq!(p.clipboard_clear_seconds, 0);
        assert_eq!(p.idle_lock_minutes, 24 * 60);
        assert_eq!(p.last_full_name, None);
    }
}
