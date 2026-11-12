//! `NSUserDefaults` behind [`crate::prefs::PrefsStore`].  Non-secret values only.

use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::NSUserDefaults;

use super::ns;
use crate::prefs::PrefsStore;

pub struct UserDefaults {
    defaults: Retained<NSUserDefaults>,
    /// Set for a throwaway suite that is deleted on drop.
    throwaway_suite: Option<String>,
}

impl UserDefaults {
    /// The app's defaults: the standard domain when bundled (the bundle id),
    /// otherwise the same `com.github.howler4695.masterpwd` domain via a suite,
    /// so `cargo run` and the bundled app share preferences.
    pub fn app() -> Self {
        if super::is_bundled() {
            return Self { defaults: NSUserDefaults::standardUserDefaults(), throwaway_suite: None };
        }
        let defaults = NSUserDefaults::initWithSuiteName(NSUserDefaults::alloc(), Some(&ns(crate::BUNDLE_ID)))
            .unwrap_or_else(NSUserDefaults::standardUserDefaults);
        Self { defaults, throwaway_suite: None }
    }

    /// A suite that is wiped when dropped (smoke test).
    pub fn throwaway(suite: &str) -> Option<Self> {
        let defaults = NSUserDefaults::initWithSuiteName(NSUserDefaults::alloc(), Some(&ns(suite)))?;
        defaults.removePersistentDomainForName(&ns(suite));
        Some(Self { defaults, throwaway_suite: Some(suite.to_owned()) })
    }
}

impl Drop for UserDefaults {
    fn drop(&mut self) {
        if let Some(suite) = &self.throwaway_suite {
            self.defaults.removePersistentDomainForName(&ns(suite));
        }
    }
}

impl PrefsStore for UserDefaults {
    fn get_bool(&self, key: &str) -> Option<bool> {
        let key = ns(key);
        self.defaults.objectForKey(&key)?;
        Some(self.defaults.boolForKey(&key))
    }
    fn set_bool(&mut self, key: &str, value: bool) {
        self.defaults.setBool_forKey(value, &ns(key));
    }
    fn get_int(&self, key: &str) -> Option<i64> {
        let key = ns(key);
        self.defaults.objectForKey(&key)?;
        Some(self.defaults.integerForKey(&key) as i64)
    }
    fn set_int(&mut self, key: &str, value: i64) {
        self.defaults.setInteger_forKey(value as isize, &ns(key));
    }
    fn get_string(&self, key: &str) -> Option<String> {
        self.defaults.stringForKey(&ns(key)).map(|s| s.to_string())
    }
    fn set_string(&mut self, key: &str, value: Option<&str>) {
        let key = ns(key);
        match value {
            // SAFETY: an NSString is a valid property-list object for defaults.
            Some(v) => unsafe { self.defaults.setObject_forKey(Some(&ns(v)), &key) },
            None => self.defaults.removeObjectForKey(&key),
        }
    }
}
