//! The seam between the app and "the data layer".
//!
//! Everything the UI needs to know about users and sites goes through
//! [`DataStore`].  This round it is backed by [`MemoryStore`] (one ad-hoc user
//! per full name, sites remembered for the session only).  Next round it gets
//! backed by `mpw-model` without touching the view-model or the AppKit layer.
//!
//! Unlocking is split in three so the slow part never runs on the main thread
//! and never needs access to the store:
//!
//! 1. [`DataStore::begin_auth`] (main thread, fast): which algorithm versions
//!    to derive keys for.
//! 2. [`KeyRing::derive`] (background thread, slow scrypt, pure function).
//! 3. [`DataStore::finish_auth`] (main thread, fast): check the key against
//!    the user's stored key ID, create the user if new.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::time::SystemTime;

use mpw_core::{
    AlgorithmVersion, Counter, KeyId, MasterKey, ResultType, COUNTER_DEFAULT,
};

/// Identifies a user within a [`DataStore`].  Not secret (it is the full name
/// today; `mpw-model` may use a file name).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId(pub String);

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What the menu and sites window show about a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSummary {
    pub id: UserId,
    pub full_name: String,
    pub avatar: u32,
    pub last_used: Option<SystemTime>,
}

/// Instructions for the background key derivation.  Contains no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPlan {
    pub full_name: String,
    /// The user's own algorithm version.  Its key is checked against the
    /// stored key ID.
    pub algorithm: AlgorithmVersion,
    /// Further versions some of the user's sites still use.
    pub extra_algorithms: Vec<AlgorithmVersion>,
}

impl AuthPlan {
    pub fn algorithms(&self) -> Vec<AlgorithmVersion> {
        let mut all = vec![self.algorithm];
        for v in &self.extra_algorithms {
            if !all.contains(v) {
                all.push(*v);
            }
        }
        all
    }
}

/// The master keys of an unlocked user, one per algorithm version needed.
///
/// [`MasterKey`] wipes itself on drop, so dropping the ring is locking.
/// Deliberately neither `Clone` nor `Debug`-revealing.
pub struct KeyRing {
    keys: Vec<MasterKey>,
}

impl KeyRing {
    /// Derive all keys the plan asks for.  SLOW (scrypt per version): call it
    /// off the main thread.
    pub fn derive(
        full_name: &str,
        master_password: &str,
        plan: &AuthPlan,
    ) -> Result<Self, mpw_core::Error> {
        let keys = plan
            .algorithms()
            .into_iter()
            .map(|v| MasterKey::derive(full_name, master_password, v))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { keys })
    }

    /// Build a ring from keys obtained elsewhere (e.g. the keychain).  The
    /// first key is the primary one.  Returns `None` if `keys` is empty.
    pub fn from_keys(keys: Vec<MasterKey>) -> Option<Self> {
        (!keys.is_empty()).then_some(Self { keys })
    }

    /// The key of the user's own algorithm version.
    pub fn primary(&self) -> &MasterKey {
        &self.keys[0]
    }

    pub fn get(&self, algorithm: AlgorithmVersion) -> Option<&MasterKey> {
        self.keys.iter().find(|k| k.algorithm() == algorithm)
    }
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyRing(<{} redacted keys>)", self.keys.len())
    }
}

/// A site's settings: everything needed to compute its results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteSettings {
    pub name: String,
    pub algorithm: AlgorithmVersion,
    pub result_type: ResultType,
    pub counter: Counter,
    /// Encrypted state for stateful password types (`result_param`).
    pub result_state: Option<String>,
    pub login_type: ResultType,
    /// Encrypted state for a stateful login name.
    pub login_state: Option<String>,
    pub uses: u32,
    pub last_used: Option<SystemTime>,
    /// `false` for a site the user has typed but never used (not yet stored).
    pub known: bool,
}

impl SiteSettings {
    /// Settings for a site that isn't stored yet.
    pub fn new(name: &str, algorithm: AlgorithmVersion, result_type: ResultType) -> Self {
        Self {
            name: name.to_owned(),
            algorithm,
            result_type,
            counter: COUNTER_DEFAULT,
            result_state: None,
            login_type: ResultType::DEFAULT_LOGIN,
            login_state: None,
            uses: 0,
            last_used: None,
            known: false,
        }
    }
}

/// Errors from the data layer.  Messages are shown to the user verbatim and
/// never contain secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    WrongMasterPassword { full_name: String },
    UnknownUser,
    Algorithm(mpw_core::Error),
    Storage(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongMasterPassword { full_name } => {
                write!(f, "Incorrect master password for {full_name}.")
            }
            Self::UnknownUser => f.write_str("That user no longer exists."),
            Self::Algorithm(e) => write!(f, "{e}"),
            Self::Storage(e) => write!(f, "Could not save: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<mpw_core::Error> for StoreError {
    fn from(e: mpw_core::Error) -> Self {
        Self::Algorithm(e)
    }
}

/// Everything the UI needs from the data layer.  All methods are called on
/// the main thread and must be fast (no key derivation in here).
pub trait DataStore {
    /// Known users, most recently used first.
    fn users(&self) -> Vec<UserSummary>;

    /// Step 1 of unlocking: what to derive for `full_name` (known or new).
    fn begin_auth(&self, full_name: &str) -> AuthPlan;

    /// Step 3 of unlocking: verify freshly derived keys (key ID check) and
    /// return the user, creating it if it is new.
    fn finish_auth(&mut self, plan: &AuthPlan, keys: &KeyRing) -> Result<UserId, StoreError>;

    /// Site names matching `query` (in-order, case-insensitive character
    /// match), best first, at most `limit`.
    fn complete_sites(&self, user: &UserId, query: &str, limit: usize) -> Vec<String>;

    /// The stored settings of `name`, or defaults for a new site.
    fn site(&self, user: &UserId, name: &str) -> Result<SiteSettings, StoreError>;

    /// Store changed settings (creates the site if needed).
    fn update_site(&mut self, user: &UserId, site: &SiteSettings) -> Result<(), StoreError>;

    /// The user used the site's result: bump its use count and last-used time
    /// (creating the site if needed).
    fn record_use(&mut self, user: &UserId, site: &SiteSettings) -> Result<(), StoreError>;

    /// Write pending changes to disk.
    fn persist(&mut self) -> Result<(), StoreError>;
}

// ------------------------------------------------------------ in-memory store

#[derive(Debug)]
struct MemUser {
    key_id: Option<KeyId>,
    algorithm: AlgorithmVersion,
    default_type: ResultType,
    sites: BTreeMap<String, SiteSettings>,
    last_used: Option<SystemTime>,
}

/// Round-1 store: users and sites live for the session only.
#[derive(Debug, Default)]
pub struct MemoryStore {
    users: HashMap<String, MemUser>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn user(&self, id: &UserId) -> Result<&MemUser, StoreError> {
        self.users.get(&id.0).ok_or(StoreError::UnknownUser)
    }

    fn user_mut(&mut self, id: &UserId) -> Result<&mut MemUser, StoreError> {
        self.users.get_mut(&id.0).ok_or(StoreError::UnknownUser)
    }
}

/// In-order, case-insensitive character match (`gml` matches `gmail.com`),
/// like the original's `*g*m*l*` LIKE pattern.
pub fn fuzzy_matches(name: &str, query: &str) -> bool {
    let mut haystack = name.chars().flat_map(char::to_lowercase);
    query
        .chars()
        .flat_map(char::to_lowercase)
        .all(|q| haystack.any(|h| h == q))
}

impl DataStore for MemoryStore {
    fn users(&self) -> Vec<UserSummary> {
        let mut users: Vec<_> = self
            .users
            .iter()
            .map(|(name, u)| UserSummary {
                id: UserId(name.clone()),
                full_name: name.clone(),
                avatar: 0,
                last_used: u.last_used,
            })
            .collect();
        users.sort_by(|a, b| b.last_used.cmp(&a.last_used).then(a.full_name.cmp(&b.full_name)));
        users
    }

    fn begin_auth(&self, full_name: &str) -> AuthPlan {
        let (algorithm, mut extra) = match self.users.get(full_name) {
            Some(u) => (u.algorithm, u.sites.values().map(|s| s.algorithm).collect()),
            None => (AlgorithmVersion::CURRENT, Vec::new()),
        };
        extra.sort();
        extra.dedup();
        extra.retain(|v| *v != algorithm);
        AuthPlan { full_name: full_name.to_owned(), algorithm, extra_algorithms: extra }
    }

    fn finish_auth(&mut self, plan: &AuthPlan, keys: &KeyRing) -> Result<UserId, StoreError> {
        let key = keys.get(plan.algorithm).unwrap_or_else(|| keys.primary());
        let key_id = key.key_id();
        let user = self.users.entry(plan.full_name.clone()).or_insert_with(|| MemUser {
            key_id: None,
            algorithm: plan.algorithm,
            default_type: ResultType::DEFAULT,
            sites: BTreeMap::new(),
            last_used: None,
        });
        match &user.key_id {
            Some(known) if *known != key_id => {
                return Err(StoreError::WrongMasterPassword { full_name: plan.full_name.clone() })
            }
            Some(_) => {}
            None => user.key_id = Some(key_id),
        }
        user.last_used = Some(SystemTime::now());
        Ok(UserId(plan.full_name.clone()))
    }

    fn complete_sites(&self, user: &UserId, query: &str, limit: usize) -> Vec<String> {
        let Ok(user) = self.user(user) else { return Vec::new() };
        let mut matches: Vec<&SiteSettings> =
            user.sites.values().filter(|s| fuzzy_matches(&s.name, query)).collect();
        // Exact (case-insensitive) match first, then prefix matches, then most
        // recently used.
        let q = query.to_lowercase();
        matches.sort_by_key(|s| {
            let n = s.name.to_lowercase();
            (n != q, !n.starts_with(&q), std::cmp::Reverse(s.last_used), s.name.clone())
        });
        matches.into_iter().take(limit).map(|s| s.name.clone()).collect()
    }

    fn site(&self, user: &UserId, name: &str) -> Result<SiteSettings, StoreError> {
        let user = self.user(user)?;
        Ok(user
            .sites
            .get(name)
            .cloned()
            .unwrap_or_else(|| SiteSettings::new(name, user.algorithm, user.default_type)))
    }

    fn update_site(&mut self, user: &UserId, site: &SiteSettings) -> Result<(), StoreError> {
        let user = self.user_mut(user)?;
        let mut site = site.clone();
        site.known = true;
        user.sites.insert(site.name.clone(), site);
        Ok(())
    }

    fn record_use(&mut self, user: &UserId, site: &SiteSettings) -> Result<(), StoreError> {
        let now = SystemTime::now();
        let user = self.user_mut(user)?;
        user.last_used = Some(now);
        let entry = user.sites.entry(site.name.clone()).or_insert_with(|| site.clone());
        entry.known = true;
        entry.uses = entry.uses.saturating_add(1);
        entry.last_used = Some(now);
        Ok(())
    }

    fn persist(&mut self) -> Result<(), StoreError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzzy_matching() {
        assert!(fuzzy_matches("gmail.com", "gml"));
        assert!(fuzzy_matches("GMail.com", "gMa"));
        assert!(fuzzy_matches("anything", ""));
        assert!(!fuzzy_matches("gmail.com", "lmg"));
        assert!(!fuzzy_matches("abc", "abcd"));
    }

    #[test]
    fn plan_lists_each_algorithm_once() {
        let plan = AuthPlan {
            full_name: "x".into(),
            algorithm: AlgorithmVersion::V3,
            extra_algorithms: vec![AlgorithmVersion::V1, AlgorithmVersion::V3, AlgorithmVersion::V1],
        };
        assert_eq!(plan.algorithms(), vec![AlgorithmVersion::V3, AlgorithmVersion::V1]);
    }

    #[test]
    fn unknown_user_is_an_error_not_a_panic() {
        let store = MemoryStore::new();
        assert_eq!(store.site(&UserId("nobody".into()), "a"), Err(StoreError::UnknownUser));
        assert!(store.complete_sites(&UserId("nobody".into()), "", 10).is_empty());
        assert_eq!(store.begin_auth("New Person").algorithm, AlgorithmVersion::CURRENT);
    }

    fn ring(byte: u8) -> KeyRing {
        KeyRing::from_keys(vec![MasterKey::from_bytes([byte; 64], AlgorithmVersion::V3)]).unwrap()
    }

    #[test]
    fn memory_store_remembers_sites_and_checks_key_id() {
        let mut store = MemoryStore::new();
        let plan = store.begin_auth("Robert");
        let user = store.finish_auth(&plan, &ring(1)).unwrap();
        // Same key again: fine.  A different key: wrong password.
        assert_eq!(store.finish_auth(&plan, &ring(1)).unwrap(), user);
        assert_eq!(
            store.finish_auth(&plan, &ring(2)),
            Err(StoreError::WrongMasterPassword { full_name: "Robert".into() })
        );

        let mut site = store.site(&user, "gmail.com").unwrap();
        assert!(!site.known);
        assert_eq!(site.result_type, ResultType::DEFAULT);
        site.counter = 3;
        store.record_use(&user, &site).unwrap();
        store.record_use(&user, &store.site(&user, "github.com").unwrap()).unwrap();
        let stored = store.site(&user, "gmail.com").unwrap();
        assert!(stored.known);
        assert_eq!((stored.counter, stored.uses), (3, 1));
        assert_eq!(store.complete_sites(&user, "gma", 10), vec!["gmail.com".to_string()]);
        assert_eq!(store.complete_sites(&user, "g", 10).len(), 2);
        assert_eq!(store.complete_sites(&user, "g", 1).len(), 1);
        assert_eq!(store.users().len(), 1);
    }
}
