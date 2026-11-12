//! The seam between the app and storage: [`DataStore`].
//!
//! Users and sites are `mpw-model` types ([`User`], [`UserKeys`]).  A
//! `DataStore` persists them; [`DiskStore`] wraps `mpw_model::UserStore`
//! (one `.mpjson` per user, atomic `0600` writes) and [`MemoryStore`] keeps
//! them in memory for tests.  Everything else (sessions, sites, results) is
//! `mpw-model` logic driven by [`crate::view_model`].
//!
//! Saving is debounced and happens on a background thread ([`SaveQueue`]);
//! failures are collected and shown to the user, never dropped.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use mpw_model::{Error as ModelError, User, UserKeys, UserStore};

/// A user as listed in the picker.  Nothing secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEntry {
    pub full_name: String,
    pub avatar: u32,
    /// Unix seconds.
    pub last_used: i64,
    pub site_count: usize,
    /// The user's "Save Password" preference (`biometric_lock` in the file).
    pub saved_keys: bool,
    /// The user's own "hide passwords" preference.
    pub mask_passwords: bool,
    /// The user's second factor (slots hold wrapped secrets and fingerprints;
    /// nothing identifying).
    pub second_factor: mpw_model::SecondFactorStatus,
}

/// Errors shown to the user.  Never contain secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    WrongMasterPassword { full_name: String },
    UserExists,
    UserNotFound,
    Model(String),
    Io(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongMasterPassword { full_name } => write!(f, "Incorrect master password for {full_name}."),
            Self::UserExists => f.write_str("A user with that name already exists."),
            Self::UserNotFound => f.write_str("That user no longer exists."),
            Self::Model(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "Could not access the user files: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl StoreError {
    /// Map an `mpw-model` error, naming the user for a wrong password.
    pub fn from_model(e: ModelError, full_name: &str) -> Self {
        match e {
            ModelError::WrongMasterPassword => Self::WrongMasterPassword { full_name: full_name.to_owned() },
            ModelError::UserExists => Self::UserExists,
            ModelError::UserNotFound => Self::UserNotFound,
            ModelError::Io(e) => Self::Io(e.to_string()),
            other => Self::Model(capitalise(&other.to_string())),
        }
    }
}

pub(crate) fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// Persistence of users.  Implementations are shared with the save thread.
pub trait DataStore: Send + Sync {
    /// Known users, most recently used first.
    fn list(&self) -> Result<Vec<UserEntry>, StoreError>;
    /// Load a user and authenticate `keys` against its key ID
    /// (`User::authenticate`).  A wrong key is `WrongMasterPassword`.
    fn load(&self, full_name: &str, keys: &mut UserKeys) -> Result<User, StoreError>;
    /// Store a user that does not exist yet.
    fn create(&self, user: &User) -> Result<(), StoreError>;
    /// Replace a stored user (atomic).  Called from the save thread.
    fn save(&self, user: &User) -> Result<(), StoreError>;
    fn delete(&self, full_name: &str) -> Result<(), StoreError>;
    /// Where the users live (for messages).
    fn location(&self) -> String;
}

// ----------------------------------------------------------------- disk

/// `mpw_model::UserStore` (the default: `~/Library/Application Support/MasterPwd/Users`,
/// inside the container when sandboxed).
pub struct DiskStore {
    store: UserStore,
}

/// Test-only override of the store directory (documented in the README of
/// the app crate and used by the smoke test).
pub const STORE_DIR_ENV: &str = "MASTERPWD_STORE_DIR";

impl DiskStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let store = UserStore::open(dir).map_err(|e| StoreError::from_model(e, ""))?;
        Ok(Self { store })
    }

    /// `$MASTERPWD_STORE_DIR` if set, else the default directory.
    pub fn open_default() -> Result<Self, StoreError> {
        match std::env::var_os(STORE_DIR_ENV).filter(|d| !d.is_empty()) {
            Some(dir) => Self::open(PathBuf::from(dir)),
            None => {
                let store = UserStore::open_default().map_err(|e| StoreError::from_model(e, ""))?;
                Ok(Self { store })
            }
        }
    }

    pub fn dir(&self) -> &Path {
        self.store.dir()
    }
}

impl DataStore for DiskStore {
    fn list(&self) -> Result<Vec<UserEntry>, StoreError> {
        let listing = self.store.list().map_err(|e| StoreError::from_model(e, ""))?;
        Ok(listing
            .users
            .into_iter()
            .map(|u| UserEntry {
                full_name: u.summary.full_name,
                avatar: u.summary.avatar,
                last_used: u.summary.last_used.as_unix(),
                site_count: u.summary.site_count,
                saved_keys: u.summary.preferences.biometric_lock,
                mask_passwords: u.summary.preferences.mask_passwords,
                second_factor: u.summary.second_factor,
            })
            .collect())
    }

    fn load(&self, full_name: &str, keys: &mut UserKeys) -> Result<User, StoreError> {
        self.store.load(full_name, keys).map_err(|e| StoreError::from_model(e, full_name))
    }

    fn create(&self, user: &User) -> Result<(), StoreError> {
        self.store.create(user).map(drop).map_err(|e| StoreError::from_model(e, user.full_name()))
    }

    fn save(&self, user: &User) -> Result<(), StoreError> {
        self.store.save(user).map(drop).map_err(|e| StoreError::from_model(e, user.full_name()))
    }

    fn delete(&self, full_name: &str) -> Result<(), StoreError> {
        self.store.delete(full_name).map_err(|e| StoreError::from_model(e, full_name))
    }

    fn location(&self) -> String {
        self.store.dir().display().to_string()
    }
}

// --------------------------------------------------------------- memory

/// Users in memory (tests).  Optionally fails saves, to test error paths.
#[derive(Default)]
pub struct MemoryStore {
    users: Mutex<BTreeMap<String, User>>,
    pub fail_saves: Mutex<bool>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// A stored copy (tests).
    pub fn get(&self, full_name: &str) -> Option<User> {
        self.users.lock().ok()?.get(full_name).cloned()
    }
}

impl DataStore for MemoryStore {
    fn list(&self) -> Result<Vec<UserEntry>, StoreError> {
        let users = self.users.lock().map_err(|_| StoreError::Io("poisoned".into()))?;
        let mut list: Vec<UserEntry> = users
            .values()
            .map(|u| UserEntry {
                full_name: u.full_name().to_owned(),
                avatar: u.avatar,
                last_used: u.last_used.as_unix(),
                site_count: u.sites().len(),
                saved_keys: u.preferences.biometric_lock,
                mask_passwords: u.preferences.mask_passwords,
                second_factor: u.second_factor_status().clone(),
            })
            .collect();
        list.sort_by(|a, b| b.last_used.cmp(&a.last_used).then(a.full_name.cmp(&b.full_name)));
        Ok(list)
    }

    fn load(&self, full_name: &str, keys: &mut UserKeys) -> Result<User, StoreError> {
        let mut user = self
            .users
            .lock()
            .map_err(|_| StoreError::Io("poisoned".into()))?
            .get(full_name)
            .cloned()
            .ok_or(StoreError::UserNotFound)?;
        user.authenticate(keys).map_err(|e| StoreError::from_model(e, full_name))?;
        Ok(user)
    }

    fn create(&self, user: &User) -> Result<(), StoreError> {
        let mut users = self.users.lock().map_err(|_| StoreError::Io("poisoned".into()))?;
        if users.contains_key(user.full_name()) {
            return Err(StoreError::UserExists);
        }
        users.insert(user.full_name().to_owned(), user.clone());
        Ok(())
    }

    fn save(&self, user: &User) -> Result<(), StoreError> {
        if self.fail_saves.lock().is_ok_and(|f| *f) {
            return Err(StoreError::Io("disk full (simulated)".into()));
        }
        self.users
            .lock()
            .map_err(|_| StoreError::Io("poisoned".into()))?
            .insert(user.full_name().to_owned(), user.clone());
        Ok(())
    }

    fn delete(&self, full_name: &str) -> Result<(), StoreError> {
        self.users
            .lock()
            .map_err(|_| StoreError::Io("poisoned".into()))?
            .remove(full_name)
            .map(drop)
            .ok_or(StoreError::UserNotFound)
    }

    fn location(&self) -> String {
        "memory".into()
    }
}

// ----------------------------------------------------------- save queue

enum Job {
    Save(Box<User>),
    /// Reply once everything before it has been written.
    Flush(Sender<()>),
}

/// Writes users on a background thread, in order.  Errors are kept until
/// [`SaveQueue::take_errors`].
pub struct SaveQueue {
    store: Arc<dyn DataStore>,
    errors: Arc<Mutex<Vec<String>>>,
    worker: Option<(Sender<Job>, JoinHandle<()>)>,
}

impl SaveQueue {
    /// Background writer.
    pub fn threaded(store: Arc<dyn DataStore>) -> Self {
        let errors = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = mpsc::channel::<Job>();
        let (store2, errors2) = (store.clone(), errors.clone());
        let spawned = std::thread::Builder::new().name("mpw-save".into()).spawn(move || {
            for job in rx {
                match job {
                    Job::Save(user) => {
                        if let Err(e) = store2.save(&user) {
                            if let Ok(mut errs) = errors2.lock() {
                                errs.push(format!("Could not save {}: {e}", user.full_name()));
                            }
                        }
                    }
                    Job::Flush(done) => {
                        let _ = done.send(());
                    }
                }
            }
        });
        match spawned {
            Ok(handle) => Self { store, errors, worker: Some((tx, handle)) },
            // No thread: fall back to saving inline.
            Err(_) => Self { store, errors, worker: None },
        }
    }

    /// Saves synchronously (tests).
    pub fn inline(store: Arc<dyn DataStore>) -> Self {
        Self { store, errors: Arc::new(Mutex::new(Vec::new())), worker: None }
    }

    pub fn store(&self) -> &Arc<dyn DataStore> {
        &self.store
    }

    /// Queue a copy of `user` for writing.  The copy holds only what the file
    /// holds (stored values stay encrypted).
    pub fn submit(&self, user: &User) {
        match &self.worker {
            Some((tx, _)) if tx.send(Job::Save(Box::new(user.clone()))).is_ok() => {}
            _ => {
                if let Err(e) = self.store.save(user) {
                    if let Ok(mut errs) = self.errors.lock() {
                        errs.push(format!("Could not save {}: {e}", user.full_name()));
                    }
                }
            }
        }
    }

    /// Wait until every queued save has been written (bounded wait).
    pub fn flush(&self) {
        if let Some((tx, _)) = &self.worker {
            let (done_tx, done_rx) = mpsc::channel();
            if tx.send(Job::Flush(done_tx)).is_ok() {
                let _ = done_rx.recv_timeout(Duration::from_secs(10));
            }
        }
    }

    pub fn take_errors(&self) -> Vec<String> {
        self.errors.lock().map(|mut e| std::mem::take(&mut *e)).unwrap_or_default()
    }
}

impl Drop for SaveQueue {
    fn drop(&mut self) {
        self.flush();
        if let Some((tx, handle)) = self.worker.take() {
            drop(tx);
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str) -> (User, UserKeys) {
        let mut user = User::new(name).unwrap();
        let mut keys = UserKeys::from_password(name, "pw");
        user.authenticate(&mut keys).unwrap();
        (user, keys)
    }

    #[test]
    fn memory_store_round_trip_and_key_check() {
        let store = MemoryStore::new();
        let (u, _) = user("Ann");
        store.create(&u).unwrap();
        assert_eq!(store.create(&u), Err(StoreError::UserExists));
        assert_eq!(store.list().unwrap()[0].full_name, "Ann");
        assert!(store.load("Ann", &mut UserKeys::from_password("Ann", "pw")).is_ok());
        assert_eq!(
            store.load("Ann", &mut UserKeys::from_password("Ann", "nope")).unwrap_err(),
            StoreError::WrongMasterPassword { full_name: "Ann".into() }
        );
        store.delete("Ann").unwrap();
        assert_eq!(store.delete("Ann"), Err(StoreError::UserNotFound));
    }

    #[test]
    fn disk_store_round_trip() {
        let dir = std::env::temp_dir().join(format!("masterpwd-test-store-{}", std::process::id()));
        let store = DiskStore::open(&dir).unwrap();
        let (mut u, _) = user("Bob Ä");
        u.add_site("example.com").unwrap();
        store.create(&u).unwrap();
        let listed = store.list().unwrap();
        assert_eq!((listed[0].full_name.as_str(), listed[0].site_count), ("Bob Ä", 1));
        let loaded = store.load("Bob Ä", &mut UserKeys::from_password("Bob Ä", "pw")).unwrap();
        assert!(loaded.site("example.com").is_some());
        store.delete("Bob Ä").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn threaded_queue_saves_in_order_and_reports_errors() {
        let mem = Arc::new(MemoryStore::new());
        let queue = SaveQueue::threaded(mem.clone());
        let (mut u, _) = user("Cy");
        for i in 0..20 {
            u.avatar = i;
            queue.submit(&u);
        }
        queue.flush();
        assert_eq!(mem.get("Cy").unwrap().avatar, 19);
        *mem.fail_saves.lock().unwrap() = true;
        queue.submit(&u);
        queue.flush();
        let errors = queue.take_errors();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("Could not save Cy"), "{errors:?}");
        assert!(queue.take_errors().is_empty());
    }
}
