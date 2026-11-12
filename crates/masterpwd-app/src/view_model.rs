//! The sites window as a state machine over `mpw-model`, free of AppKit.
//!
//! Screens: pick a user (or create one) → unlocking → unlocked (sites).  The
//! unlocked session holds the decrypted [`User`] and a password-less
//! [`UserKeys`]; locking flushes pending changes and drops both.
//!
//! The AppKit layer forwards input to the methods here, executes the returned
//! [`VmEffect`]s and renders [`SitesViewModel::view`].  Every input is
//! validated; errors end up in [`SitesView::error`], never in a panic.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mpw_core::{AlgorithmVersion, Counter, Identicon, KeyPurpose, ResultType, Zeroizing, COUNTER_INITIAL};
use mpw_model::{User, UserKeys};

use crate::data::{capitalise, DataStore, SaveQueue, StoreError, UserEntry};
use crate::keys::{DeriveJob, DerivePurpose, Derived};
use crate::prompt::{ButtonRole, Prompt, PromptAnswer, Style};

/// Pause in typing before the identicon is shown.
pub const IDENTICON_DELAY: Duration = Duration::from_millis(800);
/// Changes are written this long after the last edit (or at lock/quit).
pub const SAVE_DELAY: Duration = Duration::from_millis(1500);
/// The most sites listed.
pub const SITE_LIST_LIMIT: usize = 200;
pub const COUNTER_MAX: Counter = 9_999;
/// Number of avatar images (`avatar-0` … `avatar-18`).
pub const AVATAR_COUNT: u32 = 19;

/// Side effects the platform layer must carry out.
pub enum VmEffect {
    Derive(DeriveJob),
    ScheduleIdenticon { generation: u64, delay: Duration },
    Copy { text: Zeroizing<String> },
    CloseWindow,
    /// Ask the user; feed the answer to [`SitesViewModel::answer`].
    Ask(Ask),
}

impl fmt::Debug for VmEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Derive(j) => write!(f, "Derive({j:?})"),
            Self::ScheduleIdenticon { generation, .. } => write!(f, "ScheduleIdenticon({generation})"),
            Self::Copy { .. } => f.write_str("Copy(<redacted>)"),
            Self::CloseWindow => f.write_str("CloseWindow"),
            Self::Ask(a) => write!(f, "Ask({a:?})"),
        }
    }
}

/// A site-level question for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ask {
    StatefulPassword { site: String, result_type: ResultType },
    LoginName { site: String },
    AddQuestion { site: String },
    RemoveQuestion { site: String, keyword: String },
    DeleteSite { site: String },
    UpgradeSite { site: String, from: AlgorithmVersion },
}

impl Ask {
    pub fn prompt(&self) -> Prompt {
        match self {
            Self::StatefulPassword { site, result_type } => {
                let extra = if *result_type == ResultType::StatefulDevice {
                    "\n\nA device-private password is stored only on this Mac and is never exported."
                } else {
                    "\n\nIt is stored encrypted with your master key and included (encrypted) in exports."
                };
                Prompt::new(
                    Style::Informational,
                    format!("{} for {site}", result_type.long_name()),
                    format!("Enter the password to store for {site}.{extra}"),
                )
                .field("Password", true)
                .button("Save", ButtonRole::Default)
                .button("Cancel", ButtonRole::Cancel)
            }
            Self::LoginName { site } => Prompt::new(
                Style::Informational,
                format!("Login name for {site}"),
                format!("Enter the login name you use at {site}.  It is stored encrypted."),
            )
            .field("Login name", false)
            .button("Save", ButtonRole::Default)
            .button("Cancel", ButtonRole::Cancel),
            Self::AddQuestion { site } => Prompt::new(
                Style::Informational,
                format!("Security question for {site}"),
                "Enter one keyword of the question, e.g. \"mother\" for \"What is your mother's maiden name?\". \
                 The answer is generated from your master password, the site and this keyword.",
            )
            .field("Keyword", false)
            .button("Add", ButtonRole::Default)
            .button("Cancel", ButtonRole::Cancel),
            Self::RemoveQuestion { site, keyword } => Prompt::new(
                Style::Warning,
                format!("Remove the question \"{keyword}\"?"),
                format!("The question is removed from {site}.  Its generated answer does not change if you add it again."),
            )
            .button("Cancel", ButtonRole::Cancel)
            .button("Remove", ButtonRole::Destructive),
            Self::DeleteSite { site } => Prompt::new(
                Style::Warning,
                format!("Delete {site}?"),
                "The site and its settings (type, counter, login name, questions and any stored password) \
                 are removed from this Mac.  This cannot be undone.",
            )
            .button("Cancel", ButtonRole::Cancel)
            .button("Delete", ButtonRole::Destructive),
            Self::UpgradeSite { site, from } => Prompt::new(
                Style::Warning,
                format!("Upgrade {site} to algorithm {}?", AlgorithmVersion::CURRENT),
                format!(
                    "{site} uses the older algorithm {from}.  Upgrading CHANGES its generated password.  \
                     Afterwards, copy the new password and change it on the website.  \
                     Stored passwords and login names are kept."
                ),
            )
            .button("Cancel", ButtonRole::Cancel)
            .button("Upgrade", ButtonRole::Destructive),
        }
    }
}

struct Session {
    user: User,
    keys: UserKeys,
    dirty_since: Option<Instant>,
}

/// Which screen the window shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Pick a user and enter the master password.
    Pick,
    NewUser,
    Unlocking,
    Unlocked,
}

/// Kept for callers that only care about locked/unlocked.
pub type Mode = Screen;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub name: String,
    /// `false`: a new site named after what was typed.
    pub known: bool,
    pub uses: u32,
}

/// An entry of the type popup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeChoice {
    Password(ResultType),
    LoginDefault,
    LoginTemplate(ResultType),
    LoginPersonal,
    Answer(ResultType),
}

impl TypeChoice {
    pub fn label(self) -> String {
        match self {
            Self::Password(t) if t.is_stateful() => format!("{}…", t.long_name()),
            Self::Password(t) | Self::Answer(t) => t.long_name().to_owned(),
            Self::LoginDefault => "Your Default Login".to_owned(),
            Self::LoginTemplate(t) => format!("Generated {}", t.long_name()),
            Self::LoginPersonal => "Stored Login Name…".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRow {
    pub full_name: String,
    pub avatar: u32,
    pub saved_keys: bool,
}

/// What the window renders.  May contain the revealed result: drop promptly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SitesView {
    pub screen: Screen,
    pub users: Vec<UserRow>,
    /// Index into `users`; `users.len()` is the "New User…" row.
    pub picked: Option<usize>,
    pub picked_name: String,
    pub picked_avatar: u32,
    pub can_unlock: bool,
    pub can_quick_unlock: bool,
    pub new_name: String,
    pub new_avatar: u32,
    pub can_create: bool,
    pub passwords_match: Option<bool>,
    pub identicon: Option<Identicon>,
    pub prompt: String,
    pub site_query: String,
    pub candidates: Vec<Candidate>,
    pub selection: Option<usize>,
    pub result_label: String,
    pub result_display: Zeroizing<String>,
    pub result_masked: bool,
    pub purpose: KeyPurpose,
    pub type_choices: Vec<TypeChoice>,
    pub selected_type: Option<usize>,
    pub counter: Option<Counter>,
    /// Recovery: question keywords ("" = site-wide) and the selected one.
    pub questions: Option<(Vec<String>, usize)>,
    pub can_remove_question: bool,
    /// Algorithm of the selected site and whether it is older than current.
    pub algorithm: Option<(AlgorithmVersion, bool)>,
    pub can_delete_site: bool,
    pub can_copy: bool,
    pub error: Option<String>,
    pub notice: Option<String>,
    pub hint: &'static str,
}

const HINT_PICK: &str = "⏎ unlock · esc close";
const HINT_UNLOCKED: &str = "⏎ copy password · ⇧⏎ copy login · ↑↓ choose · ⌥ reveal · esc close";

pub fn template_types() -> Vec<ResultType> {
    ResultType::ALL.into_iter().filter(|t| t.is_template()).collect()
}

fn model_err(e: mpw_model::Error) -> String {
    capitalise(&e.to_string())
}

/// What to copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyWhat {
    Current,
    Login,
}

pub struct SitesViewModel {
    saver: SaveQueue,
    users: Vec<UserEntry>,
    picked: Option<String>,
    picking_new: bool,
    screen: Screen,
    next_job: u64,
    pending_job: Option<u64>,
    master_password: Zeroizing<String>,
    new_name: String,
    new_password: Zeroizing<String>,
    new_confirm: Zeroizing<String>,
    new_avatar: u32,
    edit_generation: u64,
    identicon: Option<Identicon>,
    session: Option<Session>,
    site_query: String,
    candidates: Vec<Candidate>,
    selection: Option<usize>,
    purpose: KeyPurpose,
    question: String,
    result: Option<Zeroizing<String>>,
    error: Option<String>,
    notice: Option<String>,
    hide_passwords: bool,
    reveal: bool,
}

impl SitesViewModel {
    pub fn new(saver: SaveQueue) -> Self {
        let mut vm = Self {
            saver,
            users: Vec::new(),
            picked: None,
            picking_new: false,
            screen: Screen::Pick,
            next_job: 1,
            pending_job: None,
            master_password: Zeroizing::new(String::new()),
            new_name: String::new(),
            new_password: Zeroizing::new(String::new()),
            new_confirm: Zeroizing::new(String::new()),
            new_avatar: 0,
            edit_generation: 0,
            identicon: None,
            session: None,
            site_query: String::new(),
            candidates: Vec::new(),
            selection: None,
            purpose: KeyPurpose::Authentication,
            question: String::new(),
            result: None,
            error: None,
            notice: None,
            hide_passwords: false,
            reveal: false,
        };
        vm.refresh_users();
        vm
    }

    pub fn store(&self) -> &Arc<dyn DataStore> {
        self.saver.store()
    }

    pub fn saver(&self) -> &SaveQueue {
        &self.saver
    }

    pub fn screen(&self) -> Screen {
        self.screen
    }

    /// Alias of [`Self::screen`].
    pub fn mode(&self) -> Screen {
        self.screen
    }

    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    pub fn unlocked_user(&self) -> Option<&str> {
        self.session.as_ref().map(|s| s.user.full_name())
    }

    pub fn user(&self) -> Option<&User> {
        self.session.as_ref().map(|s| &s.user)
    }

    /// The unlocked user and keys, for flows (import, export, keychain).
    /// Call [`Self::mark_dirty`] after changing the user.
    pub fn session_mut(&mut self) -> Option<(&mut User, &mut UserKeys)> {
        self.session.as_mut().map(|s| (&mut s.user, &mut s.keys))
    }

    pub fn users(&self) -> &[UserEntry] {
        &self.users
    }

    pub fn picked(&self) -> Option<&str> {
        self.picked.as_deref()
    }

    pub fn picked_entry(&self) -> Option<&UserEntry> {
        let picked = self.picked.as_deref()?;
        self.users.iter().find(|u| u.full_name == picked)
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn set_error(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
        self.notice = None;
    }

    pub fn set_notice(&mut self, notice: impl Into<String>) {
        self.notice = Some(notice.into());
    }

    /// The unmasked current result (tests, smoke test).
    pub fn result(&self) -> Option<&str> {
        self.result.as_deref().map(String::as_str)
    }

    pub fn set_hide_passwords(&mut self, hide: bool) {
        self.hide_passwords = hide;
    }

    pub fn set_reveal(&mut self, reveal: bool) {
        self.reveal = reveal;
    }

    // ----------------------------------------------------------------- users

    /// Re-read the user list (after creating, deleting or importing users).
    pub fn refresh_users(&mut self) {
        match self.store().list() {
            Ok(users) => self.users = users,
            Err(e) => self.error = Some(e.to_string()),
        }
        let picked_exists = self.picked.as_ref().is_some_and(|p| self.users.iter().any(|u| &u.full_name == p));
        if !picked_exists {
            self.picked = self.users.first().map(|u| u.full_name.clone());
        }
        if self.users.is_empty() && self.screen == Screen::Pick {
            self.screen = Screen::NewUser;
            self.picking_new = true;
        }
    }

    /// Pre-select a user (the last one used), if known.
    pub fn prefer_user(&mut self, full_name: &str) {
        if self.users.iter().any(|u| u.full_name == full_name) {
            self.picked = Some(full_name.to_owned());
        }
    }

    /// Pick a user in the list (`None`: the "New User…" row).  Locks a
    /// session of another user first.
    pub fn pick_user(&mut self, full_name: Option<&str>) {
        if let Some(session) = &self.session {
            if Some(session.user.full_name()) == full_name {
                return;
            }
            self.lock();
        }
        if self.screen == Screen::Unlocking {
            return;
        }
        self.error = None;
        self.notice = None;
        self.master_password = Zeroizing::new(String::new());
        self.identicon = None;
        self.edit_generation += 1;
        match full_name {
            Some(name) if self.users.iter().any(|u| u.full_name == name) => {
                self.picked = Some(name.to_owned());
                self.picking_new = false;
                self.screen = Screen::Pick;
            }
            _ => {
                self.picking_new = true;
                self.screen = Screen::NewUser;
            }
        }
    }

    /// Leave the new-user form.
    pub fn cancel_new_user(&mut self) {
        self.clear_new_user();
        if !self.users.is_empty() {
            self.picking_new = false;
            self.screen = Screen::Pick;
        }
    }

    fn clear_new_user(&mut self) {
        self.new_name.clear();
        self.new_password = Zeroizing::new(String::new());
        self.new_confirm = Zeroizing::new(String::new());
        self.identicon = None;
        self.edit_generation += 1;
    }

    pub fn set_master_password(&mut self, password: Zeroizing<String>) -> Vec<VmEffect> {
        if self.screen != Screen::Pick || *self.master_password == *password {
            return Vec::new();
        }
        self.master_password = password;
        self.credentials_edited()
    }

    pub fn set_new_name(&mut self, name: &str) -> Vec<VmEffect> {
        if self.screen != Screen::NewUser || self.new_name == name {
            return Vec::new();
        }
        self.new_name = name.to_owned();
        self.credentials_edited()
    }

    pub fn set_new_password(&mut self, password: Zeroizing<String>) -> Vec<VmEffect> {
        if self.screen != Screen::NewUser || *self.new_password == *password {
            return Vec::new();
        }
        self.new_password = password;
        self.credentials_edited()
    }

    pub fn set_new_confirm(&mut self, password: Zeroizing<String>) {
        if self.screen == Screen::NewUser {
            self.new_confirm = password;
            self.error = None;
        }
    }

    /// Cycle the avatar of the new user (±1, wrapping).
    pub fn cycle_new_avatar(&mut self, delta: i32) {
        self.new_avatar = (self.new_avatar as i32 + delta).rem_euclid(AVATAR_COUNT as i32) as u32;
    }

    fn identicon_inputs(&self) -> Option<(&str, &str)> {
        match self.screen {
            Screen::Pick => Some((self.picked.as_deref()?, self.master_password.as_str())),
            Screen::NewUser => Some((self.new_name.as_str(), self.new_password.as_str())),
            _ => None,
        }
        .filter(|(n, p)| !n.is_empty() && !p.is_empty())
    }

    fn credentials_edited(&mut self) -> Vec<VmEffect> {
        self.error = None;
        self.identicon = None;
        self.edit_generation += 1;
        if self.identicon_inputs().is_none() {
            return Vec::new();
        }
        vec![VmEffect::ScheduleIdenticon { generation: self.edit_generation, delay: IDENTICON_DELAY }]
    }

    pub fn identicon_due(&mut self, generation: u64) {
        if generation != self.edit_generation {
            return;
        }
        if let Some((name, password)) = self.identicon_inputs() {
            self.identicon = Some(mpw_core::identicon(name, password));
        }
    }

    fn start_job(&mut self, purpose: DerivePurpose, full_name: &str, password: Zeroizing<String>) -> VmEffect {
        let id = self.next_job;
        self.next_job += 1;
        self.pending_job = Some(id);
        self.screen = Screen::Unlocking;
        VmEffect::Derive(DeriveJob::new(id, purpose, full_name, password))
    }

    pub fn submit_unlock(&mut self) -> Vec<VmEffect> {
        match self.screen {
            Screen::NewUser => return self.submit_new_user(),
            Screen::Pick => {}
            _ => return Vec::new(),
        }
        let Some(name) = self.picked.clone() else {
            self.error = Some("Choose a user first, or create one.".into());
            return Vec::new();
        };
        if self.master_password.is_empty() {
            self.error = Some("Enter your master password.".into());
            return Vec::new();
        }
        self.error = None;
        let password = std::mem::replace(&mut self.master_password, Zeroizing::new(String::new()));
        vec![self.start_job(DerivePurpose::Unlock, &name, password)]
    }

    fn submit_new_user(&mut self) -> Vec<VmEffect> {
        let name = self.new_name.clone();
        if name.trim().is_empty() {
            self.error = Some("Enter your full name, exactly as on an official document.".into());
            return Vec::new();
        }
        if let Err(e) = User::new(&name) {
            self.error = Some(model_err(e));
            return Vec::new();
        }
        if self.users.iter().any(|u| u.full_name == name) {
            self.error = Some(format!("{name} already exists: pick it in the list instead."));
            return Vec::new();
        }
        if self.new_password.is_empty() {
            self.error = Some("Choose a master password.".into());
            return Vec::new();
        }
        if *self.new_password != *self.new_confirm {
            self.error = Some("The two master passwords differ.".into());
            return Vec::new();
        }
        self.error = None;
        let password = std::mem::replace(&mut self.new_password, Zeroizing::new(String::new()));
        self.new_confirm = Zeroizing::new(String::new());
        vec![self.start_job(DerivePurpose::CreateUser, &name, password)]
    }

    /// A background derivation finished.  Stale results are dropped (wiping
    /// their keys).  Flow derivations are not handled here.
    pub fn derive_finished(&mut self, derived: Derived) {
        if self.pending_job != Some(derived.id) || self.screen != Screen::Unlocking {
            return;
        }
        self.pending_job = None;
        let (keys, icon) = match derived.result {
            Ok(k) => k,
            Err(e) => {
                self.screen = if derived.purpose == DerivePurpose::CreateUser { Screen::NewUser } else { Screen::Pick };
                self.error = Some(capitalise(&e));
                return;
            }
        };
        match derived.purpose {
            DerivePurpose::CreateUser => self.finish_create(&derived.full_name, keys, icon),
            _ => {
                if let Err(e) = self.open_session(&derived.full_name, keys, Some(icon)) {
                    self.screen = Screen::Pick;
                    self.error = Some(e.to_string());
                }
            }
        }
    }

    fn finish_create(&mut self, full_name: &str, mut keys: UserKeys, icon: Identicon) {
        let result = (|| -> Result<User, StoreError> {
            let mut user = User::new(full_name).map_err(|e| StoreError::from_model(e, full_name))?;
            user.avatar = self.new_avatar;
            user.authenticate(&mut keys).map_err(|e| StoreError::from_model(e, full_name))?;
            user.identicon = Some(icon);
            self.store().create(&user)?;
            Ok(user)
        })();
        match result {
            Ok(user) => {
                self.clear_new_user();
                self.picking_new = false;
                self.picked = Some(full_name.to_owned());
                self.refresh_users();
                self.begin_session(user, keys);
            }
            Err(e) => {
                self.screen = Screen::NewUser;
                self.error = Some(e.to_string());
            }
        }
    }

    /// Load a stored user with `keys` (verified against its key ID) and open
    /// the session.  Used by unlock and by the saved-keys path.
    pub fn open_session(&mut self, full_name: &str, mut keys: UserKeys, icon: Option<Identicon>) -> Result<(), StoreError> {
        let mut user = self.store().load(full_name, &mut keys)?;
        let mut dirty = false;
        if let Some(icon) = icon {
            if user.identicon.as_ref() != Some(&icon) {
                user.identicon = Some(icon);
                dirty = true;
            }
        }
        user.touch();
        self.begin_session(user, keys);
        if dirty {
            self.mark_dirty();
        }
        Ok(())
    }

    fn begin_session(&mut self, user: User, keys: UserKeys) {
        self.picked = Some(user.full_name().to_owned());
        self.session = Some(Session { user, keys, dirty_since: None });
        self.screen = Screen::Unlocked;
        self.identicon = None;
        self.master_password = Zeroizing::new(String::new());
        self.error = None;
        self.reset_site();
    }

    /// Remember that the session user changed; it is saved after a pause.
    pub fn mark_dirty(&mut self) {
        if let Some(s) = &mut self.session {
            s.dirty_since.get_or_insert_with(Instant::now);
        }
    }

    /// Replace the session's user (after an import into it).
    pub fn replace_session_user(&mut self, user: User) {
        if let Some(s) = &mut self.session {
            if s.user.full_name() == user.full_name() {
                s.user = user;
                s.dirty_since = None;
                self.refresh_candidates();
            }
        }
    }

    /// Write pending changes now (queued on the save thread).
    pub fn persist_now(&mut self) {
        if let Some(s) = &mut self.session {
            if s.dirty_since.take().is_some() {
                self.saver.submit(&s.user);
            }
        }
    }

    /// Debounced saving; call about once a second.
    pub fn tick(&mut self, now: Instant) {
        let due = self
            .session
            .as_ref()
            .and_then(|s| s.dirty_since)
            .is_some_and(|since| now.saturating_duration_since(since) >= SAVE_DELAY);
        if due {
            self.persist_now();
        }
    }

    /// Delete a stored user (and its session).  Pending saves are flushed
    /// first so they cannot resurrect the file.
    pub fn delete_user(&mut self, full_name: &str) -> Result<(), StoreError> {
        let had_session = self.unlocked_user() == Some(full_name);
        if had_session {
            if let Some(s) = &mut self.session {
                s.dirty_since = None;
            }
        }
        self.saver.flush();
        self.store().delete(full_name)?;
        if had_session {
            self.session = None;
            self.lock();
        }
        if self.picked.as_deref() == Some(full_name) {
            self.picked = None;
        }
        self.refresh_users();
        Ok(())
    }

    /// Drop the session WITHOUT saving it (its stored file was replaced).
    pub fn discard_session(&mut self) {
        self.session = None;
        self.lock();
    }

    /// Drop the keys and decrypted user (after queueing pending changes) and
    /// clear every secret field.
    pub fn lock(&mut self) {
        self.persist_now();
        self.session = None; // UserKeys and User are dropped; keys are wiped
        self.pending_job = None;
        self.next_job += 1;
        self.master_password = Zeroizing::new(String::new());
        self.clear_new_user();
        self.identicon = None;
        self.reveal = false;
        self.screen = if self.users.is_empty() { Screen::NewUser } else { Screen::Pick };
        self.picking_new = self.users.is_empty();
        self.reset_site();
    }

    // ------------------------------------------------------------------ sites

    pub fn set_site_query(&mut self, query: &str) {
        if self.site_query == query {
            return;
        }
        self.site_query = query.to_owned();
        self.error = None;
        self.notice = None;
        self.refresh_candidates();
    }

    fn refresh_candidates(&mut self) {
        let previous = self.selected_name().map(str::to_owned);
        self.candidates.clear();
        self.selection = None;
        if let Some(s) = &self.session {
            let q = self.site_query.as_str();
            let mut known: Vec<(&str, u32, i64)> = s
                .user
                .sites()
                .filter(|site| crate::fuzzy_matches(site.name(), q))
                .map(|site| (site.name(), site.uses, site.last_used.as_unix()))
                .collect();
            known.sort_by(|a, b| (a.0 != q).cmp(&(b.0 != q)).then(b.2.cmp(&a.2)).then(a.0.cmp(b.0)));
            known.truncate(SITE_LIST_LIMIT);
            let exact = known.iter().any(|k| k.0 == q);
            self.candidates =
                known.into_iter().map(|(name, uses, _)| Candidate { name: name.to_owned(), known: true, uses }).collect();
            if !q.is_empty() && !exact {
                self.candidates.push(Candidate { name: q.to_owned(), known: false, uses: 0 });
            }
            if !self.candidates.is_empty() {
                let keep = previous.and_then(|p| self.candidates.iter().position(|c| c.name == p));
                self.selection = Some(if q.is_empty() { keep.unwrap_or(0) } else { 0 });
            }
        }
        self.recompute();
    }

    pub fn move_selection(&mut self, delta: isize) {
        let n = self.candidates.len();
        if n == 0 {
            return;
        }
        let current = self.selection.unwrap_or(0) as isize;
        self.selection = Some((current + delta).rem_euclid(n as isize) as usize);
        self.question.clear();
        self.recompute();
    }

    pub fn select(&mut self, index: usize) {
        if index < self.candidates.len() && self.selection != Some(index) {
            self.selection = Some(index);
            self.question.clear();
            self.recompute();
        }
    }

    fn selected(&self) -> Option<&Candidate> {
        self.candidates.get(self.selection?)
    }

    pub fn selected_name(&self) -> Option<&str> {
        self.selected().map(|c| c.name.as_str())
    }

    pub fn set_purpose(&mut self, purpose: KeyPurpose) {
        if self.purpose != purpose {
            self.purpose = purpose;
            self.recompute();
        }
    }

    pub fn select_question(&mut self, keyword: &str) {
        self.question = keyword.to_owned();
        self.recompute();
    }

    /// Create the selected site if it is new (on first copy or first edit).
    fn ensure_site(&mut self) -> Option<String> {
        let name = self.selected_name()?.to_owned();
        let session = self.session.as_mut()?;
        if session.user.site(&name).is_none() {
            if let Err(e) = session.user.add_site(&name) {
                self.error = Some(model_err(e));
                return None;
            }
            session.dirty_since.get_or_insert_with(Instant::now);
            if let Some(c) = self.selection.and_then(|i| self.candidates.get_mut(i)) {
                c.known = true;
            }
        }
        Some(name)
    }

    /// The type popup's entries for the current purpose and site.
    pub fn type_choices(&self) -> (Vec<TypeChoice>, Option<usize>) {
        let Some(session) = &self.session else { return (Vec::new(), None) };
        let Some(name) = self.selected_name() else { return (Vec::new(), None) };
        let site = session.user.site(name);
        match self.purpose {
            KeyPurpose::Authentication => {
                let mut choices: Vec<TypeChoice> = template_types().into_iter().map(TypeChoice::Password).collect();
                choices.push(TypeChoice::Password(ResultType::StatefulPersonal));
                choices.push(TypeChoice::Password(ResultType::StatefulDevice));
                let current = site.map_or(session.user.default_type, |s| s.result_type);
                if !choices.contains(&TypeChoice::Password(current)) {
                    choices.push(TypeChoice::Password(current));
                }
                let i = choices.iter().position(|c| *c == TypeChoice::Password(current));
                (choices, i)
            }
            KeyPurpose::Identification => {
                let mut choices = vec![TypeChoice::LoginDefault];
                choices.extend(template_types().into_iter().map(TypeChoice::LoginTemplate));
                choices.push(TypeChoice::LoginPersonal);
                let current = match site.and_then(|s| s.login_type()) {
                    None => TypeChoice::LoginDefault,
                    Some(t) if t.is_stateful() => TypeChoice::LoginPersonal,
                    Some(t) => TypeChoice::LoginTemplate(t),
                };
                let i = choices.iter().position(|c| *c == current);
                (choices, i)
            }
            KeyPurpose::Recovery => {
                let t = site
                    .and_then(|s| s.question(&self.question))
                    .map_or(ResultType::DEFAULT_ANSWER, |q| q.result_type);
                (vec![TypeChoice::Answer(t)], Some(0))
            }
        }
    }

    /// The user picked an entry of the type popup.
    pub fn choose_type(&mut self, choice: TypeChoice) -> Vec<VmEffect> {
        if self.type_choices().1.and_then(|i| self.type_choices().0.get(i).copied()) == Some(choice) {
            return Vec::new();
        }
        let Some(name) = self.ensure_site() else { return Vec::new() };
        let mut result: Result<(), mpw_model::Error> = Ok(());
        let mut effects = Vec::new();
        if let Some(s) = &mut self.session {
            match choice {
                TypeChoice::Password(t) if t.is_stateful() => {
                    effects.push(VmEffect::Ask(Ask::StatefulPassword { site: name, result_type: t }));
                }
                TypeChoice::Password(t) => {
                    if let Some(site) = s.user.site_mut(&name) {
                        site.result_type = t;
                    }
                }
                TypeChoice::LoginDefault => {
                    if let Some(site) = s.user.site_mut(&name) {
                        site.use_default_login();
                    }
                }
                TypeChoice::LoginTemplate(t) => {
                    if let Some(site) = s.user.site_mut(&name) {
                        result = site.set_generated_login(t);
                    }
                }
                TypeChoice::LoginPersonal => effects.push(VmEffect::Ask(Ask::LoginName { site: name })),
                TypeChoice::Answer(_) => {}
            }
        }
        if let Err(e) = result {
            self.error = Some(model_err(e));
        }
        if effects.is_empty() {
            self.mark_dirty();
            self.recompute();
        }
        effects
    }

    pub fn set_counter(&mut self, counter: Counter) {
        let counter = counter.clamp(COUNTER_INITIAL, COUNTER_MAX);
        let current = self.selected_name().and_then(|n| self.user()?.site(n)).map(|s| s.counter);
        if current == Some(counter) || (current.is_none() && counter == COUNTER_INITIAL) {
            return;
        }
        let Some(name) = self.ensure_site() else { return };
        if let Some(site) = self.session.as_mut().and_then(|s| s.user.site_mut(&name)) {
            site.counter = counter;
        }
        self.mark_dirty();
        self.recompute();
    }

    pub fn ask_add_question(&mut self) -> Vec<VmEffect> {
        match self.ensure_site() {
            Some(site) => vec![VmEffect::Ask(Ask::AddQuestion { site })],
            None => Vec::new(),
        }
    }

    pub fn ask_remove_question(&mut self) -> Vec<VmEffect> {
        match (self.selected_name(), self.question.is_empty()) {
            (Some(site), false) => {
                vec![VmEffect::Ask(Ask::RemoveQuestion { site: site.to_owned(), keyword: self.question.clone() })]
            }
            _ => Vec::new(),
        }
    }

    pub fn ask_delete_site(&mut self) -> Vec<VmEffect> {
        match self.selected() {
            Some(c) if c.known => vec![VmEffect::Ask(Ask::DeleteSite { site: c.name.clone() })],
            _ => Vec::new(),
        }
    }

    pub fn ask_upgrade_site(&mut self) -> Vec<VmEffect> {
        let Some(name) = self.selected_name() else { return Vec::new() };
        match self.user().and_then(|u| u.site(name)) {
            Some(site) if site.algorithm() < AlgorithmVersion::CURRENT => {
                vec![VmEffect::Ask(Ask::UpgradeSite { site: name.to_owned(), from: site.algorithm() })]
            }
            _ => Vec::new(),
        }
    }

    /// The user answered an [`Ask`].  The confirming button is the one that
    /// is not "Cancel".
    pub fn answer(&mut self, ask: Ask, answer: PromptAnswer) {
        let prompt = ask.prompt();
        let confirmed = prompt.buttons.get(answer.button).is_some_and(|b| b.role != ButtonRole::Cancel);
        if !confirmed {
            self.recompute();
            return;
        }
        let Some(session) = self.session.as_mut() else { return };
        let (user, keys) = (&mut session.user, &mut session.keys);
        let value = answer.value(0);
        let result: Result<Option<String>, String> = match &ask {
            Ask::StatefulPassword { site, result_type } => {
                if value.is_empty() {
                    Err("The password must not be empty.".into())
                } else {
                    user.set_site_password(keys, site, *result_type, value).map(|_| None).map_err(model_err)
                }
            }
            Ask::LoginName { site } => {
                if value.trim().is_empty() {
                    Err("The login name must not be empty.".into())
                } else {
                    user.set_site_login_name(keys, site, value).map(|_| None).map_err(model_err)
                }
            }
            Ask::AddQuestion { site } => {
                let keyword = value.trim().to_owned();
                if keyword.is_empty() {
                    Err("Enter a keyword.".into())
                } else {
                    match user.site_mut(site).map(|s| s.add_question(&keyword).map(drop)) {
                        Some(Ok(())) => Ok(Some(keyword)),
                        Some(Err(e)) => Err(model_err(e)),
                        None => Err("The site no longer exists.".into()),
                    }
                }
            }
            Ask::RemoveQuestion { site, keyword } => {
                user.site_mut(site).and_then(|s| s.remove_question(keyword));
                Ok(Some(String::new()))
            }
            Ask::DeleteSite { site } => {
                user.remove_site(site);
                Ok(None)
            }
            Ask::UpgradeSite { site, .. } => {
                user.set_site_algorithm(keys, site, AlgorithmVersion::CURRENT).map(|_| None).map_err(model_err)
            }
        };
        match result {
            Ok(question) => {
                session.dirty_since.get_or_insert_with(Instant::now);
                if let Some(q) = question {
                    self.question = q;
                }
                match ask {
                    Ask::DeleteSite { site } => {
                        self.notice = Some(format!("Deleted {site}."));
                        self.refresh_candidates();
                    }
                    Ask::UpgradeSite { site, .. } => {
                        self.notice = Some(format!("{site} now uses {}: its password changed.", AlgorithmVersion::CURRENT));
                        self.recompute();
                    }
                    _ => self.recompute(),
                }
            }
            Err(e) => {
                self.error = Some(e);
                self.recompute();
            }
        }
    }

    fn recompute(&mut self) {
        self.result = None;
        let name = match self.selected() {
            Some(c) => c.name.clone(),
            None => return,
        };
        let Some(session) = self.session.as_mut() else { return };
        let (user, keys) = (&session.user, &mut session.keys);
        let known = user.site(&name).is_some();
        if self.purpose == KeyPurpose::Recovery && known {
            let has = user.site(&name).is_some_and(|s| s.question(&self.question).is_some());
            if !has {
                self.question.clear();
            }
        }
        let result = if known {
            match self.purpose {
                KeyPurpose::Authentication => user.site_password(keys, &name),
                KeyPurpose::Identification => user.site_login(keys, &name),
                KeyPurpose::Recovery => user.site_answer(keys, &name, &self.question),
            }
        } else {
            transient_result(user, keys, &name, self.purpose, &self.question)
        };
        match result {
            Ok(r) => self.result = Some(r),
            Err(mpw_model::Error::NoStoredValue(what)) => {
                self.error = Some(format!("No {what} is stored for {name} yet: choose the type again to enter it."))
            }
            Err(e) => self.error = Some(model_err(e)),
        }
    }

    /// ⏎ / ⇧⏎: copy and dismiss.
    pub fn copy(&mut self, what: CopyWhat) -> Vec<VmEffect> {
        match self.screen {
            Screen::Pick | Screen::NewUser => return self.submit_unlock(),
            Screen::Unlocking => return Vec::new(),
            Screen::Unlocked => {}
        }
        if self.selected().is_none() {
            self.error = Some("Type the name of a site first.".into());
            return Vec::new();
        }
        let text = if what == CopyWhat::Login && self.purpose != KeyPurpose::Identification {
            let previous = self.purpose;
            self.purpose = KeyPurpose::Identification;
            self.recompute();
            let login = self.result.clone();
            self.purpose = previous;
            self.recompute();
            login
        } else {
            self.result.clone()
        };
        let Some(text) = text else {
            if self.error.is_none() {
                self.error = Some("Nothing to copy.".into());
            }
            return Vec::new();
        };
        let Some(name) = self.ensure_site() else { return Vec::new() };
        if let Some(s) = &mut self.session {
            if let Err(e) = s.user.use_site(&name) {
                self.error = Some(model_err(e));
            }
            s.dirty_since.get_or_insert_with(Instant::now);
        }
        vec![VmEffect::Copy { text }]
    }

    pub fn cancel(&mut self) -> Vec<VmEffect> {
        vec![VmEffect::CloseWindow]
    }

    pub fn window_shown(&mut self) {
        self.reveal = false;
        if self.session.is_none() {
            self.refresh_users();
        } else {
            self.reset_site();
        }
    }

    fn reset_site(&mut self) {
        self.site_query.clear();
        self.question.clear();
        self.purpose = KeyPurpose::Authentication;
        self.error = None;
        self.notice = None;
        self.refresh_candidates();
    }

    // -------------------------------------------------------------------- view

    fn masked(&self) -> bool {
        let user_pref = self.user().is_some_and(|u| u.preferences.mask_passwords);
        (self.hide_passwords || user_pref) && !self.reveal && self.purpose == KeyPurpose::Authentication
    }

    pub fn view(&self) -> SitesView {
        let users: Vec<UserRow> = self
            .users
            .iter()
            .map(|u| UserRow { full_name: u.full_name.clone(), avatar: u.avatar, saved_keys: u.saved_keys })
            .collect();
        let picked = if self.picking_new || self.screen == Screen::NewUser {
            Some(users.len())
        } else {
            self.picked.as_ref().and_then(|p| users.iter().position(|u| &u.full_name == p))
        };
        let entry = self.picked_entry();
        let what = match self.purpose {
            KeyPurpose::Authentication => "password",
            KeyPurpose::Identification => "login name",
            KeyPurpose::Recovery => "security answer",
        };
        let prompt = match (self.screen, &self.session) {
            (_, Some(s)) => format!("{}'s {what} for:", s.user.full_name()),
            (Screen::Unlocking, _) => "Unlocking…".to_owned(),
            (Screen::NewUser, _) => "New user: your full name and a master password".to_owned(),
            _ => match &self.picked {
                Some(name) => format!("Enter {name}'s master password:"),
                None => "Choose a user:".to_owned(),
            },
        };
        let site = self.selected().and_then(|c| self.user()?.site(&c.name));
        let result_label = match self.selected() {
            Some(c) if self.purpose == KeyPurpose::Recovery && !self.question.is_empty() => {
                format!("Your answer to \"{}\" for {}:", self.question, c.name)
            }
            Some(c) => format!("Your {what} for {}:", c.name),
            None => String::new(),
        };
        let masked = self.masked();
        let result_display = match &self.result {
            Some(r) if masked => Zeroizing::new("●".repeat(r.chars().count())),
            Some(r) => r.clone(),
            None => Zeroizing::new(String::new()),
        };
        let (type_choices, selected_type) = self.type_choices();
        let questions = (self.purpose == KeyPurpose::Recovery && self.selected().is_some()).then(|| {
            let mut list = vec![String::new()];
            if let Some(site) = site {
                list.extend(site.questions().map(|q| q.keyword().to_owned()).filter(|k| !k.is_empty()));
            }
            let i = list.iter().position(|k| *k == self.question).unwrap_or(0);
            (list, i)
        });
        SitesView {
            screen: self.screen,
            picked,
            picked_name: self.picked.clone().unwrap_or_default(),
            picked_avatar: entry.map_or(0, |e| e.avatar),
            can_unlock: self.screen == Screen::Pick && self.picked.is_some() && !self.master_password.is_empty(),
            can_quick_unlock: self.screen == Screen::Pick && entry.is_some_and(|e| e.saved_keys),
            new_name: self.new_name.clone(),
            new_avatar: self.new_avatar,
            can_create: self.screen == Screen::NewUser
                && !self.new_name.trim().is_empty()
                && !self.new_password.is_empty()
                && *self.new_password == *self.new_confirm,
            passwords_match: (self.screen == Screen::NewUser && !self.new_confirm.is_empty())
                .then(|| *self.new_password == *self.new_confirm),
            users,
            identicon: self.identicon.clone(),
            prompt,
            site_query: self.site_query.clone(),
            candidates: self.candidates.clone(),
            selection: self.selection,
            result_label,
            result_display,
            result_masked: masked && self.result.is_some(),
            purpose: self.purpose,
            type_choices,
            selected_type,
            counter: (self.purpose == KeyPurpose::Authentication && self.selected().is_some())
                .then(|| site.map_or(COUNTER_INITIAL, |s| s.counter)),
            can_remove_question: questions.as_ref().is_some_and(|(_, i)| *i > 0),
            questions,
            algorithm: self
                .selected()
                .and_then(|_| site.map(|s| s.algorithm()).or_else(|| self.user().map(|u| u.algorithm())))
                .map(|v| (v, v < AlgorithmVersion::CURRENT)),
            can_delete_site: self.selected().is_some_and(|c| c.known),
            can_copy: self.result.is_some(),
            error: self.error.clone(),
            notice: self.notice.clone(),
            hint: if self.screen == Screen::Unlocked { HINT_UNLOCKED } else { HINT_PICK },
        }
    }
}

/// Results for a site the user has typed but not created yet, with the
/// user's defaults (what `add_site` would give it).
fn transient_result(
    user: &User,
    keys: &mut UserKeys,
    name: &str,
    purpose: KeyPurpose,
    keyword: &str,
) -> Result<Zeroizing<String>, mpw_model::Error> {
    let algorithm = user.algorithm();
    let context = (!keyword.is_empty()).then_some(keyword);
    match purpose {
        KeyPurpose::Authentication => Ok(keys.key(algorithm)?.site_result(
            name,
            COUNTER_INITIAL,
            purpose,
            None,
            user.default_type,
            None,
        )?),
        KeyPurpose::Identification if user.login_type().is_stateful() => user.user_login(keys),
        KeyPurpose::Identification => {
            Ok(keys.key(algorithm)?.site_result(name, COUNTER_INITIAL, purpose, None, user.login_type(), None)?)
        }
        KeyPurpose::Recovery => Ok(keys.key(algorithm)?.site_result(
            name,
            COUNTER_INITIAL,
            purpose,
            context,
            ResultType::DEFAULT_ANSWER,
            None,
        )?),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::data::MemoryStore;
    use crate::keys::derive_all;

    pub const NAME: &str = "Robert Lee Mitchell";
    pub const PASSWORD: &str = "banana colored duckling";
    pub const SITE: &str = "masterpasswordapp.com";
    /// Reference test vector: v3, counter 1, Long.
    pub const SITE_PASSWORD: &str = "Jejr5[RepuSosp";

    pub fn pw(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    pub fn vm_with(store: Arc<MemoryStore>) -> SitesViewModel {
        SitesViewModel::new(SaveQueue::inline(store))
    }

    pub fn run(effects: Vec<VmEffect>) -> Option<Derived> {
        effects.into_iter().find_map(|e| match e {
            VmEffect::Derive(job) => Some(job.run()),
            _ => None,
        })
    }

    /// Create (or unlock) `NAME` synchronously.
    pub fn create_user(vm: &mut SitesViewModel, name: &str, password: &str) {
        vm.pick_user(None);
        vm.set_new_name(name);
        vm.set_new_password(pw(password));
        vm.set_new_confirm(pw(password));
        let derived = run(vm.submit_unlock()).expect("derive job");
        vm.derive_finished(derived);
        assert_eq!(vm.screen(), Screen::Unlocked, "{:?}", vm.error());
    }

    pub fn unlock(vm: &mut SitesViewModel, name: &str, password: &str) {
        vm.pick_user(Some(name));
        vm.set_master_password(pw(password));
        if let Some(d) = run(vm.submit_unlock()) {
            vm.derive_finished(d);
        }
    }

    #[test]
    fn first_run_offers_new_user_and_validates() {
        let mut vm = vm_with(Arc::new(MemoryStore::new()));
        assert_eq!(vm.screen(), Screen::NewUser);
        assert!(vm.submit_unlock().is_empty());
        assert!(vm.error().unwrap().contains("full name"));
        vm.set_new_name(NAME);
        vm.set_new_password(pw("a"));
        vm.set_new_confirm(pw("b"));
        assert_eq!(vm.view().passwords_match, Some(false));
        assert!(vm.submit_unlock().is_empty());
        assert_eq!(vm.error(), Some("The two master passwords differ."));
        vm.set_new_confirm(pw("a"));
        assert!(vm.view().can_create);
    }

    #[test]
    fn create_copy_lock_unlock_and_wrong_password() {
        let store = Arc::new(MemoryStore::new());
        let mut vm = vm_with(store.clone());
        vm.cycle_new_avatar(-1);
        create_user(&mut vm, NAME, PASSWORD);
        assert_eq!(store.get(NAME).unwrap().avatar, AVATAR_COUNT - 1);

        vm.set_site_query(SITE);
        assert_eq!(vm.view().candidates, vec![Candidate { name: SITE.into(), known: false, uses: 0 }]);
        assert_eq!(vm.result(), Some(SITE_PASSWORD));
        vm.set_hide_passwords(true);
        assert_eq!(*vm.view().result_display, "●".repeat(SITE_PASSWORD.len()));
        vm.set_reveal(true);
        assert_eq!(*vm.view().result_display, SITE_PASSWORD);
        match vm.copy(CopyWhat::Current).as_slice() {
            [VmEffect::Copy { text }] => assert_eq!(**text, SITE_PASSWORD),
            other => panic!("{other:?}"),
        }
        vm.lock();
        assert_eq!(vm.screen(), Screen::Pick);
        assert!(!vm.is_unlocked());
        let saved = store.get(NAME).unwrap();
        assert_eq!(saved.site(SITE).unwrap().uses, 1, "lock flushed the change");

        unlock(&mut vm, NAME, "wrong");
        assert_eq!(vm.screen(), Screen::Pick);
        assert_eq!(vm.error(), Some(format!("Incorrect master password for {NAME}.").as_str()));
        unlock(&mut vm, NAME, PASSWORD);
        assert_eq!(vm.screen(), Screen::Unlocked);
        // Empty query lists all sites, most recent first.
        assert_eq!(vm.view().candidates[0].name, SITE);
        assert_eq!(vm.result(), Some(SITE_PASSWORD));
    }

    #[test]
    fn site_settings_and_asks() {
        let store = Arc::new(MemoryStore::new());
        let mut vm = vm_with(store.clone());
        create_user(&mut vm, NAME, PASSWORD);
        vm.set_site_query("example.com");
        let first = vm.result().unwrap().to_owned();
        vm.set_counter(2);
        assert_ne!(vm.result().unwrap(), first);
        assert!(vm.user().unwrap().site("example.com").is_some(), "editing creates the site");
        vm.choose_type(TypeChoice::Password(ResultType::TemplatePin));
        assert_eq!(vm.result().unwrap().len(), 4);

        // Stateful: asks, then stores.
        let effects = vm.choose_type(TypeChoice::Password(ResultType::StatefulPersonal));
        let Some(VmEffect::Ask(ask)) = effects.into_iter().next() else { panic!() };
        assert!(ask.prompt().is_well_formed());
        vm.answer(ask, PromptAnswer::with_values(0, &["my own pw"]));
        assert_eq!(vm.result(), Some("my own pw"));

        // Login: stored login name.
        vm.set_purpose(KeyPurpose::Identification);
        let generated_login = vm.result().unwrap().to_owned();
        let Some(VmEffect::Ask(ask)) = vm.choose_type(TypeChoice::LoginPersonal).into_iter().next() else { panic!() };
        vm.answer(ask.clone(), PromptAnswer::button(1)); // cancel
        assert_eq!(vm.result(), Some(generated_login.as_str()));
        vm.answer(ask, PromptAnswer::with_values(0, &["rob@example.com"]));
        assert_eq!(vm.result(), Some("rob@example.com"));

        // ⇧⏎ copies the login regardless of purpose.
        vm.set_purpose(KeyPurpose::Authentication);
        match vm.copy(CopyWhat::Login).as_slice() {
            [VmEffect::Copy { text }] => assert_eq!(**text, "rob@example.com"),
            other => panic!("{other:?}"),
        }

        // Questions.
        vm.set_purpose(KeyPurpose::Recovery);
        let site_wide = vm.result().unwrap().to_owned();
        let Some(VmEffect::Ask(ask)) = vm.ask_add_question().into_iter().next() else { panic!() };
        vm.answer(ask, PromptAnswer::with_values(0, &["mother"]));
        let view = vm.view();
        assert_eq!(view.questions, Some((vec![String::new(), "mother".into()], 1)));
        assert_ne!(vm.result().unwrap(), site_wide);
        assert!(view.can_remove_question);
        let Some(VmEffect::Ask(ask)) = vm.ask_remove_question().into_iter().next() else { panic!() };
        assert!(ask.prompt().is_well_formed());
        vm.answer(ask, PromptAnswer::button(1));
        assert_eq!(vm.view().questions, Some((vec![String::new()], 0)));

        // Persisted on lock.
        vm.lock();
        let saved = store.get(NAME).unwrap();
        let site = saved.site("example.com").unwrap();
        assert_eq!((site.counter, site.result_type), (2, ResultType::StatefulPersonal));
    }

    #[test]
    fn delete_and_upgrade_site() {
        let store = Arc::new(MemoryStore::new());
        let mut vm = vm_with(store.clone());
        create_user(&mut vm, NAME, PASSWORD);
        vm.set_site_query(SITE);
        vm.copy(CopyWhat::Current);
        // Make it an old site.
        {
            let (user, keys) = vm.session_mut().unwrap();
            user.set_site_algorithm(keys, SITE, AlgorithmVersion::V1).unwrap();
        }
        vm.set_site_query("");
        vm.set_site_query(SITE);
        assert_eq!(vm.view().algorithm, Some((AlgorithmVersion::V1, true)));
        let Some(VmEffect::Ask(ask)) = vm.ask_upgrade_site().into_iter().next() else { panic!() };
        let prompt = ask.prompt();
        assert!(prompt.message.contains("CHANGES"));
        assert_eq!(prompt.buttons[0].role, ButtonRole::Cancel, "destructive is not the default");
        vm.answer(ask, PromptAnswer::button(prompt.button_index("Upgrade").unwrap()));
        assert_eq!(vm.view().algorithm, Some((AlgorithmVersion::V3, false)));
        // (v1 and v3 agree for an all-ASCII name and site.)
        assert_eq!(vm.result(), Some(SITE_PASSWORD));
        assert!(vm.ask_upgrade_site().is_empty());

        let Some(VmEffect::Ask(ask)) = vm.ask_delete_site().into_iter().next() else { panic!() };
        vm.answer(ask, PromptAnswer::button(1));
        assert!(vm.user().unwrap().site(SITE).is_none());
        assert_eq!(vm.view().candidates, vec![Candidate { name: SITE.into(), known: false, uses: 0 }]);
    }

    #[test]
    fn per_user_mask_preference_is_honoured() {
        let store = Arc::new(MemoryStore::new());
        let mut vm = vm_with(store.clone());
        create_user(&mut vm, NAME, PASSWORD);
        vm.session_mut().unwrap().0.preferences.mask_passwords = true;
        vm.set_site_query(SITE);
        assert!(vm.view().result_masked);
    }

    #[test]
    fn stale_or_wrong_derivations_are_dropped() {
        let store = Arc::new(MemoryStore::new());
        let mut vm = vm_with(store.clone());
        create_user(&mut vm, NAME, PASSWORD);
        vm.lock();
        vm.set_master_password(pw(PASSWORD));
        let derived = run(vm.submit_unlock()).unwrap();
        vm.lock();
        vm.derive_finished(derived);
        assert!(!vm.is_unlocked());
    }

    #[test]
    fn saved_keys_open_a_session_but_wrong_keys_do_not() {
        let store = Arc::new(MemoryStore::new());
        let mut vm = vm_with(store.clone());
        create_user(&mut vm, NAME, PASSWORD);
        vm.lock();
        let (wrong, _) = derive_all(NAME, "other").unwrap();
        assert!(matches!(vm.open_session(NAME, wrong, None), Err(StoreError::WrongMasterPassword { .. })));
        let (right, _) = derive_all(NAME, PASSWORD).unwrap();
        vm.open_session(NAME, right, None).unwrap();
        assert!(vm.is_unlocked());
    }

    #[test]
    fn delete_user_removes_it_and_returns_to_new_user() {
        let store = Arc::new(MemoryStore::new());
        let mut vm = vm_with(store.clone());
        create_user(&mut vm, NAME, PASSWORD);
        vm.delete_user(NAME).unwrap();
        assert!(store.get(NAME).is_none());
        assert!(!vm.is_unlocked());
        assert_eq!(vm.screen(), Screen::NewUser);
    }

    #[test]
    fn selection_moves_and_wraps() {
        let store = Arc::new(MemoryStore::new());
        let mut vm = vm_with(store);
        create_user(&mut vm, NAME, PASSWORD);
        for site in ["gmail.com", "github.com"] {
            vm.set_site_query(site);
            vm.copy(CopyWhat::Current);
        }
        vm.set_site_query("g");
        assert_eq!(vm.view().candidates.len(), 3, "two known + the typed 'g'");
        vm.move_selection(-1);
        assert_eq!(vm.view().result_label, "Your password for g:");
        vm.move_selection(1);
        assert_eq!(vm.view().selection, Some(0));
    }
}
