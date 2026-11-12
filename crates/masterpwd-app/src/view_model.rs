//! The sites window as a state machine, free of AppKit types.
//!
//! The AppKit layer forwards user input to the methods here, executes the
//! returned [`VmEffect`]s and renders [`SitesViewModel::view`].  Every input is
//! validated here; errors end up in [`SitesView::error`], never in a panic.

use std::fmt;
use std::time::Duration;

use mpw_core::{
    identicon, Counter, Identicon, KeyPurpose, ResultType, Zeroizing, COUNTER_INITIAL,
};

use crate::data::{AuthPlan, DataStore, KeyRing, SiteSettings, StoreError, UserId};

/// Pause in typing before the identicon is shown (it leaks a few bits about
/// the password, so it is not updated on every keystroke).
pub const IDENTICON_DELAY: Duration = Duration::from_millis(800);
/// How many matching sites are offered.
pub const COMPLETION_LIMIT: usize = 6;
/// The highest counter the UI accepts.
pub const COUNTER_MAX: Counter = 9_999;

/// Side effects the platform layer must carry out.
pub enum VmEffect {
    /// Run [`UnlockJob::run`] on a background thread and feed the outcome to
    /// [`SitesViewModel::unlock_finished`] on the main thread.
    StartUnlock(UnlockJob),
    /// Call [`SitesViewModel::identicon_due`] with `generation` after `delay`.
    ScheduleIdenticon { generation: u64, delay: Duration },
    /// Put `text` on the pasteboard, then dismiss the window.
    Copy { text: Zeroizing<String> },
    /// Dismiss the sites window.
    CloseWindow,
}

impl fmt::Debug for VmEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartUnlock(job) => write!(f, "StartUnlock({job:?})"),
            Self::ScheduleIdenticon { generation, delay } => {
                write!(f, "ScheduleIdenticon({generation}, {delay:?})")
            }
            Self::Copy { .. } => f.write_str("Copy(<redacted>)"),
            Self::CloseWindow => f.write_str("CloseWindow"),
        }
    }
}

/// A key derivation to run off the main thread.  `Send`; secrets redacted from
/// `Debug` and wiped on drop.
pub struct UnlockJob {
    id: u64,
    plan: AuthPlan,
    master_password: Zeroizing<String>,
}

impl UnlockJob {
    /// The slow part (scrypt).  Never call this on the main thread.
    pub fn run(self) -> UnlockOutcome {
        // A panic here would leave the window stuck on "Unlocking…".
        let result = std::panic::catch_unwind(|| {
            KeyRing::derive(&self.plan.full_name, &self.master_password, &self.plan)
        })
        .unwrap_or_else(|_| Err(mpw_core::Error::Internal("key derivation failed unexpectedly".into())));
        UnlockOutcome { id: self.id, plan: self.plan, result }
    }
}

impl fmt::Debug for UnlockJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnlockJob(#{}, {:?}, <redacted>)", self.id, self.plan.algorithm)
    }
}

/// The result of an [`UnlockJob`].
pub struct UnlockOutcome {
    id: u64,
    plan: AuthPlan,
    result: Result<KeyRing, mpw_core::Error>,
}

impl fmt::Debug for UnlockOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnlockOutcome(#{}, ok: {})", self.id, self.result.is_ok())
    }
}

enum Phase {
    Locked,
    Unlocking { job: u64 },
    Unlocked { user: UserId, keys: KeyRing },
}

/// Which screen the sites window shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Locked,
    Unlocking,
    Unlocked,
}

/// One entry in the site list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub name: String,
    /// `false`: a new site named after what was typed.
    pub known: bool,
}

/// Everything the window renders.  May contain the (revealed) result: drop it
/// promptly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SitesView {
    pub mode: Mode,
    pub full_name: String,
    pub identicon: Option<Identicon>,
    pub can_unlock: bool,
    pub prompt: String,
    pub site_query: String,
    pub candidates: Vec<Candidate>,
    pub selection: Option<usize>,
    pub result_label: String,
    /// The result as displayed: masked unless revealed.  Empty if none.
    pub result_display: Zeroizing<String>,
    pub result_masked: bool,
    pub purpose: KeyPurpose,
    pub type_choices: Vec<ResultType>,
    pub selected_type: Option<ResultType>,
    /// `None`: the counter does not apply (no site, or not a password).
    pub counter: Option<Counter>,
    /// `Some` for security answers: the question keyword (may be empty).
    pub question: Option<String>,
    pub can_copy: bool,
    pub error: Option<String>,
    pub hint: &'static str,
}

const HINT_LOCKED: &str = "⏎ unlock · esc close";
const HINT_UNLOCKED: &str = "⏎ copy & close · ↑↓ choose site · ⌥ reveal · esc close";

/// The template types offered for every purpose.
pub fn template_types() -> Vec<ResultType> {
    ResultType::ALL.into_iter().filter(|t| t.is_template()).collect()
}

pub struct SitesViewModel<S: DataStore> {
    store: S,
    phase: Phase,
    next_job: u64,
    full_name: String,
    master_password: Zeroizing<String>,
    edit_generation: u64,
    identicon: Option<Identicon>,
    site_query: String,
    candidates: Vec<Candidate>,
    selection: Option<usize>,
    site: Option<SiteSettings>,
    purpose: KeyPurpose,
    answer_type: ResultType,
    question: String,
    result: Option<Zeroizing<String>>,
    error: Option<String>,
    hide_passwords: bool,
    reveal: bool,
}

impl<S: DataStore> SitesViewModel<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            phase: Phase::Locked,
            next_job: 1,
            full_name: String::new(),
            master_password: Zeroizing::new(String::new()),
            edit_generation: 0,
            identicon: None,
            site_query: String::new(),
            candidates: Vec::new(),
            selection: None,
            site: None,
            purpose: KeyPurpose::Authentication,
            answer_type: ResultType::DEFAULT_ANSWER,
            question: String::new(),
            result: None,
            error: None,
            hide_passwords: false,
            reveal: false,
        }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    pub fn mode(&self) -> Mode {
        match self.phase {
            Phase::Locked => Mode::Locked,
            Phase::Unlocking { .. } => Mode::Unlocking,
            Phase::Unlocked { .. } => Mode::Unlocked,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        matches!(self.phase, Phase::Unlocked { .. })
    }

    pub fn unlocked_user(&self) -> Option<&UserId> {
        match &self.phase {
            Phase::Unlocked { user, .. } => Some(user),
            _ => None,
        }
    }

    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    // ------------------------------------------------------------- locked

    pub fn set_full_name(&mut self, name: &str) -> Vec<VmEffect> {
        if !matches!(self.phase, Phase::Locked) || self.full_name == name {
            return Vec::new();
        }
        self.full_name = name.to_owned();
        self.credentials_edited()
    }

    pub fn set_master_password(&mut self, password: Zeroizing<String>) -> Vec<VmEffect> {
        if !matches!(self.phase, Phase::Locked) || *self.master_password == *password {
            return Vec::new();
        }
        self.master_password = password;
        self.credentials_edited()
    }

    fn credentials_edited(&mut self) -> Vec<VmEffect> {
        self.error = None;
        self.identicon = None;
        self.edit_generation += 1;
        if self.full_name.is_empty() || self.master_password.is_empty() {
            return Vec::new();
        }
        vec![VmEffect::ScheduleIdenticon { generation: self.edit_generation, delay: IDENTICON_DELAY }]
    }

    /// The typing pause scheduled by an edit has elapsed.
    pub fn identicon_due(&mut self, generation: u64) {
        if generation != self.edit_generation
            || !matches!(self.phase, Phase::Locked)
            || self.full_name.is_empty()
            || self.master_password.is_empty()
        {
            return;
        }
        self.identicon = Some(identicon(&self.full_name, &self.master_password));
    }

    pub fn submit_unlock(&mut self) -> Vec<VmEffect> {
        if !matches!(self.phase, Phase::Locked) {
            return Vec::new();
        }
        if self.full_name.trim().is_empty() {
            self.error = Some("Enter your full name.".into());
            return Vec::new();
        }
        if self.master_password.is_empty() {
            self.error = Some("Enter your master password.".into());
            return Vec::new();
        }
        self.error = None;
        let id = self.next_job;
        self.next_job += 1;
        self.phase = Phase::Unlocking { job: id };
        let plan = self.store.begin_auth(&self.full_name);
        let master_password = std::mem::replace(&mut self.master_password, Zeroizing::new(String::new()));
        vec![VmEffect::StartUnlock(UnlockJob { id, plan, master_password })]
    }

    /// A background derivation finished.  Stale outcomes (locked meanwhile,
    /// or superseded) are dropped, which wipes their keys.
    pub fn unlock_finished(&mut self, outcome: UnlockOutcome) {
        if !matches!(self.phase, Phase::Unlocking { job } if job == outcome.id) {
            return;
        }
        let keys = match outcome.result {
            Ok(keys) => keys,
            Err(e) => {
                self.phase = Phase::Locked;
                self.error = Some(e.to_string());
                return;
            }
        };
        match self.store.finish_auth(&outcome.plan, &keys) {
            Ok(user) => {
                self.phase = Phase::Unlocked { user, keys };
                self.identicon = None;
                self.reset_site();
            }
            Err(e) => {
                self.phase = Phase::Locked;
                self.identicon = None;
                self.error = Some(e.to_string());
            }
        }
    }

    // ------------------------------------------------------------ unlocked

    pub fn set_site_query(&mut self, query: &str) {
        if self.site_query == query {
            return;
        }
        self.site_query = query.to_owned();
        self.error = None;
        self.refresh_candidates();
    }

    fn refresh_candidates(&mut self) {
        self.candidates.clear();
        self.selection = None;
        if let Phase::Unlocked { user, .. } = &self.phase {
            if !self.site_query.is_empty() {
                let names = self.store.complete_sites(user, &self.site_query, COMPLETION_LIMIT);
                let exact = names.contains(&self.site_query);
                self.candidates = names.into_iter().map(|name| Candidate { name, known: true }).collect();
                if !exact {
                    self.candidates.push(Candidate { name: self.site_query.clone(), known: false });
                }
                self.selection = Some(0);
            }
        }
        self.load_selected_site();
    }

    /// Move the selection in the site list (↑ = -1, ↓ = +1), wrapping.
    pub fn move_selection(&mut self, delta: isize) {
        let n = self.candidates.len();
        if n == 0 {
            return;
        }
        let current = self.selection.unwrap_or(0) as isize;
        self.selection = Some((current + delta).rem_euclid(n as isize) as usize);
        self.load_selected_site();
    }

    pub fn select(&mut self, index: usize) {
        if index < self.candidates.len() {
            self.selection = Some(index);
            self.load_selected_site();
        }
    }

    fn load_selected_site(&mut self) {
        self.site = None;
        if let (Phase::Unlocked { user, .. }, Some(i)) = (&self.phase, self.selection) {
            if let Some(c) = self.candidates.get(i) {
                match self.store.site(user, &c.name) {
                    Ok(site) => self.site = Some(site),
                    Err(e) => self.error = Some(e.to_string()),
                }
            }
        }
        self.recompute();
    }

    pub fn set_purpose(&mut self, purpose: KeyPurpose) {
        if self.purpose != purpose {
            self.purpose = purpose;
            self.recompute();
        }
    }

    pub fn set_question(&mut self, question: &str) {
        if self.question != question {
            self.question = question.to_owned();
            self.recompute();
        }
    }

    /// Change the result type for the current purpose.
    pub fn set_result_type(&mut self, result_type: ResultType) {
        match self.purpose {
            KeyPurpose::Recovery => self.answer_type = result_type,
            KeyPurpose::Authentication | KeyPurpose::Identification => {
                let Some(site) = &mut self.site else { return };
                if self.purpose == KeyPurpose::Authentication {
                    if site.result_type != result_type {
                        site.result_type = result_type;
                        site.result_state = None;
                    }
                } else if site.login_type != result_type {
                    site.login_type = result_type;
                    site.login_state = None;
                }
                self.save_site();
            }
        }
        self.recompute();
    }

    pub fn set_counter(&mut self, counter: Counter) {
        let counter = counter.clamp(COUNTER_INITIAL, COUNTER_MAX);
        let Some(site) = &mut self.site else { return };
        if site.counter != counter {
            site.counter = counter;
            self.save_site();
            self.recompute();
        }
    }

    /// Persist edits to a site the store already knows; new sites keep their
    /// edits locally until first use.
    fn save_site(&mut self) {
        if let (Phase::Unlocked { user, .. }, Some(site)) = (&self.phase, &self.site) {
            if site.known {
                if let Err(e) = self.store.update_site(user, site) {
                    self.error = Some(e.to_string());
                }
            }
        }
    }

    pub fn set_hide_passwords(&mut self, hide: bool) {
        self.hide_passwords = hide;
    }

    /// ⌥ held or released.
    pub fn set_reveal(&mut self, reveal: bool) {
        self.reveal = reveal;
    }

    fn recompute(&mut self) {
        self.result = None;
        let (Phase::Unlocked { keys, .. }, Some(site)) = (&self.phase, &self.site) else { return };
        let Some(key) = keys.get(site.algorithm) else {
            self.error = Some(format!("No key for algorithm {} (lock and unlock again).", site.algorithm));
            return;
        };
        let context = (!self.question.is_empty()).then_some(self.question.as_str());
        let result = match self.purpose {
            KeyPurpose::Authentication => key.site_result(
                &site.name,
                site.counter,
                KeyPurpose::Authentication,
                None,
                site.result_type,
                site.result_state.as_deref(),
            ),
            KeyPurpose::Identification => key.site_result(
                &site.name,
                COUNTER_INITIAL,
                KeyPurpose::Identification,
                None,
                site.login_type,
                site.login_state.as_deref(),
            ),
            KeyPurpose::Recovery => key.site_result(
                &site.name,
                COUNTER_INITIAL,
                KeyPurpose::Recovery,
                context,
                self.answer_type,
                None,
            ),
        };
        match result {
            Ok(r) => self.result = Some(r),
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    /// ⏎: copy the current result and dismiss.
    pub fn copy(&mut self) -> Vec<VmEffect> {
        match self.phase {
            Phase::Locked => return self.submit_unlock(),
            Phase::Unlocking { .. } => return Vec::new(),
            Phase::Unlocked { .. } => {}
        }
        let Some(text) = self.result.clone() else {
            if self.error.is_none() {
                self.error = Some("Type the name of a site first.".into());
            }
            return Vec::new();
        };
        if let (Phase::Unlocked { user, .. }, Some(site)) = (&self.phase, &mut self.site) {
            match self.store.record_use(user, site) {
                Ok(()) => site.known = true,
                // Still copy: failing to remember the site must not block the
                // user from getting their password.
                Err(e) => self.error = Some(StoreError::to_string(&e)),
            }
        }
        vec![VmEffect::Copy { text }]
    }

    /// Esc.
    pub fn cancel(&mut self) -> Vec<VmEffect> {
        vec![VmEffect::CloseWindow]
    }

    /// The window is being shown: start from an empty site field.
    pub fn window_shown(&mut self) {
        self.reveal = false;
        self.reset_site();
    }

    fn reset_site(&mut self) {
        self.site_query.clear();
        self.question.clear();
        self.purpose = KeyPurpose::Authentication;
        self.error = None;
        self.refresh_candidates();
    }

    /// Drop the keys and clear every field except the (non-secret) full name.
    pub fn lock(&mut self) {
        self.phase = Phase::Locked; // drops the KeyRing, which zeroizes it
        self.next_job += 1;
        self.master_password = Zeroizing::new(String::new());
        self.edit_generation += 1;
        self.identicon = None;
        self.reveal = false;
        self.reset_site();
    }

    /// Show an error coming from outside (e.g. the pasteboard).
    pub fn set_error(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
    }

    /// The unmasked current result.  For tests and the smoke test.
    pub fn result(&self) -> Option<&str> {
        self.result.as_deref().map(String::as_str)
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn view(&self) -> SitesView {
        let mode = self.mode();
        let site_name = self.site.as_ref().map(|s| s.name.as_str());
        let what = match self.purpose {
            KeyPurpose::Authentication => "password",
            KeyPurpose::Identification => "login name",
            KeyPurpose::Recovery => "security answer",
        };
        let prompt = match (&self.phase, mode) {
            (Phase::Unlocked { user, .. }, _) => format!("{user}'s {what} for:"),
            (_, Mode::Unlocking) => "Unlocking…".to_owned(),
            _ => "Enter your full name and master password:".to_owned(),
        };
        let result_label = match site_name {
            Some(name) => format!("Your {what} for {name}:"),
            None => String::new(),
        };
        let masked = self.hide_passwords && !self.reveal && self.purpose == KeyPurpose::Authentication;
        let result_display = match &self.result {
            Some(r) if masked => Zeroizing::new("●".repeat(r.chars().count())),
            Some(r) => r.clone(),
            None => Zeroizing::new(String::new()),
        };
        let selected_type = self.site.as_ref().map(|s| match self.purpose {
            KeyPurpose::Authentication => s.result_type,
            KeyPurpose::Identification => s.login_type,
            KeyPurpose::Recovery => self.answer_type,
        });
        let mut type_choices = template_types();
        if let Some(t) = selected_type {
            if !type_choices.contains(&t) {
                type_choices.push(t);
            }
        }
        SitesView {
            mode,
            full_name: self.full_name.clone(),
            identicon: self.identicon.clone(),
            can_unlock: mode == Mode::Locked
                && !self.full_name.trim().is_empty()
                && !self.master_password.is_empty(),
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
            counter: self
                .site
                .as_ref()
                .filter(|_| self.purpose == KeyPurpose::Authentication)
                .map(|s| s.counter),
            question: (self.purpose == KeyPurpose::Recovery).then(|| self.question.clone()),
            can_copy: self.result.is_some(),
            error: self.error.clone(),
            hint: if mode == Mode::Unlocked { HINT_UNLOCKED } else { HINT_LOCKED },
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::data::MemoryStore;

    pub const NAME: &str = "Robert Lee Mitchell";
    pub const PASSWORD: &str = "banana colored duckling";
    pub const SITE: &str = "masterpasswordapp.com";
    /// Reference test vector: v3, counter 1, Long.
    pub const SITE_PASSWORD: &str = "Jejr5[RepuSosp";

    fn pw(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    /// Run the unlock synchronously (tests only; the app runs it on a thread).
    pub fn unlock<S: DataStore>(vm: &mut SitesViewModel<S>, name: &str, password: &str) {
        vm.set_full_name(name);
        vm.set_master_password(pw(password));
        let mut effects = vm.submit_unlock();
        assert_eq!(vm.mode(), Mode::Unlocking);
        let Some(VmEffect::StartUnlock(job)) = effects.pop() else { panic!("no unlock job") };
        vm.unlock_finished(job.run());
    }

    #[test]
    fn empty_input_is_rejected_with_a_message() {
        let mut vm = SitesViewModel::new(MemoryStore::new());
        assert!(vm.submit_unlock().is_empty());
        assert_eq!(vm.error(), Some("Enter your full name."));
        vm.set_full_name(NAME);
        assert!(vm.submit_unlock().is_empty());
        assert_eq!(vm.error(), Some("Enter your master password."));
        assert_eq!(vm.mode(), Mode::Locked);
        assert!(!vm.view().can_unlock);
        // Copy while locked = try to unlock.
        assert!(vm.copy().is_empty());
    }

    #[test]
    fn identicon_waits_for_a_typing_pause() {
        let mut vm = SitesViewModel::new(MemoryStore::new());
        assert!(vm.set_full_name(NAME).is_empty(), "no password yet");
        let first = vm.set_master_password(pw("banana"));
        let second = vm.set_master_password(pw(PASSWORD));
        let gen = |e: &[VmEffect]| match e {
            [VmEffect::ScheduleIdenticon { generation, .. }] => *generation,
            other => panic!("{other:?}"),
        };
        // The stale timer does nothing.
        vm.identicon_due(gen(&first));
        assert!(vm.view().identicon.is_none());
        vm.identicon_due(gen(&second));
        let shown = vm.view().identicon.expect("identicon after pause");
        assert_eq!(shown, identicon(NAME, PASSWORD));
        // Editing again hides it.
        vm.set_master_password(pw("x"));
        assert!(vm.view().identicon.is_none());
    }

    #[test]
    fn unlock_site_copy_lock_against_the_real_algorithm() {
        let mut vm = SitesViewModel::new(MemoryStore::new());
        unlock(&mut vm, NAME, PASSWORD);
        assert_eq!(vm.mode(), Mode::Unlocked, "{:?}", vm.error());
        assert_eq!(vm.view().prompt, format!("{NAME}'s password for:"));

        vm.set_site_query(SITE);
        let view = vm.view();
        assert_eq!(view.candidates, vec![Candidate { name: SITE.into(), known: false }]);
        assert_eq!(vm.result(), Some(SITE_PASSWORD));
        assert_eq!(view.counter, Some(1));
        assert_eq!(view.selected_type, Some(ResultType::TemplateLong));

        // Masking.
        vm.set_hide_passwords(true);
        assert_eq!(*vm.view().result_display, "●".repeat(SITE_PASSWORD.len()));
        vm.set_reveal(true);
        assert_eq!(*vm.view().result_display, SITE_PASSWORD);

        match vm.copy().as_slice() {
            [VmEffect::Copy { text }] => assert_eq!(**text, SITE_PASSWORD),
            other => panic!("{other:?}"),
        }
        // The site is now remembered and completes.
        vm.window_shown();
        vm.set_site_query("mpa");
        assert_eq!(vm.view().candidates[0], Candidate { name: SITE.into(), known: true });
        assert_eq!(vm.result(), Some(SITE_PASSWORD));

        vm.lock();
        assert_eq!(vm.mode(), Mode::Locked);
        let view = vm.view();
        assert!(view.result_display.is_empty() && view.candidates.is_empty() && !view.can_unlock);
        assert_eq!(view.full_name, NAME, "the name survives locking");
    }

    #[test]
    fn counter_type_and_purpose() {
        let mut vm = SitesViewModel::new(MemoryStore::new());
        unlock(&mut vm, NAME, PASSWORD);
        vm.set_site_query(SITE);
        let first = vm.result().unwrap().to_owned();
        vm.set_counter(2);
        assert_ne!(vm.result().unwrap(), first);
        vm.set_counter(0); // clamped to 1
        assert_eq!(vm.result().unwrap(), first);
        vm.set_result_type(ResultType::TemplatePin);
        let pin = vm.result().unwrap().to_owned();
        assert_eq!(pin.len(), 4);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));

        vm.set_purpose(KeyPurpose::Identification);
        let view = vm.view();
        assert_eq!(view.selected_type, Some(ResultType::TemplateName));
        assert_eq!(view.counter, None);
        assert!(vm.result().unwrap().chars().all(|c| c.is_ascii_lowercase()));

        vm.set_purpose(KeyPurpose::Recovery);
        let any_answer = vm.result().unwrap().to_owned();
        vm.set_question("mother");
        assert_ne!(vm.result().unwrap(), any_answer);
        assert_eq!(vm.view().question.as_deref(), Some("mother"));
        // Answers are never masked.
        vm.set_hide_passwords(true);
        assert!(!vm.view().result_masked);
    }

    #[test]
    fn edits_to_a_known_site_are_persisted() {
        let mut vm = SitesViewModel::new(MemoryStore::new());
        unlock(&mut vm, NAME, PASSWORD);
        vm.set_site_query("example.com");
        vm.copy();
        vm.window_shown();
        vm.set_site_query("example.com");
        vm.set_counter(5);
        vm.window_shown();
        vm.set_site_query("example.com");
        assert_eq!(vm.view().counter, Some(5));
    }

    #[test]
    fn selection_moves_and_wraps() {
        let mut vm = SitesViewModel::new(MemoryStore::new());
        unlock(&mut vm, NAME, PASSWORD);
        for site in ["gmail.com", "github.com"] {
            vm.set_site_query(site);
            vm.copy();
        }
        vm.set_site_query("g");
        let view = vm.view();
        assert_eq!(view.candidates.len(), 3, "two known + the typed 'g'");
        assert_eq!(view.selection, Some(0));
        vm.move_selection(-1);
        assert_eq!(vm.view().selection, Some(2));
        assert_eq!(vm.view().result_label, "Your password for g:");
        vm.move_selection(1);
        assert_eq!(vm.view().selection, Some(0));
    }

    #[test]
    fn wrong_password_for_a_known_user() {
        let mut vm = SitesViewModel::new(MemoryStore::new());
        unlock(&mut vm, NAME, PASSWORD);
        vm.lock();
        unlock(&mut vm, NAME, "wrong");
        assert_eq!(vm.mode(), Mode::Locked);
        assert_eq!(vm.error(), Some(format!("Incorrect master password for {NAME}.").as_str()));
        // A correct retry works.
        unlock(&mut vm, NAME, PASSWORD);
        assert_eq!(vm.mode(), Mode::Unlocked);
    }

    #[test]
    fn locking_during_unlock_discards_the_keys() {
        let mut vm = SitesViewModel::new(MemoryStore::new());
        vm.set_full_name(NAME);
        vm.set_master_password(pw(PASSWORD));
        let Some(VmEffect::StartUnlock(job)) = vm.submit_unlock().pop() else { panic!() };
        vm.lock();
        vm.unlock_finished(job.run());
        assert_eq!(vm.mode(), Mode::Locked);
    }

    #[test]
    fn copy_without_a_site_explains_itself() {
        let mut vm = SitesViewModel::new(MemoryStore::new());
        unlock(&mut vm, NAME, PASSWORD);
        assert!(vm.copy().is_empty());
        assert!(vm.error().is_some());
        assert!(matches!(vm.cancel().as_slice(), [VmEffect::CloseWindow]));
    }
}
