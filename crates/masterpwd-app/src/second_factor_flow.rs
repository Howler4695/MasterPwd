//! Smart card / recovery code second factor: the app flows on top of
//! `mpw_model::second_factor`.
//!
//! The user's effective master password is `typed password + " " + recovery
//! code`; the code's secret is kept in the user file wrapped to enrolled card
//! keys.  This module obtains the secret (card unwrap, or the typed recovery
//! code), and drives enable / disable / new code / add / remove card, plus the
//! second-factor variants of unlock, master-password change, reveal-export
//! and import.
//!
//! PIN safety: a card unwrap only ever starts from an explicit user action (or
//! once, when the card the user was asked to insert arrives); a failure is
//! reported and never retried automatically.  Unwraps and every operation that
//! runs scrypt execute on a worker thread ([`Work`]).

use std::collections::BTreeMap;
use std::fmt;

use mpw_core::{Identicon, Zeroizing};
use mpw_model::{
    RecoveryCode, SecondFactor, SecondFactorStatus, SecondSecret, Slot, SlotKind, User, UserKeys,
};

use crate::card::{hex, short_fingerprint, CardKey, UnwrapError, WrapAlgorithm};
use crate::core::{AppCore, LockReason, UiEffect};
use crate::data::{capitalise, StoreError};
use crate::keys::{derive_all_with_secret, without_password, DerivePurpose, Derived};
use crate::prompt::{ButtonRole, Prompt, PromptAnswer, Style};
use crate::view_model::CardPanel;

/// Background work: a card unwrap or a key derivation / re-keying.
pub struct Work {
    pub id: u64,
    pub task: Box<dyn FnOnce() -> WorkOutput + Send>,
}

impl fmt::Debug for Work {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Work(#{})", self.id)
    }
}

pub enum WorkOutput {
    Unwrapped(Result<Zeroizing<Vec<u8>>, UnwrapError>),
    Keys(Result<Box<(UserKeys, Identicon)>, String>),
    Rekeyed(Result<Box<(User, UserKeys)>, String>),
}

/// What the second secret is needed for.
pub(crate) enum Goal {
    Unlock { password: Zeroizing<String> },
    Disable { password: Zeroizing<String> },
    ChangePassword { old: Zeroizing<String>, new: Zeroizing<String> },
    Rotate,
    AddCard { key: Box<CardKey> },
    ExportReveal { password: Zeroizing<String> },
    Import { flow: u64, step: u32, password: Zeroizing<String> },
}

pub(crate) struct Request {
    goal: Goal,
    name: String,
    /// `None`: the user's second-factor data is unreadable (code only).
    factor: Option<SecondFactor>,
    /// Waiting for an enrolled card to be inserted (unlock only).
    waiting: bool,
    /// Token of the card used, if any.
    token: Option<String>,
}

enum WorkPurpose {
    /// Unwrap for the pending [`Request`].
    Secret,
    /// Verify a freshly wrapped slot (enable / add card): compare to `expect`.
    Verify { slot: Box<Slot>, expect: SecondSecret, enabling: bool },
    /// Second-factor unlock keys.
    UnlockKeys { name: String, token: Option<String> },
    /// Keys for export / import continuation.
    FlowKeys { flow: u64, step: u32, name: String },
    Rekey { what: &'static str, done: &'static str },
}

struct EnableFlow {
    secret: SecondSecret,
    slots: Vec<Slot>,
}

struct RotateFlow {
    old: SecondSecret,
    new: SecondSecret,
    slots: Vec<Slot>,
}

#[derive(Default)]
pub(crate) struct SfState {
    request: Option<Request>,
    works: BTreeMap<u64, WorkPurpose>,
    enable: Option<EnableFlow>,
    rotate: Option<RotateFlow>,
    add: Option<SecondSecret>,
    /// Token of the card that unlocked the session (lock when removed).
    pub(crate) unlocked_token: Option<String>,
    tokens: Vec<String>,
}

pub(crate) enum SfPending {
    Explain,
    CardChoice { key: Box<CardKey>, adding: bool },
    NoCard,
    ShowCode,
    Confirm,
    RecoveryCode,
    DisableConfirm,
    RotateExplain,
    RemoveSlot { id: String, last: bool },
}

pub const LOCK_ON_REMOVAL_DEFAULT: bool = true;

fn slot_label(key: &CardKey) -> String {
    // Never the certificate subject (holder name / DoD ID): slots are exported.
    format!("Smart card {} ({})", key.kind, key.slot.describe())
}

fn code_groups_last(code: &str) -> String {
    code.rsplit('-').next().unwrap_or("").to_owned()
}

fn date(t: i64) -> String {
    mpw_model::Timestamp::from_unix(t).to_rfc3339().get(..10).unwrap_or("?").to_owned()
}

impl AppCore {
    fn sf_factor(status: &SecondFactorStatus) -> Option<Option<SecondFactor>> {
        match status {
            SecondFactorStatus::Disabled => None,
            SecondFactorStatus::Enabled(f) => Some(Some(f.clone())),
            SecondFactorStatus::Unreadable => Some(None),
        }
    }

    /// The unlocked user's second factor, if enabled.
    fn session_factor(&self) -> Option<Option<SecondFactor>> {
        self.vm.user().and_then(|u| Self::sf_factor(u.second_factor_status()))
    }

    pub fn session_has_second_factor(&self) -> bool {
        self.session_factor().is_some()
    }

    fn work(&mut self, purpose: WorkPurpose, task: impl FnOnce() -> WorkOutput + Send + 'static) -> UiEffect {
        let id = self.id();
        self.sf.works.insert(id, purpose);
        UiEffect::Work(Work { id, task: Box::new(task) })
    }

    /// An enrolled slot whose card is inserted.
    fn present_enrolled(&self, factor: &SecondFactor) -> Option<(CardKey, Slot)> {
        let keys = self.cards.keys().unwrap_or_default();
        keys.into_iter().find_map(|k| {
            let fp = hex(&k.fingerprint);
            factor.slots().iter().find(|s| s.fingerprint().eq_ignore_ascii_case(&fp)).map(|s| (k, s.clone()))
        })
    }

    // ---------------------------------------------------- obtain the secret

    /// Start obtaining the second secret for `goal`: unwrap with an inserted
    /// enrolled card, wait for one (unlock), or ask for the recovery code.
    pub(crate) fn request_secret(&mut self, name: String, factor: Option<SecondFactor>, goal: Goal) -> Vec<UiEffect> {
        let unlocking = matches!(goal, Goal::Unlock { .. });
        let enrolled = factor.as_ref().map_or(0, |f| f.slots().len());
        self.sf.request = Some(Request { goal, name, factor, waiting: false, token: None });
        if let Some((key, slot)) = self.sf.request.as_ref().and_then(|r| r.factor.as_ref()).and_then(|f| self.present_enrolled(f)) {
            return self.start_unwrap(key, slot);
        }
        if unlocking && enrolled > 0 {
            if let Some(r) = &mut self.sf.request {
                r.waiting = true;
            }
            self.vm.set_card_panel(Some(CardPanel {
                note: format!(
                    "Insert your smart card ({enrolled} enrolled), or use your recovery code.  \
                     You will be asked for the card's PIN once."
                ),
                can_retry: false,
                busy: false,
            }));
            return Vec::new();
        }
        vec![self.ask_recovery_code(None)]
    }

    fn start_unwrap(&mut self, key: CardKey, slot: Slot) -> Vec<UiEffect> {
        let Some(algorithm) = WrapAlgorithm::from_id(slot.algorithm()) else {
            return self.secret_failed(format!("The enrolled card uses an unknown method ({}).", slot.algorithm()));
        };
        let unlocking = matches!(self.sf.request.as_ref().map(|r| &r.goal), Some(Goal::Unlock { .. }));
        if let Some(r) = &mut self.sf.request {
            r.waiting = false;
            r.token = Some(key.token_id.clone());
        }
        let note = "Waiting for your smart card: enter its PIN in the system dialog…";
        if unlocking {
            self.vm.set_card_panel(Some(CardPanel { note: note.into(), can_retry: false, busy: true }));
        } else {
            self.vm.set_notice(note);
        }
        let cards = self.cards.clone();
        let fingerprint = key.fingerprint;
        let blob = slot.wrapped().to_vec();
        // ONE attempt: the task is not retried, whatever happens.
        vec![self.work(WorkPurpose::Secret, move || WorkOutput::Unwrapped(cards.unwrap(&fingerprint, algorithm, &blob)))]
    }

    /// "Try Card Again" (unlock): one more attempt, by explicit request.
    pub fn retry_card(&mut self) -> Vec<UiEffect> {
        let factor = self.sf.request.as_ref().and_then(|r| r.factor.clone());
        match factor.and_then(|f| self.present_enrolled(&f)) {
            Some((key, slot)) => self.start_unwrap(key, slot),
            None => {
                self.vm.set_card_panel(Some(CardPanel {
                    note: "No enrolled smart card is inserted.  Insert it, or use your recovery code.".into(),
                    can_retry: false,
                    busy: false,
                }));
                if let Some(r) = &mut self.sf.request {
                    r.waiting = true;
                }
                Vec::new()
            }
        }
    }

    /// "Use Recovery Code…".
    pub fn use_recovery_code(&mut self) -> Vec<UiEffect> {
        if self.sf.request.is_none() {
            return Vec::new();
        }
        if let Some(r) = &mut self.sf.request {
            r.waiting = false;
        }
        vec![self.ask_recovery_code(None)]
    }

    /// Leave the card step (unlock screen "Cancel").
    pub fn cancel_card(&mut self) {
        self.sf.request = None;
        self.vm.cancel_second_factor(None);
    }

    fn ask_recovery_code(&mut self, problem: Option<String>) -> UiEffect {
        let name = self.sf.request.as_ref().map_or_else(String::new, |r| r.name.clone());
        let mut message = format!(
            "Type {name}'s recovery code (35 characters; dashes and case don't matter).  \
             It replaces the smart card."
        );
        if let Some(p) = problem {
            message = format!("{p}\n\n{message}");
        }
        let prompt = Prompt::new(Style::Informational, "Recovery code", message)
            .field("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX", false)
            .button("Continue", ButtonRole::Default)
            .button("Cancel", ButtonRole::Cancel);
        self.ask_sf(prompt, SfPending::RecoveryCode)
    }

    fn secret_failed(&mut self, message: String) -> Vec<UiEffect> {
        let unlocking = matches!(self.sf.request.as_ref().map(|r| &r.goal), Some(Goal::Unlock { .. }));
        if unlocking {
            let present = self
                .sf
                .request
                .as_ref()
                .and_then(|r| r.factor.clone())
                .and_then(|f| self.present_enrolled(&f))
                .is_some();
            self.vm.set_card_panel(Some(CardPanel { note: message, can_retry: present, busy: false }));
            Vec::new()
        } else {
            // Offer the recovery code instead; never retry the card by ourselves.
            vec![self.ask_recovery_code(Some(message))]
        }
    }

    fn secret_obtained(&mut self, secret: SecondSecret) -> Vec<UiEffect> {
        let Some(request) = self.sf.request.take() else { return Vec::new() };
        if let Some(f) = &request.factor {
            if !f.matches(&secret) {
                self.sf.request = Some(request);
                return self.secret_failed(
                    "That is not this user's current second factor (an old recovery code, or a card \
                     enrolled for someone else)."
                        .into(),
                );
            }
        }
        let name = request.name;
        match request.goal {
            Goal::Unlock { password } => {
                self.vm.set_card_panel(Some(CardPanel { note: "Unlocking…".into(), can_retry: false, busy: true }));
                let n = name.clone();
                let purpose = WorkPurpose::UnlockKeys { name, token: request.token };
                vec![self.work(purpose, move || WorkOutput::Keys(derive_all_with_secret(&n, &password, &secret).map(Box::new)))]
            }
            Goal::ExportReveal { password } => {
                let Some(flow) = self.export.as_ref().map(|f| f.id) else { return Vec::new() };
                let n = name.clone();
                let purpose = WorkPurpose::FlowKeys { flow, step: crate::core::STEP_EXPORT, name };
                vec![self.work(purpose, move || WorkOutput::Keys(derive_all_with_secret(&n, &password, &secret).map(Box::new)))]
            }
            Goal::Import { flow, step, password } => {
                let n = name.clone();
                let purpose = WorkPurpose::FlowKeys { flow, step, name };
                vec![self.work(purpose, move || WorkOutput::Keys(derive_all_with_secret(&n, &password, &secret).map(Box::new)))]
            }
            Goal::Disable { password } => {
                let Some(mut user) = self.vm.user().cloned() else { return Vec::new() };
                let purpose = WorkPurpose::Rekey {
                    what: "Second factor not turned off",
                    done: "Second factor turned off: every generated password changed back to the ones of your master password alone.",
                };
                vec![self.work(purpose, move || {
                    WorkOutput::Rekeyed(rekey_boxed(&mut user, |u| u.disable_second_factor(&password, &secret)))
                })]
            }
            Goal::ChangePassword { old, new } => {
                let Some(mut user) = self.vm.user().cloned() else { return Vec::new() };
                let purpose = WorkPurpose::Rekey {
                    what: "Master password not changed",
                    done: "Master password changed: every generated password is different now.  Your smart cards and recovery code still work.",
                };
                vec![self.work(purpose, move || {
                    WorkOutput::Rekeyed(rekey_boxed(&mut user, |u| u.change_master_password_with_second_factor(&old, &new, &secret)))
                })]
            }
            Goal::Rotate => {
                let new = match SecondSecret::generate() {
                    Ok(s) => s,
                    Err(e) => return vec![self.error_prompt("No new recovery code", capitalise(&e.to_string()))],
                };
                // Re-enrol the enrolled cards that are inserted now (public-key
                // wrap, no PIN); the others must be added again.
                let mut slots = Vec::new();
                if let Some(f) = self.session_factor().flatten() {
                    for key in self.cards.keys().unwrap_or_default() {
                        let fp = hex(&key.fingerprint);
                        if !f.slots().iter().any(|s| s.fingerprint().eq_ignore_ascii_case(&fp)) {
                            continue;
                        }
                        if let Some(recipient) = key.recipient() {
                            if let Ok(blob) = self.cards.wrap(&recipient, new.as_bytes()) {
                                if let Ok(slot) = Slot::new(SlotKind::SmartCard, &slot_label(&key), &fp, recipient.algorithm.id(), blob) {
                                    slots.push(slot);
                                }
                            }
                        }
                    }
                }
                self.sf.rotate = Some(RotateFlow { old: secret, new, slots });
                vec![self.show_code()]
            }
            Goal::AddCard { key } => {
                let Some(recipient) = key.recipient() else {
                    return vec![self.error_prompt("Card not added", "This card cannot decrypt.")];
                };
                let blob = match self.cards.wrap(&recipient, secret.as_bytes()) {
                    Ok(b) => b,
                    Err(e) => return vec![self.error_prompt("Card not added", capitalise(&e))],
                };
                let slot = match Slot::new(SlotKind::SmartCard, &slot_label(&key), &hex(&key.fingerprint), recipient.algorithm.id(), blob.clone()) {
                    Ok(s) => s,
                    Err(e) => return vec![self.error_prompt("Card not added", capitalise(&e.to_string()))],
                };
                self.verify_slot(&key, slot, blob, recipient.algorithm, secret, false)
            }
        }
    }

    /// Unwrap a freshly wrapped slot once with its card (one PIN prompt) and
    /// compare, so a card that cannot really decrypt is never enrolled.
    fn verify_slot(&mut self, key: &CardKey, slot: Slot, blob: Vec<u8>, algorithm: WrapAlgorithm, expect: SecondSecret, enabling: bool) -> Vec<UiEffect> {
        self.vm.set_notice("Checking the card: enter its PIN in the system dialog…");
        let cards = self.cards.clone();
        let fingerprint = key.fingerprint;
        let purpose = WorkPurpose::Verify { slot: Box::new(slot), expect, enabling };
        vec![self.work(purpose, move || WorkOutput::Unwrapped(cards.unwrap(&fingerprint, algorithm, &blob)))]
    }

    // --------------------------------------------------------- work results

    pub fn work_finished(&mut self, id: u64, output: WorkOutput, now: std::time::Instant) -> Vec<UiEffect> {
        self.last_activity = now;
        let Some(purpose) = self.sf.works.remove(&id) else { return Vec::new() };
        match (purpose, output) {
            (WorkPurpose::Secret, WorkOutput::Unwrapped(result)) => {
                if self.sf.request.is_none() {
                    return Vec::new(); // abandoned (lock / cancel)
                }
                match result.map_err(|e| e.to_string()).and_then(|b| SecondSecret::from_bytes(&b).map_err(|e| e.to_string())) {
                    Ok(secret) => self.secret_obtained(secret),
                    Err(e) => self.secret_failed(e),
                }
            }
            (WorkPurpose::Verify { slot, expect, enabling }, WorkOutput::Unwrapped(result)) => {
                let ok = matches!(&result, Ok(b) if b.as_slice() == expect.as_bytes());
                if !ok {
                    self.sf.enable = None;
                    self.sf.add = None;
                    let why = match result {
                        Err(e) => e.to_string(),
                        Ok(_) => "The card returned something else than what was stored for it.".into(),
                    };
                    return vec![self.error_prompt("The card could not be enrolled", format!("{why}\n\nNothing was changed."))];
                }
                self.vm.set_notice("The card was checked: it can unlock this user.");
                if enabling {
                    self.sf.enable = Some(EnableFlow { secret: expect, slots: vec![*slot] });
                    vec![self.show_code()]
                } else {
                    let result = match self.vm.session_mut() {
                        Some((user, keys)) => user.add_second_factor_slot(keys, *slot),
                        None => return Vec::new(),
                    };
                    match result {
                        Ok(()) => {
                            self.vm.mark_dirty();
                            self.vm.persist_now();
                            self.vm.set_notice("Smart card added.  It now unlocks this user too.");
                            Vec::new()
                        }
                        Err(e) => vec![self.error_prompt("Card not added", capitalise(&e.to_string()))],
                    }
                }
            }
            (WorkPurpose::UnlockKeys { name, token }, WorkOutput::Keys(result)) => {
                if !self.vm.card_active() {
                    return Vec::new(); // cancelled meanwhile
                }
                let outcome = result.map_err(|e| capitalise(&e)).and_then(|b| {
                    let (keys, icon) = *b;
                    self.vm.open_session(&name, keys, Some(icon)).map_err(|e| match e {
                        StoreError::WrongMasterPassword { full_name } => format!(
                            "Incorrect master password for {full_name}.  (The second factor was accepted: it is the typed \
                             password that does not match.)"
                        ),
                        other => other.to_string(),
                    })
                });
                match outcome {
                    Ok(()) => {
                        self.sf.unlocked_token = token;
                        self.remember_unlocked_user_pub();
                    }
                    Err(e) => self.vm.cancel_second_factor(Some(e)),
                }
                Vec::new()
            }
            (WorkPurpose::FlowKeys { flow, step, name }, WorkOutput::Keys(result)) => {
                let derived =
                    Derived { id: 0, purpose: DerivePurpose::Flow { flow, step }, full_name: name, result: result.map(|b| *b) };
                self.flow_derived_pub(flow, step, derived)
            }
            (WorkPurpose::Rekey { what, done }, WorkOutput::Rekeyed(result)) => match result.map(|b| *b) {
                Ok((user, keys)) => {
                    let name = user.full_name().to_owned();
                    self.vm.replace_session(user, keys);
                    // Saved Keychain keys would bypass the card (and are stale).
                    let _ = self.vault.delete_all(&name);
                    if let Some((u, _)) = self.vm.session_mut() {
                        u.preferences.biometric_lock = false;
                    }
                    self.vm.mark_dirty();
                    self.vm.persist_now();
                    self.vm.saver().flush();
                    self.vm.refresh_users();
                    self.sf.unlocked_token = None;
                    vec![self.info(done.split(':').next().unwrap_or(done).to_owned(), done)]
                }
                Err(e) => vec![self.error_prompt(what, e)],
            },
            _ => Vec::new(),
        }
    }

    // ---------------------------------------------------------------- enable

    pub(crate) fn sf_enable(&mut self) -> Vec<UiEffect> {
        let Some(name) = self.vm.unlocked_user().map(str::to_owned) else { return Vec::new() };
        if self.session_has_second_factor() {
            return Vec::new();
        }
        let prompt = Prompt::new(
            Style::Critical,
            format!("Require a smart card for {name}?"),
            format!(
                "Your passwords will then come from your master password PLUS a random secret.  The secret is \
                 not taken from your card: it is newly generated, and stored in your user file encrypted so \
                 that only your smart card can decrypt it.  What changes:\n\n\
                 • EVERY generated password, login name and answer of {name} changes: you must update them on \
                 each site.  Stored passwords are kept.\n\
                 • You get a recovery code, shown once.  You need it if the card is lost, replaced or expires \
                 (CACs are reissued every few years).  Anywhere else, type your master password, a space and \
                 the code.\n\
                 • Unlocking asks for the card and its PIN.  Save Password (Touch ID) is turned off.\n\
                 • The card's PIN is asked once now, to check the card really works."
            ),
        )
        .button("Cancel", ButtonRole::Cancel)
        .button("Continue…", ButtonRole::Destructive);
        vec![self.ask_sf(prompt, SfPending::Explain)]
    }

    fn sf_choose_card(&mut self, adding: bool) -> Vec<UiEffect> {
        let enrolled: Vec<String> =
            self.session_factor().flatten().map(|f| f.slots().iter().map(|s| s.fingerprint().to_owned()).collect()).unwrap_or_default();
        let keys: Vec<CardKey> = match self.cards.keys() {
            Ok(k) => k.into_iter().filter(|k| !enrolled.iter().any(|e| e.eq_ignore_ascii_case(&hex(&k.fingerprint)))).collect(),
            Err(e) => return vec![self.error_prompt("Smart cards are not available", e)],
        };
        let now = mpw_model::Timestamp::now().as_unix();
        match crate::card::choose(&keys, now) {
            Ok(i) => {
                let key = keys[i].clone();
                let until = key.not_after.map_or_else(|| "unknown".into(), date);
                let prompt = Prompt::new(
                    Style::Informational,
                    if adding { "Add this smart card?" } else { "Use this smart card?" },
                    format!(
                        "{}\n{} key, {}\nFingerprint {}\nValid until {until}",
                        key.label,
                        key.kind,
                        key.slot.describe(),
                        short_fingerprint(&key.fingerprint)
                    ),
                )
                .button(if adding { "Add This Card" } else { "Use This Card" }, ButtonRole::Default)
                .button("Cancel", ButtonRole::Cancel);
                let prompt = if adding { prompt } else { prompt.button("Without a Card…", ButtonRole::Normal) };
                vec![self.ask_sf(prompt, SfPending::CardChoice { key: Box::new(key), adding })]
            }
            Err(reason) if adding => vec![self.error_prompt("No card to add", reason)],
            Err(reason) => vec![self.no_card_prompt(reason)],
        }
    }

    fn no_card_prompt(&mut self, reason: String) -> UiEffect {
        let prompt = Prompt::new(
            Style::Critical,
            "No usable smart card",
            format!(
                "{reason}\n\nYou can still turn the second factor on with only a recovery code: you would type \
                 the code every time you unlock, and add a card later.  If you lose the code you lose access \
                 to every password of this user."
            ),
        )
        .button("Cancel", ButtonRole::Cancel)
        .button("Use Recovery Code Only…", ButtonRole::Destructive);
        self.ask_sf(prompt, SfPending::NoCard)
    }

    fn show_code(&mut self) -> UiEffect {
        let code = match (&self.sf.enable, &self.sf.rotate) {
            (Some(e), _) => e.secret.recovery_code(),
            (None, Some(r)) => r.new.recovery_code(),
            _ => return self.error_prompt("Internal error", "No recovery code."),
        };
        let cards = self.sf.enable.as_ref().map(|e| e.slots.len()).or(self.sf.rotate.as_ref().map(|r| r.slots.len())).unwrap_or(0);
        let prompt = Prompt::new(
            Style::Warning,
            "Your recovery code",
            format!(
                "{}\n\nWrite it down (or store it in a safe place) now: it is shown only once.  With your master \
                 password and this code anyone can recreate your passwords; without the code, a lost card means \
                 lost passwords.  {}",
                code.as_str(),
                if cards == 0 { "No card is enrolled: you will type this code to unlock." } else { "Your card is enrolled." }
            ),
        )
        .button("I Have Saved It", ButtonRole::Default)
        .button("Copy Code", ButtonRole::Normal)
        .button("Cancel", ButtonRole::Cancel);
        self.ask_sf(prompt, SfPending::ShowCode)
    }

    fn confirm_prompt(&mut self, problem: Option<&str>) -> UiEffect {
        let rotating = self.sf.rotate.is_some();
        let mut message = String::from(
            "Type the LAST 5 characters of the recovery code, to show you have it, and your current master password.",
        );
        if let Some(p) = problem {
            message = format!("{p}\n\n{message}");
        }
        let prompt = Prompt::new(Style::Warning, if rotating { "Confirm the new recovery code" } else { "Confirm and turn on" }, message)
            .field("Last 5 characters of the recovery code", false)
            .field("Current master password", true)
            .button("Cancel", ButtonRole::Cancel)
            .button(if rotating { "Replace Recovery Code" } else { "Turn On Second Factor" }, ButtonRole::Destructive);
        self.ask_sf(prompt, SfPending::Confirm)
    }

    // ------------------------------------------------- other management

    pub(crate) fn sf_disable(&mut self) -> Vec<UiEffect> {
        let Some(name) = self.vm.unlocked_user().map(str::to_owned) else { return Vec::new() };
        let prompt = Prompt::new(
            Style::Critical,
            format!("Turn off the second factor for {name}?"),
            "EVERY generated password changes back to the ones of your master password alone; update them on \
             each site.  Enrolled cards and the recovery code stop working.  Enter your master password; the \
             card (or recovery code) is asked next.",
        )
        .field("Current master password", true)
        .button("Cancel", ButtonRole::Cancel)
        .button("Turn Off…", ButtonRole::Destructive);
        vec![self.ask_sf(prompt, SfPending::DisableConfirm)]
    }

    pub(crate) fn sf_rotate(&mut self) -> Vec<UiEffect> {
        let Some(name) = self.vm.unlocked_user().map(str::to_owned) else { return Vec::new() };
        let prompt = Prompt::new(
            Style::Critical,
            "Replace the recovery code?",
            format!(
                "A new secret and recovery code replace the old ones.  EVERY generated password of {name} \
                 changes.  Enrolled cards that are inserted now are re-enrolled; other cards must be added \
                 again.  The current card or recovery code is asked first."
            ),
        )
        .button("Cancel", ButtonRole::Cancel)
        .button("Continue…", ButtonRole::Destructive);
        vec![self.ask_sf(prompt, SfPending::RotateExplain)]
    }

    pub(crate) fn sf_add_card(&mut self) -> Vec<UiEffect> {
        if self.session_factor().is_none() {
            return Vec::new();
        }
        self.sf_choose_card(true)
    }

    pub(crate) fn sf_remove_slot(&mut self, index: usize) -> Vec<UiEffect> {
        let Some(f) = self.session_factor().flatten() else { return Vec::new() };
        let Some(slot) = f.slots().get(index).cloned() else { return Vec::new() };
        let last = f.slots().len() == 1;
        let prompt = Prompt::new(
            Style::Warning,
            format!("Remove {}?", slot.label()),
            format!(
                "Fingerprint {}, added {}.  The card can no longer unlock this user.  Passwords do not change.{}",
                &slot.fingerprint()[..16],
                date(slot.added().as_unix()),
                if last { "\n\nIt is the LAST card: you will need your recovery code every time you unlock.  Only continue if you have the code." } else { "" }
            ),
        )
        .button("Cancel", ButtonRole::Cancel)
        .button("Remove", ButtonRole::Destructive);
        vec![self.ask_sf(prompt, SfPending::RemoveSlot { id: slot.id().to_owned(), last })]
    }

    // --------------------------------------------------------------- dialogs

    fn ask_sf(&mut self, prompt: Prompt, pending: SfPending) -> UiEffect {
        self.ask_pub(prompt, crate::core::Pending::Sf(pending))
    }

    pub(crate) fn sf_answered(&mut self, pending: SfPending, answer: PromptAnswer) -> Vec<UiEffect> {
        match pending {
            SfPending::Explain => {
                if answer.button != 1 {
                    return Vec::new();
                }
                self.sf_choose_card(false)
            }
            SfPending::CardChoice { key, adding } => match (answer.button, adding) {
                (0, false) => {
                    let secret = match SecondSecret::generate() {
                        Ok(s) => s,
                        Err(e) => return vec![self.error_prompt("Second factor not turned on", capitalise(&e.to_string()))],
                    };
                    let Some(recipient) = key.recipient() else { return Vec::new() };
                    let blob = match self.cards.wrap(&recipient, secret.as_bytes()) {
                        Ok(b) => b,
                        Err(e) => return vec![self.error_prompt("Second factor not turned on", capitalise(&e))],
                    };
                    let slot = match Slot::new(SlotKind::SmartCard, &slot_label(&key), &hex(&key.fingerprint), recipient.algorithm.id(), blob.clone()) {
                        Ok(s) => s,
                        Err(e) => return vec![self.error_prompt("Second factor not turned on", capitalise(&e.to_string()))],
                    };
                    self.verify_slot(&key, slot, blob, recipient.algorithm, secret, true)
                }
                (0, true) => {
                    let Some(name) = self.vm.unlocked_user().map(str::to_owned) else { return Vec::new() };
                    let factor = self.session_factor().flatten();
                    self.request_secret(name, factor, Goal::AddCard { key })
                }
                (2, false) => vec![self.no_card_prompt("You chose to continue without a card.".into())],
                _ => Vec::new(),
            },
            SfPending::NoCard => {
                if answer.button != 1 {
                    return Vec::new();
                }
                match SecondSecret::generate() {
                    Ok(secret) => {
                        self.sf.enable = Some(EnableFlow { secret, slots: Vec::new() });
                        vec![self.show_code()]
                    }
                    Err(e) => vec![self.error_prompt("Second factor not turned on", capitalise(&e.to_string()))],
                }
            }
            SfPending::ShowCode => match answer.button {
                0 => vec![self.confirm_prompt(None)],
                1 => {
                    let code = match (&self.sf.enable, &self.sf.rotate) {
                        (Some(e), _) => e.secret.recovery_code(),
                        (None, Some(r)) => r.new.recovery_code(),
                        _ => return Vec::new(),
                    };
                    let now = std::time::Instant::now();
                    if let Err(e) = self.clipboard.copy(self.pasteboard.as_mut(), &code, now) {
                        self.vm.set_error(format!("Could not copy: {e}"));
                    }
                    vec![self.show_code()]
                }
                _ => {
                    self.sf.enable = None;
                    self.sf.rotate = None;
                    Vec::new()
                }
            },
            SfPending::Confirm => {
                if answer.button != 1 {
                    self.sf.enable = None;
                    self.sf.rotate = None;
                    return Vec::new();
                }
                let code = match (&self.sf.enable, &self.sf.rotate) {
                    (Some(e), _) => e.secret.recovery_code(),
                    (None, Some(r)) => r.new.recovery_code(),
                    _ => return Vec::new(),
                };
                let typed: String = answer.value(0).chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
                if !typed.eq_ignore_ascii_case(&code_groups_last(&code)) {
                    return vec![self.confirm_prompt(Some("Those are not the last 5 characters of the recovery code."))];
                }
                let password = Zeroizing::new(answer.value(1).to_owned());
                if password.is_empty() {
                    return vec![self.confirm_prompt(Some("Enter your current master password."))];
                }
                let Some(mut user) = self.vm.user().cloned() else { return Vec::new() };
                if let Some(e) = self.sf.enable.take() {
                    let purpose = WorkPurpose::Rekey {
                        what: "Second factor not turned on",
                        done: "Second factor turned on: every generated password changed.  Update them on each site.  Keep your recovery code safe.",
                    };
                    vec![self.work(purpose, move || {
                        WorkOutput::Rekeyed(rekey_boxed(&mut user, |u| {
                            u.enable_second_factor(&password, &e.secret, e.slots, RecoveryCode::ConfirmedSaved)
                        }))
                    })]
                } else if let Some(r) = self.sf.rotate.take() {
                    let purpose = WorkPurpose::Rekey {
                        what: "Recovery code not replaced",
                        done: "New recovery code in place: every generated password changed.  Cards that were not inserted must be added again.",
                    };
                    vec![self.work(purpose, move || {
                        WorkOutput::Rekeyed(rekey_boxed(&mut user, |u| {
                            u.rotate_second_secret(&password, &r.old, &r.new, r.slots, RecoveryCode::ConfirmedSaved)
                        }))
                    })]
                } else {
                    Vec::new()
                }
            }
            SfPending::RecoveryCode => {
                if answer.button != 0 {
                    self.sf.request = None;
                    self.vm.cancel_second_factor(None);
                    return Vec::new();
                }
                match SecondSecret::parse_recovery_code(answer.value(0)) {
                    Ok(secret) => self.secret_obtained(secret),
                    Err(e) => vec![self.ask_recovery_code(Some(capitalise(&e.to_string())))],
                }
            }
            SfPending::DisableConfirm => {
                if answer.button != 1 || answer.value(0).is_empty() {
                    return Vec::new();
                }
                let Some(name) = self.vm.unlocked_user().map(str::to_owned) else { return Vec::new() };
                let factor = self.session_factor().flatten();
                self.request_secret(name, factor, Goal::Disable { password: Zeroizing::new(answer.value(0).to_owned()) })
            }
            SfPending::RotateExplain => {
                if answer.button != 1 {
                    return Vec::new();
                }
                let Some(name) = self.vm.unlocked_user().map(str::to_owned) else { return Vec::new() };
                let factor = self.session_factor().flatten();
                self.request_secret(name, factor, Goal::Rotate)
            }
            SfPending::RemoveSlot { id, last } => {
                if answer.button != 1 {
                    return Vec::new();
                }
                let recovery = if last { RecoveryCode::ConfirmedSaved } else { RecoveryCode::NotConfirmed };
                let result = match self.vm.session_mut() {
                    Some((user, keys)) => user.remove_second_factor_slot(keys, &id, recovery),
                    None => return Vec::new(),
                };
                match result {
                    Ok(slot) => {
                        self.vm.mark_dirty();
                        self.vm.persist_now();
                        self.vm.set_notice(format!("Removed {}.", slot.label()));
                        Vec::new()
                    }
                    Err(e) => vec![self.error_prompt("Card not removed", capitalise(&e.to_string()))],
                }
            }
        }
    }

    // ------------------------------------------------------------- presence

    /// Card presence, called from `tick`: lock if the unlocking card was
    /// removed; continue a pending unlock when the awaited card arrives.
    pub(crate) fn sf_tick(&mut self) -> Vec<UiEffect> {
        let tokens = self.cards.tokens();
        // Checked on every tick, not only on changes: the card may have been
        // pulled before we ever saw the token list change.
        if let Some(t) = self.sf.unlocked_token.clone() {
            if self.prefs.lock_on_card_removal && self.vm.is_unlocked() && !tokens.contains(&t) {
                self.lock(LockReason::CardRemoved);
                self.set_close_reason("smart card removed");
                self.vm.set_error("Locked: the smart card was removed.");
                self.sf.tokens = tokens;
                return Vec::new();
            }
        }
        if tokens == self.sf.tokens {
            return Vec::new();
        }
        self.sf.tokens = tokens.clone();
        let waiting = self.sf.request.as_ref().is_some_and(|r| r.waiting);
        if waiting {
            if let Some((key, slot)) = self.sf.request.as_ref().and_then(|r| r.factor.clone()).and_then(|f| self.present_enrolled(&f)) {
                // The card the user was asked to insert: one attempt.
                return self.start_unwrap(key, slot);
            }
        }
        Vec::new()
    }

    pub(crate) fn sf_reset(&mut self) {
        let tokens = std::mem::take(&mut self.sf.tokens);
        self.sf = SfState { tokens, ..SfState::default() };
    }

    /// Menu lines: the enrolled cards (label, fingerprint, date, inserted?).
    pub(crate) fn sf_menu_slots(&self) -> Vec<(String, bool)> {
        let Some(Some(f)) = self.session_factor() else { return Vec::new() };
        let inserted: Vec<String> = self.cards.keys().unwrap_or_default().iter().map(|k| hex(&k.fingerprint)).collect();
        f.slots()
            .iter()
            .map(|s| {
                let here = inserted.iter().any(|i| i.eq_ignore_ascii_case(s.fingerprint()));
                (
                    format!("{} — {} — added {}{}", s.label(), &s.fingerprint()[..16], date(s.added().as_unix()), if here { " — inserted ✓" } else { "" }),
                    here,
                )
            })
            .collect()
    }
}

fn rekey_boxed(
    user: &mut User,
    op: impl FnOnce(&mut User) -> mpw_model::Result<UserKeys>,
) -> Result<Box<(User, UserKeys)>, String> {
    rekey(user, op).map(Box::new)
}

/// Run a re-keying model operation on `user`, then turn the returned key
/// holder into a password-less one authenticated against the result.
fn rekey(user: &mut User, op: impl FnOnce(&mut User) -> mpw_model::Result<UserKeys>) -> Result<(User, UserKeys), String> {
    let name = user.full_name().to_owned();
    let keys = op(user).map_err(|e| match StoreError::from_model(e, &name) {
        StoreError::WrongMasterPassword { .. } => "Incorrect master password.".to_owned(),
        other => other.to_string(),
    })?;
    let mut keys = without_password(&name, keys)?;
    user.authenticate(&mut keys).map_err(|e| capitalise(&e.to_string()))?;
    Ok((user.clone(), keys))
}
