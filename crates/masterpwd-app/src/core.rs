//! The whole app's behaviour, minus AppKit: lock policy, preferences, the
//! clipboard, the menu, dialogs and the multi-step flows (import, export,
//! saved keys).  The platform layer owns one [`AppCore`], forwards every event
//! to it and carries out the returned [`UiEffect`]s.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mpw_core::Zeroizing;
use mpw_model::{ExportMode, Format, KeyId, User, UserFile, UserKeys};

use crate::clipboard::{ClipboardGuard, Pasteboard};
use crate::data::{capitalise, StoreError};
use crate::keys::{copy_keys, DeriveJob, DerivePurpose, Derived, KeyVault};
use crate::menu::{MenuCommand, MenuEntry, MenuItem, Modifiers};
use crate::prefs::{Preferences, PrefsStore, CLIPBOARD_CLEAR_CHOICES, IDLE_LOCK_CHOICES};
use crate::prompt::{ButtonRole, FileRequest, Prompt, PromptAnswer, Style};
use crate::view_model::{Ask, Screen, SitesViewModel, VmEffect};

/// What the platform layer must do.
pub enum UiEffect {
    ShowSitesWindow,
    CloseSitesWindow,
    /// Give focus back to the previous app (so the user can paste).
    HideApp,
    Derive(DeriveJob),
    ScheduleIdenticon { generation: u64, delay: Duration },
    SetLoginItem(bool),
    ShowWelcome,
    Terminate,
    /// Show a dialog; answer with [`AppCore::prompt_answered`].
    Prompt(Prompt),
    /// Show an open/save panel; answer with [`AppCore::file_chosen`].
    ChooseFile(FileRequest),
    /// Ask for device-owner authentication (Touch ID or the account
    /// password); answer with [`AppCore::device_auth_finished`].
    DeviceAuth { id: u64, reason: String },
}

impl fmt::Debug for UiEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShowSitesWindow => f.write_str("ShowSitesWindow"),
            Self::CloseSitesWindow => f.write_str("CloseSitesWindow"),
            Self::HideApp => f.write_str("HideApp"),
            Self::Derive(j) => write!(f, "Derive({j:?})"),
            Self::ScheduleIdenticon { generation, .. } => write!(f, "ScheduleIdenticon({generation})"),
            Self::SetLoginItem(on) => write!(f, "SetLoginItem({on})"),
            Self::ShowWelcome => f.write_str("ShowWelcome"),
            Self::Terminate => f.write_str("Terminate"),
            Self::Prompt(p) => write!(f, "Prompt({:?})", p.title),
            Self::ChooseFile(r) => write!(f, "ChooseFile({:?})", r.title),
            Self::DeviceAuth { id, .. } => write!(f, "DeviceAuth({id})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    Command,
    Hotkey,
    Sleep,
    ScreenLocked,
    SessionSwitched,
    Idle,
    /// "Remember Password" is off and the sites window closed.
    WindowClosed,
    Quit,
}

impl LockReason {
    /// Every lock clears our clipboard secret, except the routine
    /// window-closed lock that follows a copy.
    pub fn clears_clipboard(self) -> bool {
        self != Self::WindowClosed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemEvent {
    WillSleep,
    ScreensDidSleep,
    ScreenLocked,
    ScreensaverStarted,
    SessionResignedActive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginItemState {
    Unavailable(String),
    Disabled,
    Enabled,
    RequiresApproval,
}

// ----------------------------------------------------------------- flows

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportMode {
    Undecided,
    New,
    Merge,
    Replace,
}

struct ImportFlow {
    id: u64,
    file: UserFile,
    name: String,
    file_key_id: Option<KeyId>,
    exists: bool,
    mode: ImportMode,
    /// Keys authenticated against the stored user (merge/replace).
    existing_keys: Option<UserKeys>,
    existing_key_id: Option<KeyId>,
    /// Keys for the import file.
    import_keys: Option<UserKeys>,
}

struct ExportFlow {
    id: u64,
    reveal: bool,
    /// For a revealed export: keys re-derived from the re-entered password.
    keys: Option<UserKeys>,
}

enum Pending {
    Ask(Ask),
    Info,
    DeleteUser(String),
    ImportChoice,
    ImportExistingPassword,
    ImportPassword,
    ExportWarning,
    ExportPassword,
    ChangePassword,
}

enum FilePending {
    Import,
    Export,
}

const STEP_EXISTING: u32 = 1;
const STEP_IMPORT: u32 = 2;
const STEP_EXPORT: u32 = 3;
const STEP_CHANGE_CURRENT: u32 = 4;
const STEP_CHANGE_NEW: u32 = 5;

pub struct AppCore {
    vm: SitesViewModel,
    prefs: Preferences,
    prefs_store: Box<dyn PrefsStore>,
    pasteboard: Box<dyn Pasteboard>,
    clipboard: ClipboardGuard,
    vault: Box<dyn KeyVault>,
    /// Whether device-owner authentication can be used (else: why not).
    quick_unlock: Result<(), String>,
    last_activity: Instant,
    window_open: bool,
    login_item: LoginItemState,
    next_id: u64,
    prompts: BTreeMap<u64, Pending>,
    files: BTreeMap<u64, FilePending>,
    import: Option<ImportFlow>,
    export: Option<ExportFlow>,
    device_auth: Option<(u64, String)>,
    last_save_error: Option<String>,
    change_password: Option<ChangeFlow>,
    last_close_reason: Option<String>,
}

/// Change Master Password: both derivations run off the main thread.
struct ChangeFlow {
    id: u64,
    current: Option<(UserKeys, mpw_core::Identicon)>,
    new: Option<(UserKeys, mpw_core::Identicon)>,
}

fn plural(n: u32, unit: &str) -> String {
    if n == 1 { format!("1 {unit}") } else { format!("{n} {unit}s") }
}

/// Write an export file: created `0600`, written in place.
///
/// Not via a temporary file + rename (as `mpw_model::export_to` does): under
/// the App Sandbox we may write only the exact file the user picked in the
/// save panel, not a sibling temporary file.
pub fn write_export(path: &Path, user: &User, mode: ExportMode<'_>) -> Result<Format, String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let format = Format::from_path(path).unwrap_or(Format::Json);
    let data = mpw_model::write(user, format, mode).map_err(|e| capitalise(&e.to_string()))?;
    let io = |e: std::io::Error| format!("Could not write {}: {e}", path.display());
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(io)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(io)?;
    f.write_all(data.as_bytes()).map_err(io)?;
    f.sync_all().map_err(io)?;
    Ok(format)
}

impl AppCore {
    pub fn new(
        vm: SitesViewModel,
        prefs_store: Box<dyn PrefsStore>,
        pasteboard: Box<dyn Pasteboard>,
        vault: Box<dyn KeyVault>,
        quick_unlock: Result<(), String>,
        login_item: LoginItemState,
        now: Instant,
    ) -> Self {
        let prefs = Preferences::load(prefs_store.as_ref());
        let mut vm = vm;
        vm.set_hide_passwords(prefs.hide_passwords);
        if let Some(name) = &prefs.last_full_name {
            vm.prefer_user(name);
        }
        Self {
            vm,
            clipboard: ClipboardGuard::new(prefs.clipboard_timeout()),
            prefs,
            prefs_store,
            pasteboard,
            vault,
            quick_unlock,
            last_activity: now,
            window_open: false,
            login_item,
            next_id: 1,
            prompts: BTreeMap::new(),
            files: BTreeMap::new(),
            import: None,
            export: None,
            device_auth: None,
            last_save_error: None,
            change_password: None,
            last_close_reason: None,
        }
    }

    pub fn vm(&self) -> &SitesViewModel {
        &self.vm
    }

    pub fn prefs(&self) -> &Preferences {
        &self.prefs
    }

    pub fn login_item(&self) -> &LoginItemState {
        &self.login_item
    }

    pub fn set_login_item(&mut self, state: LoginItemState) {
        self.login_item = state;
    }

    pub fn clipboard_holds_secret(&self) -> bool {
        self.clipboard.holds_secret(self.pasteboard.as_ref())
    }

    pub fn quick_unlock_available(&self) -> &Result<(), String> {
        &self.quick_unlock
    }

    fn id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    fn save_prefs(&mut self) {
        self.prefs.save(self.prefs_store.as_mut());
    }

    fn ask(&mut self, prompt: Prompt, pending: Pending) -> UiEffect {
        let id = self.id();
        self.prompts.insert(id, pending);
        UiEffect::Prompt(Prompt { id, ..prompt })
    }

    fn info(&mut self, title: impl Into<String>, message: impl Into<String>) -> UiEffect {
        self.ask(Prompt::info(title, message), Pending::Info)
    }

    fn error_prompt(&mut self, title: impl Into<String>, message: impl Into<String>) -> UiEffect {
        let prompt = Prompt::new(Style::Warning, title, message).button("OK", ButtonRole::Default);
        self.ask(prompt, Pending::Info)
    }

    pub fn launched(&mut self) -> Vec<UiEffect> {
        if self.prefs.welcome_shown {
            return Vec::new();
        }
        self.prefs.welcome_shown = true;
        self.save_prefs();
        vec![UiEffect::ShowWelcome]
    }

    /// Forward a sites-window interaction to the view-model.
    pub fn vm_event(&mut self, now: Instant, f: impl FnOnce(&mut SitesViewModel) -> Vec<VmEffect>) -> Vec<UiEffect> {
        self.last_activity = now;
        let effects = f(&mut self.vm);
        self.map_vm_effects(effects, now)
    }

    fn map_vm_effects(&mut self, effects: Vec<VmEffect>, now: Instant) -> Vec<UiEffect> {
        let mut out = Vec::new();
        for effect in effects {
            match effect {
                VmEffect::Derive(job) => out.push(UiEffect::Derive(job)),
                VmEffect::ScheduleIdenticon { generation, delay } => {
                    out.push(UiEffect::ScheduleIdenticon { generation, delay })
                }
                VmEffect::CloseWindow => {
                    self.last_close_reason = Some("Esc / cancel".into());
                    out.push(UiEffect::CloseSitesWindow)
                }
                VmEffect::Copy { text } => match self.clipboard.copy(self.pasteboard.as_mut(), &text, now) {
                    Ok(()) => {
                        self.last_close_reason = Some("copied".into());
                        out.extend([UiEffect::CloseSitesWindow, UiEffect::HideApp])
                    }
                    Err(e) => self.vm.set_error(format!("Could not copy: {e}")),
                },
                VmEffect::Ask(ask) => {
                    let prompt = ask.prompt();
                    out.push(self.ask(prompt, Pending::Ask(ask)));
                }
            }
        }
        out
    }

    /// A background derivation finished.
    pub fn derive_finished(&mut self, derived: Derived, now: Instant) -> Vec<UiEffect> {
        self.last_activity = now;
        match derived.purpose {
            DerivePurpose::Unlock | DerivePurpose::CreateUser => {
                self.vm.derive_finished(derived);
                self.remember_unlocked_user();
                Vec::new()
            }
            DerivePurpose::Flow { flow, step } => self.flow_derived(flow, step, derived),
        }
    }

    fn remember_unlocked_user(&mut self) {
        if let Some(name) = self.vm.unlocked_user().map(str::to_owned) {
            if self.prefs.last_full_name.as_deref() != Some(name.as_str()) {
                self.prefs.last_full_name = Some(name);
                self.save_prefs();
            }
        }
    }

    /// Lock: drop keys and decrypted data (pending changes are saved first),
    /// abandon flows and dialogs.
    pub fn lock(&mut self, reason: LockReason) {
        self.vm.lock();
        self.import = None;
        self.export = None;
        self.device_auth = None;
        self.change_password = None;
        self.prompts.clear();
        self.files.clear();
        if reason.clears_clipboard() {
            self.clipboard.clear_if_ours(self.pasteboard.as_mut());
        }
    }

    pub fn window_did_show(&mut self, now: Instant) {
        self.window_open = true;
        self.last_activity = now;
        self.vm.window_shown();
    }

    pub fn window_did_close(&mut self) {
        self.window_open = false;
        self.vm.set_reveal(false);
        if !self.prefs.remember_password && self.prompts.is_empty() && self.files.is_empty() {
            self.lock(LockReason::WindowClosed);
        }
    }

    pub fn is_window_open(&self) -> bool {
        self.window_open
    }

    /// Keyboard focus left us for another app (the app resigned active, or
    /// the non-activating sites panel lost key status to another app):
    /// dismiss the sites window, as the original did — unless one of our
    /// dialogs, panels or the Touch ID prompt is up.
    pub fn app_did_resign_active(&mut self) -> Vec<UiEffect> {
        if self.window_open && self.prompts.is_empty() && self.files.is_empty() && self.device_auth.is_none() {
            self.last_close_reason = Some("keyboard focus moved to another app".into());
            vec![UiEffect::CloseSitesWindow]
        } else {
            Vec::new()
        }
    }

    /// Whether a dialog, file panel or Touch ID prompt of ours is pending.
    pub fn is_busy(&self) -> bool {
        !self.prompts.is_empty() || !self.files.is_empty() || self.device_auth.is_some()
    }

    /// Why the sites window last closed (debug state).
    pub fn last_close_reason(&self) -> Option<&str> {
        self.last_close_reason.as_deref()
    }

    pub fn set_close_reason(&mut self, reason: impl Into<String>) {
        self.last_close_reason = Some(reason.into());
    }

    pub fn system_event(&mut self, event: SystemEvent) -> Vec<UiEffect> {
        let reason = match event {
            SystemEvent::WillSleep | SystemEvent::ScreensDidSleep => LockReason::Sleep,
            SystemEvent::ScreenLocked | SystemEvent::ScreensaverStarted => LockReason::ScreenLocked,
            SystemEvent::SessionResignedActive => LockReason::SessionSwitched,
        };
        self.lock(reason);
        if self.window_open {
            self.last_close_reason = Some(format!("system event: {event:?}"));
            vec![UiEffect::CloseSitesWindow]
        } else {
            Vec::new()
        }
    }

    /// About once a second: clipboard timeout, idle lock, debounced saves and
    /// save errors.
    pub fn tick(&mut self, now: Instant) {
        self.clipboard.tick(self.pasteboard.as_mut(), now);
        if let Some(idle) = self.prefs.idle_timeout() {
            if self.vm.screen() != Screen::Pick
                && self.vm.screen() != Screen::NewUser
                && now.saturating_duration_since(self.last_activity) >= idle
            {
                self.lock(LockReason::Idle);
            }
        }
        self.vm.tick(now);
        self.collect_save_errors();
    }

    fn collect_save_errors(&mut self) {
        let errors = self.vm.saver().take_errors();
        if let Some(last) = errors.last() {
            self.vm.set_error(format!("{last} — your changes are still in memory; they will be retried on the next change."));
            self.last_save_error = Some(last.clone());
        }
    }

    pub fn last_save_error(&self) -> Option<&str> {
        self.last_save_error.as_deref()
    }

    pub fn lock_hotkey(&mut self) -> Vec<UiEffect> {
        self.lock(LockReason::Hotkey);
        Vec::new()
    }

    /// Quit: save, wipe our clipboard secret and keys, terminate.
    pub fn quit(&mut self) -> Vec<UiEffect> {
        self.lock(LockReason::Quit);
        self.vm.saver().flush();
        self.collect_save_errors();
        if let Some(e) = &self.last_save_error {
            eprintln!("MasterPwd: {e}");
        }
        self.save_prefs();
        vec![UiEffect::Terminate]
    }

    // -------------------------------------------------------------- dialogs

    /// A dialog was answered.  Unknown ids (abandoned by a lock) are ignored.
    pub fn prompt_answered(&mut self, id: u64, answer: PromptAnswer, now: Instant) -> Vec<UiEffect> {
        self.last_activity = now;
        let Some(pending) = self.prompts.remove(&id) else { return Vec::new() };
        match pending {
            Pending::Info => Vec::new(),
            Pending::Ask(ask) => {
                self.vm.answer(ask, answer);
                Vec::new()
            }
            Pending::DeleteUser(name) => {
                if answer.button != 1 {
                    return Vec::new();
                }
                let _ = self.vault.delete_all(&name);
                match self.vm.delete_user(&name) {
                    Ok(()) => {
                        self.vm.set_notice(format!("Deleted {name}."));
                        Vec::new()
                    }
                    Err(e) => vec![self.error_prompt("Could not delete the user", e.to_string())],
                }
            }
            Pending::ImportChoice => {
                let mode = match answer.button {
                    0 => ImportMode::Merge,
                    2 => ImportMode::Replace,
                    _ => {
                        self.import = None;
                        return Vec::new();
                    }
                };
                if let Some(f) = &mut self.import {
                    f.mode = mode;
                }
                self.import_advance()
            }
            Pending::ImportExistingPassword | Pending::ImportPassword => {
                let step = if matches!(pending, Pending::ImportExistingPassword) { STEP_EXISTING } else { STEP_IMPORT };
                let Some((flow_id, name)) = self.import.as_ref().map(|f| (f.id, f.name.clone())) else {
                    return Vec::new();
                };
                if answer.button != 0 || answer.value(0).is_empty() {
                    self.import = None;
                    return Vec::new();
                }
                let id = self.id();
                let job = DeriveJob::new(
                    id,
                    DerivePurpose::Flow { flow: flow_id, step },
                    &name,
                    Zeroizing::new(answer.value(0).to_owned()),
                );
                vec![UiEffect::Derive(job)]
            }
            Pending::ExportWarning => {
                if answer.button != 1 {
                    self.export = None;
                    return Vec::new();
                }
                let name = self.vm.unlocked_user().unwrap_or_default().to_owned();
                let prompt = Prompt::new(
                    Style::Warning,
                    format!("Re-enter {name}'s master password"),
                    "To export your passwords in clear text, confirm your master password.",
                )
                .field("Master password", true)
                .button("Continue", ButtonRole::Default)
                .button("Cancel", ButtonRole::Cancel);
                vec![self.ask(prompt, Pending::ExportPassword)]
            }
            Pending::ChangePassword => self.change_password_answered(answer),
            Pending::ExportPassword => {
                let (Some(flow), Some(name)) = (&self.export, self.vm.unlocked_user()) else { return Vec::new() };
                if answer.button != 0 || answer.value(0).is_empty() {
                    self.export = None;
                    return Vec::new();
                }
                let (flow_id, name) = (flow.id, name.to_owned());
                let id = self.id();
                let job = DeriveJob::new(
                    id,
                    DerivePurpose::Flow { flow: flow_id, step: STEP_EXPORT },
                    &name,
                    Zeroizing::new(answer.value(0).to_owned()),
                );
                vec![UiEffect::Derive(job)]
            }
        }
    }

    /// A file panel was answered.
    pub fn file_chosen(&mut self, id: u64, path: Option<PathBuf>, now: Instant) -> Vec<UiEffect> {
        self.last_activity = now;
        let Some(pending) = self.files.remove(&id) else { return Vec::new() };
        let Some(path) = path else {
            self.export = None;
            return Vec::new();
        };
        match pending {
            FilePending::Import => self.import_path(&path),
            FilePending::Export => self.export_to(&path),
        }
    }

    // ---------------------------------------------------------------- import

    /// Start importing a file (from the open panel, or opened in Finder).
    pub fn import_path(&mut self, path: &Path) -> Vec<UiEffect> {
        if self.import.is_some() {
            return vec![self.error_prompt("An import is already in progress", "Finish or cancel it first.")];
        }
        let file = match mpw_model::read_user_file(path) {
            Ok(f) => f,
            Err(e) => {
                let file = path.file_name().map_or_else(String::new, |f| f.to_string_lossy().into_owned());
                return vec![self.error_prompt(format!("Could not import {file}"), capitalise(&e.to_string()))];
            }
        };
        let name = file.summary().full_name.clone();
        let exists = self.vm.users().iter().any(|u| u.full_name == name);
        let id = self.id();
        self.import = Some(ImportFlow {
            id,
            file_key_id: file.summary().key_id.clone(),
            file,
            name,
            exists,
            mode: ImportMode::Undecided,
            existing_keys: None,
            existing_key_id: None,
            import_keys: None,
        });
        self.import_advance()
    }

    fn import_advance(&mut self) -> Vec<UiEffect> {
        let Some(flow) = self.import.as_mut() else { return Vec::new() };
        let name = flow.name.clone();
        let sites = flow.file.summary().site_count;
        let clear_text = !flow.file.summary().redacted;
        let clear_note = if clear_text { "\n\nThis file contains passwords in clear text: delete it after importing." } else { "" };
        match flow.mode {
            ImportMode::Undecided if !flow.exists => {
                flow.mode = ImportMode::New;
                self.import_advance()
            }
            ImportMode::Undecided => {
                let prompt = Prompt::new(
                    Style::Warning,
                    format!("{name} already exists on this Mac"),
                    format!(
                        "The file has {sites} site{}.{clear_note}\n\n\
                         Merge: adds the sites you don't have yet and updates sites the file used more recently. \
                         Nothing is deleted and your master password stays the same.\n\n\
                         Replace: DELETES {name}'s current sites and settings on this Mac and uses the file instead. \
                         This cannot be undone and needs {name}'s current master password.",
                        if sites == 1 { "" } else { "s" }
                    ),
                )
                .button("Merge", ButtonRole::Default)
                .button("Cancel", ButtonRole::Cancel)
                .button("Replace…", ButtonRole::Destructive);
                vec![self.ask(prompt, Pending::ImportChoice)]
            }
            ImportMode::New => {
                if flow.import_keys.is_some() {
                    return self.import_execute();
                }
                let prompt = Prompt::new(
                    Style::Informational,
                    format!("Import {name}?"),
                    format!(
                        "{name} is new on this Mac.  The file has {sites} site{}.{clear_note}\n\n\
                         Enter the master password this export was made with.",
                        if sites == 1 { "" } else { "s" }
                    ),
                )
                .field("Master password of the export", true)
                .button("Import", ButtonRole::Default)
                .button("Cancel", ButtonRole::Cancel);
                vec![self.ask(prompt, Pending::ImportPassword)]
            }
            ImportMode::Merge | ImportMode::Replace => {
                if flow.existing_keys.is_none() {
                    // Use the session's keys if this user is unlocked.
                    let session_keys = match self.vm.session_mut() {
                        Some((user, keys)) if user.full_name() == name => {
                            copy_keys(&name, keys).map(|k| (k, user.key_id().cloned()))
                        }
                        _ => None,
                    };
                    let flow = self.import.as_mut().expect("checked above");
                    match session_keys {
                        Some((keys, key_id)) => {
                            flow.existing_keys = Some(keys);
                            flow.existing_key_id = key_id;
                        }
                        None => {
                            let replace = flow.mode == ImportMode::Replace;
                            let prompt = Prompt::new(
                                Style::Warning,
                                format!("{name}'s current master password"),
                                if replace {
                                    format!("Replacing deletes {name}'s current sites.  Confirm with {name}'s current master password.")
                                } else {
                                    format!("To merge into {name}, enter {name}'s current master password.")
                                },
                            )
                            .field("Current master password", true)
                            .button("Continue", ButtonRole::Default)
                            .button("Cancel", ButtonRole::Cancel);
                            return vec![self.ask(prompt, Pending::ImportExistingPassword)];
                        }
                    }
                }
                let flow = self.import.as_mut().expect("checked above");
                if flow.import_keys.is_none() {
                    let same = flow.file_key_id.is_none() || flow.file_key_id == flow.existing_key_id;
                    if same {
                        let existing = flow.existing_keys.as_mut().expect("set above");
                        flow.import_keys = copy_keys(&name, existing);
                    } else {
                        let prompt = Prompt::new(
                            Style::Informational,
                            "This export uses a different master password",
                            format!("Enter the master password {name} had when this file was exported."),
                        )
                        .field("Master password of the export", true)
                        .button("Continue", ButtonRole::Default)
                        .button("Cancel", ButtonRole::Cancel);
                        return vec![self.ask(prompt, Pending::ImportPassword)];
                    }
                }
                self.import_execute()
            }
        }
    }

    fn flow_derived(&mut self, flow_id: u64, step: u32, derived: Derived) -> Vec<UiEffect> {
        if step == STEP_CHANGE_CURRENT || step == STEP_CHANGE_NEW {
            return self.change_password_derived(flow_id, step, derived);
        }
        let keys = match derived.result {
            Ok((keys, _)) => keys,
            Err(e) => {
                self.import = None;
                self.export = None;
                return vec![self.error_prompt("Key derivation failed", capitalise(&e))];
            }
        };
        match step {
            STEP_EXISTING if self.import.as_ref().is_some_and(|f| f.id == flow_id) => {
                let name = derived.full_name;
                let mut keys = keys;
                match self.vm.store().load(&name, &mut keys) {
                    Ok(user) => {
                        if let Some(f) = &mut self.import {
                            f.existing_key_id = user.key_id().cloned();
                            f.existing_keys = Some(keys);
                        }
                        self.import_advance()
                    }
                    Err(e) => {
                        self.import = None;
                        vec![self.error_prompt("Import cancelled", e.to_string())]
                    }
                }
            }
            STEP_IMPORT if self.import.as_ref().is_some_and(|f| f.id == flow_id) => {
                if let Some(f) = &mut self.import {
                    f.import_keys = Some(keys);
                }
                self.import_advance()
            }
            STEP_EXPORT if self.export.as_ref().is_some_and(|f| f.id == flow_id) => {
                let Some(user) = self.vm.user() else { return Vec::new() };
                let mut check = user.clone();
                let mut keys = keys;
                if let Err(e) = check.authenticate(&mut keys) {
                    self.export = None;
                    let e = StoreError::from_model(e, user.full_name());
                    return vec![self.error_prompt("Export cancelled", e.to_string())];
                }
                let name = user.full_name().to_owned();
                if let Some(f) = &mut self.export {
                    f.keys = Some(keys);
                }
                vec![self.choose_export_file(&name, true)]
            }
            _ => Vec::new(),
        }
    }

    fn import_execute(&mut self) -> Vec<UiEffect> {
        let Some(mut flow) = self.import.take() else { return Vec::new() };
        let name = flow.name.clone();
        let Some(mut import_keys) = flow.import_keys.take() else { return Vec::new() };
        let imported = match flow.file.load(&mut import_keys) {
            Ok(u) => u,
            Err(e) => {
                let e = StoreError::from_model(e, &name);
                let msg = match e {
                    StoreError::WrongMasterPassword { .. } => {
                        "The master password does not match this export file.  Nothing was imported.".to_owned()
                    }
                    other => other.to_string(),
                };
                return vec![self.error_prompt("Import failed", msg)];
            }
        };
        let sites = imported.sites().len();
        match flow.mode {
            ImportMode::New | ImportMode::Undecided => match self.vm.store().create(&imported) {
                Ok(()) => {
                    self.vm.refresh_users();
                    vec![self.info(
                        format!("Imported {name}"),
                        format!("{sites} site{} imported.  Pick {name} and unlock to use them.", if sites == 1 { "" } else { "s" }),
                    )]
                }
                Err(e) => vec![self.error_prompt("Import failed", e.to_string())],
            },
            ImportMode::Merge => {
                let Some(mut existing_keys) = flow.existing_keys.take() else { return Vec::new() };
                let session_is_user = self.vm.unlocked_user() == Some(name.as_str());
                let result = if session_is_user {
                    let (user, keys) = self.vm.session_mut().expect("unlocked");
                    let r = mpw_model::merge(user, keys, &imported, &mut import_keys);
                    if r.is_ok() {
                        self.vm.mark_dirty();
                        self.vm.persist_now();
                        self.vm.saver().flush();
                    }
                    r.map_err(|e| StoreError::from_model(e, &name))
                } else {
                    match self.vm.store().load(&name, &mut existing_keys) {
                        Ok(mut user) => mpw_model::merge(&mut user, &mut existing_keys, &imported, &mut import_keys)
                            .map_err(|e| StoreError::from_model(e, &name))
                            .and_then(|s| {
                                self.vm.saver().flush();
                                self.vm.store().save(&user).map(|()| s)
                            }),
                        Err(e) => Err(e),
                    }
                };
                self.vm.refresh_users();
                if session_is_user {
                    self.vm.set_site_query("");
                }
                match result {
                    Ok(s) => {
                        let list = |v: &[String]| if v.is_empty() { "none".to_owned() } else { v.join(", ") };
                        vec![self.info(
                            format!("Merged into {name}"),
                            format!(
                                "Added {}: {}\nUpdated {}: {}\nSkipped {} (stored values could not be converted): {}",
                                s.added.len(),
                                list(&s.added),
                                s.replaced.len(),
                                list(&s.replaced),
                                s.skipped.len(),
                                list(&s.skipped)
                            ),
                        )]
                    }
                    Err(e) => vec![self.error_prompt("Merge failed", e.to_string())],
                }
            }
            ImportMode::Replace => {
                if self.vm.unlocked_user() == Some(name.as_str()) {
                    // Don't let the old session overwrite the replacement.
                    self.vm.discard_session();
                }
                self.vm.saver().flush();
                let _ = self.vault.delete_all(&name);
                match self.vm.store().save(&imported) {
                    Ok(()) => {
                        self.vm.refresh_users();
                        vec![self.info(
                            format!("Replaced {name}"),
                            format!("{name} now has the {sites} site{} from the file.  Saved keys in the Keychain were removed.",
                                if sites == 1 { "" } else { "s" }),
                        )]
                    }
                    Err(e) => vec![self.error_prompt("Replace failed", e.to_string())],
                }
            }
        }
    }

    // ---------------------------------------------------------------- export

    fn choose_export_file(&mut self, name: &str, reveal: bool) -> UiEffect {
        let id = self.id();
        self.files.insert(id, FilePending::Export);
        let date = mpw_model::Timestamp::now().to_rfc3339();
        let day = date.get(..10).unwrap_or("export");
        UiEffect::ChooseFile(FileRequest {
            id,
            save: true,
            title: if reveal { "Export Sites (Passwords Visible)".into() } else { "Export Sites".into() },
            message: if reveal {
                "WARNING: this file will contain your passwords in clear text.  Keep it safe and delete it when done.".into()
            } else {
                "Passwords stay encrypted with your master password.  Use .mpsites for the classic format.".into()
            },
            extensions: vec!["mpjson", "mpsites"],
            suggested_name: format!("{name} ({day}).mpjson"),
        })
    }

    fn export_to(&mut self, path: &Path) -> Vec<UiEffect> {
        let Some(mut flow) = self.export.take() else { return Vec::new() };
        let Some(user) = self.vm.user().cloned() else { return Vec::new() };
        let result = match (flow.reveal, flow.keys.as_mut()) {
            (true, Some(keys)) => write_export(path, &user, ExportMode::Revealed(keys)),
            (true, None) => Err("The master password was not confirmed.".into()),
            (false, _) => write_export(path, &user, ExportMode::Redacted),
        };
        drop(flow); // wipes the re-derived keys
        let file = path.file_name().map_or_else(String::new, |f| f.to_string_lossy().into_owned());
        match result {
            Ok(format) => {
                self.vm.set_notice(format!("Exported {} sites to {file} ({}).", user.sites().len(), format.name()));
                Vec::new()
            }
            Err(e) => vec![self.error_prompt("Export failed", e)],
        }
    }

    // ------------------------------------------------ change master password

    fn ask_change_password(&mut self) -> Vec<UiEffect> {
        let Some(name) = self.vm.unlocked_user().map(str::to_owned) else { return Vec::new() };
        let prompt = Prompt::new(
            Style::Critical,
            format!("Change {name}'s master password?"),
            format!(
                "EVERY generated password, login name and answer of {name} changes with the master password: \
                 you will have to change your password on every site.  Only do this if your master password \
                 was compromised.\n\nStored (personal) passwords are re-encrypted and kept.  Any key saved in \
                 the Keychain is removed.  All or nothing: if anything cannot be converted, nothing changes."
            ),
        )
        .field("Current master password", true)
        .field("New master password", true)
        .field("New master password again", true)
        .button("Cancel", ButtonRole::Cancel)
        .button("Change Master Password", ButtonRole::Destructive);
        vec![self.ask(prompt, Pending::ChangePassword)]
    }

    fn change_password_answered(&mut self, answer: PromptAnswer) -> Vec<UiEffect> {
        if answer.button != 1 {
            return Vec::new();
        }
        let Some(name) = self.vm.unlocked_user().map(str::to_owned) else { return Vec::new() };
        let (current, new, again) = (answer.value(0), answer.value(1), answer.value(2));
        let problem = if current.is_empty() || new.is_empty() {
            Some("Enter your current and your new master password.")
        } else if new != again {
            Some("The two new master passwords differ.")
        } else if new == current {
            Some("The new master password is the same as the current one.")
        } else {
            None
        };
        if let Some(problem) = problem {
            return vec![self.error_prompt("Master password not changed", problem)];
        }
        let flow = self.id();
        self.change_password = Some(ChangeFlow { id: flow, current: None, new: None });
        let (a, b) = (self.id(), self.id());
        vec![
            UiEffect::Derive(DeriveJob::new(
                a,
                DerivePurpose::Flow { flow, step: STEP_CHANGE_CURRENT },
                &name,
                Zeroizing::new(current.to_owned()),
            )),
            UiEffect::Derive(DeriveJob::new(
                b,
                DerivePurpose::Flow { flow, step: STEP_CHANGE_NEW },
                &name,
                Zeroizing::new(new.to_owned()),
            )),
        ]
    }

    fn change_password_derived(&mut self, flow_id: u64, step: u32, derived: Derived) -> Vec<UiEffect> {
        let Some(flow) = self.change_password.as_mut().filter(|f| f.id == flow_id) else { return Vec::new() };
        let keys = match derived.result {
            Ok(k) => k,
            Err(e) => {
                self.change_password = None;
                return vec![self.error_prompt("Master password not changed", capitalise(&e))];
            }
        };
        if step == STEP_CHANGE_CURRENT {
            flow.current = Some(keys);
        } else {
            flow.new = Some(keys);
        }
        if flow.current.is_none() || flow.new.is_none() {
            return Vec::new();
        }
        let flow = self.change_password.take().expect("checked above");
        let ((mut old, _), (mut new, new_icon)) = (flow.current.expect("set"), flow.new.expect("set"));
        let Some((user, _)) = self.vm.session_mut() else { return Vec::new() };
        let name = user.full_name().to_owned();
        // Check the current password against the key ID first.
        if let Err(e) = user.authenticate(&mut old) {
            let e = StoreError::from_model(e, &name);
            return vec![self.error_prompt("Master password not changed", e.to_string())];
        }
        if let Err(e) = user.change_master_password(&mut old, &mut new) {
            return vec![self.error_prompt("Master password not changed", capitalise(&e.to_string()))];
        }
        user.identicon = Some(new_icon);
        user.preferences.biometric_lock = false;
        let _ = self.vault.delete_all(&name);
        self.vm.replace_session_keys(new);
        self.vm.mark_dirty();
        self.vm.persist_now();
        self.vm.saver().flush();
        self.vm.refresh_users();
        vec![self.info(
            format!("{name}'s master password was changed"),
            "Every generated password is different now: update your password on each site (copy the new one \
             from here).  Saved Keychain keys were removed; turn Save Password on again if you want it.",
        )]
    }

    // ------------------------------------------------------- saved keys

    /// "Unlock with Touch ID" for the picked user.
    pub fn quick_unlock(&mut self) -> Vec<UiEffect> {
        let Some(entry) = self.vm.picked_entry() else { return Vec::new() };
        let name = entry.full_name.clone();
        if !entry.saved_keys {
            return Vec::new();
        }
        if let Err(why) = &self.quick_unlock {
            self.vm.set_error(format!("{why} Enter your master password instead."));
            return Vec::new();
        }
        let id = self.id();
        self.device_auth = Some((id, name.clone()));
        vec![UiEffect::DeviceAuth { id, reason: format!("unlock {name}'s saved Master Password key") }]
    }

    pub fn device_auth_finished(&mut self, id: u64, result: Result<(), String>, now: Instant) -> Vec<UiEffect> {
        self.last_activity = now;
        let Some((expected, name)) = self.device_auth.take() else { return Vec::new() };
        if expected != id {
            return Vec::new();
        }
        if let Err(e) = result {
            self.vm.set_error(format!("Not unlocked ({e}).  Enter your master password instead."));
            return Vec::new();
        }
        match self.vault.load_all(&name) {
            Ok(Some(keys)) => match self.vm.open_session(&name, keys, None) {
                Ok(()) => self.remember_unlocked_user(),
                Err(StoreError::WrongMasterPassword { .. }) => {
                    let _ = self.vault.delete_all(&name);
                    self.vm.set_error(
                        "The saved key no longer matches this user (was the master password changed?).  \
                         It was removed from the Keychain; enter your master password.",
                    );
                }
                Err(e) => self.vm.set_error(e.to_string()),
            },
            Ok(None) => self.vm.set_error("No saved key was found in the Keychain.  Enter your master password."),
            Err(e) => self.vm.set_error(format!("Could not read the Keychain: {e}")),
        }
        Vec::new()
    }

    fn toggle_save_password(&mut self) -> Vec<UiEffect> {
        if let Err(why) = &self.quick_unlock {
            let why = why.clone();
            return vec![self.error_prompt("Save Password is not available", why)];
        }
        let vault = &self.vault;
        let Some((user, keys)) = self.vm.session_mut() else { return Vec::new() };
        let name = user.full_name().to_owned();
        let enable = !user.preferences.biometric_lock;
        let result = if enable {
            vault.store_all(&name, keys).map(Some)
        } else {
            vault.delete_all(&name).map(|()| None)
        };
        match result {
            Ok(where_) => {
                user.preferences.biometric_lock = enable;
                self.vm.mark_dirty();
                self.vm.persist_now();
                self.vm.saver().flush();
                self.vm.refresh_users();
                self.vm.set_notice(match where_ {
                    Some(w) => format!("{name}'s derived keys are saved in the {w}; unlock with Touch ID or your Mac password."),
                    None => format!("{name}'s saved keys were removed from the Keychain."),
                });
                Vec::new()
            }
            Err(e) => vec![self.error_prompt("Keychain error", e)],
        }
    }

    // -------------------------------------------------------------- commands

    pub fn command(&mut self, command: MenuCommand, now: Instant) -> Vec<UiEffect> {
        self.last_activity = now;
        match command {
            MenuCommand::Open => vec![UiEffect::ShowSitesWindow],
            MenuCommand::Lock => {
                self.lock(LockReason::Command);
                Vec::new()
            }
            MenuCommand::Quit => self.quit(),
            MenuCommand::ToggleHidePasswords => {
                self.prefs.hide_passwords = !self.prefs.hide_passwords;
                self.vm.set_hide_passwords(self.prefs.hide_passwords);
                self.save_prefs();
                Vec::new()
            }
            MenuCommand::ToggleRememberPassword => {
                self.prefs.remember_password = !self.prefs.remember_password;
                self.save_prefs();
                Vec::new()
            }
            MenuCommand::ClipboardClear(seconds) => {
                self.prefs.clipboard_clear_seconds = seconds;
                self.clipboard.set_timeout(self.prefs.clipboard_timeout(), now);
                self.save_prefs();
                Vec::new()
            }
            MenuCommand::IdleLock(minutes) => {
                self.prefs.idle_lock_minutes = minutes;
                self.save_prefs();
                Vec::new()
            }
            MenuCommand::ToggleOpenAtLogin => match self.login_item {
                LoginItemState::Unavailable(_) => Vec::new(),
                LoginItemState::Disabled => vec![UiEffect::SetLoginItem(true)],
                LoginItemState::Enabled | LoginItemState::RequiresApproval => vec![UiEffect::SetLoginItem(false)],
            },
            MenuCommand::ShowWelcome => vec![UiEffect::ShowWelcome],
            MenuCommand::ChangeMasterPassword => self.ask_change_password(),
            MenuCommand::ToggleSavePassword => self.toggle_save_password(),
            MenuCommand::SelectUser(i) => {
                let name = self.vm.users().get(i as usize).map(|u| u.full_name.clone());
                if let Some(name) = name {
                    if self.vm.unlocked_user().is_some_and(|u| u != name) {
                        self.lock(LockReason::Command);
                    }
                    self.vm.pick_user(Some(&name));
                }
                vec![UiEffect::ShowSitesWindow]
            }
            MenuCommand::NewUser => {
                if self.vm.is_unlocked() {
                    self.lock(LockReason::Command);
                }
                self.vm.pick_user(None);
                vec![UiEffect::ShowSitesWindow]
            }
            MenuCommand::DeleteUser => {
                let Some(name) = self.vm.unlocked_user().or(self.vm.picked()).map(str::to_owned) else {
                    return Vec::new();
                };
                let sites = self.vm.users().iter().find(|u| u.full_name == name).map_or(0, |u| u.site_count);
                let prompt = Prompt::new(
                    Style::Critical,
                    format!("Delete {name}?"),
                    format!(
                        "This removes {name} and all {sites} site{} from this Mac, including stored passwords, \
                         login names, questions and any key saved in the Keychain.  Generated passwords can be \
                         recreated later with the same name and master password; stored ones cannot.  \
                         This cannot be undone.",
                        if sites == 1 { "" } else { "s" }
                    ),
                )
                .button("Cancel", ButtonRole::Cancel)
                .button(format!("Delete {name}"), ButtonRole::Destructive);
                vec![self.ask(prompt, Pending::DeleteUser(name))]
            }
            MenuCommand::ImportSites => {
                let id = self.id();
                self.files.insert(id, FilePending::Import);
                vec![UiEffect::ChooseFile(FileRequest {
                    id,
                    save: false,
                    title: "Import Sites".into(),
                    message: "Choose a Master Password export (.mpsites or .mpjson).".into(),
                    extensions: vec!["mpsites", "mpjson", "json", "txt"],
                    suggested_name: String::new(),
                })]
            }
            MenuCommand::ExportSecure => {
                let Some(name) = self.vm.unlocked_user().map(str::to_owned) else { return Vec::new() };
                let id = self.id();
                self.export = Some(ExportFlow { id, reveal: false, keys: None });
                vec![self.choose_export_file(&name, false)]
            }
            MenuCommand::ExportReveal => {
                let Some(name) = self.vm.unlocked_user().map(str::to_owned) else { return Vec::new() };
                let id = self.id();
                self.export = Some(ExportFlow { id, reveal: true, keys: None });
                let prompt = Prompt::new(
                    Style::Critical,
                    "Export passwords in clear text?",
                    format!(
                        "The file will contain {name}'s passwords, login names and answers in clear text. \
                         Anyone who gets the file gets your passwords.  Prefer the secure export unless you \
                         really need the plain values (device-private passwords are never exported)."
                    ),
                )
                .button("Cancel", ButtonRole::Cancel)
                .button("Export Passwords…", ButtonRole::Destructive);
                vec![self.ask(prompt, Pending::ExportWarning)]
            }
        }
    }

    /// The status menu, modelled on the original `MainMenu.xib`.
    pub fn menu(&self) -> Vec<MenuEntry> {
        let ctrl_cmd = Modifiers { command: true, control: true, option: false };
        let ctrl_opt_cmd = Modifiers { command: true, control: true, option: true };
        let unlocked = self.vm.unlocked_user();
        let lock = if unlocked.is_none() {
            MenuItem::new("Lock (Locked)", MenuCommand::Lock).enabled(false).tooltip("Master Password is currently locked.")
        } else {
            MenuItem::new("Lock", MenuCommand::Lock)
        };

        let mut user_items: Vec<MenuEntry> = self
            .vm
            .users()
            .iter()
            .enumerate()
            .map(|(i, u)| {
                let current = unlocked == Some(u.full_name.as_str())
                    || (unlocked.is_none() && self.vm.picked() == Some(u.full_name.as_str()));
                MenuItem::new(u.full_name.clone(), MenuCommand::SelectUser(i as u32)).checked(current).into()
            })
            .collect();
        if user_items.is_empty() {
            user_items.push(MenuItem::new("No Users Yet", MenuCommand::Open).enabled(false).into());
        }
        let users = MenuItem::submenu("Users", user_items);

        let delete_target = unlocked.or(self.vm.picked());
        let delete = match delete_target {
            Some(name) => MenuItem::new(format!("Delete “{name}”…"), MenuCommand::DeleteUser),
            None => MenuItem::new("Delete User…", MenuCommand::DeleteUser).enabled(false).tooltip("There is no user to delete."),
        };

        let (login_enabled, login_checked, login_tip) = match &self.login_item {
            LoginItemState::Unavailable(why) => (false, false, Some(why.clone())),
            LoginItemState::Disabled => (true, false, None),
            LoginItemState::Enabled => (true, true, None),
            LoginItemState::RequiresApproval => {
                (true, true, Some("Allow Master Password in System Settings ▸ General ▸ Login Items.".to_owned()))
            }
        };
        let mut open_at_login =
            MenuItem::new("Open at Login", MenuCommand::ToggleOpenAtLogin).enabled(login_enabled).checked(login_checked);
        open_at_login.tooltip = login_tip.or_else(|| Some("Open Master Password when you log in.".into()));

        let save_checked = self.vm.user().is_some_and(|u| u.preferences.biometric_lock);
        let save_password = match (&self.quick_unlock, unlocked) {
            (Err(why), _) => MenuItem::new("Save Password in Keychain", MenuCommand::ToggleSavePassword)
                .enabled(false)
                .tooltip(why.clone()),
            (Ok(()), None) => MenuItem::new("Save Password in Keychain", MenuCommand::ToggleSavePassword)
                .enabled(false)
                .checked(false)
                .tooltip("Unlock first."),
            (Ok(()), Some(name)) => MenuItem::new("Save Password in Keychain", MenuCommand::ToggleSavePassword)
                .checked(save_checked)
                .tooltip(format!(
                    "Keep {name}'s derived master keys (never the master password) in your login Keychain, \
                     so you can unlock with Touch ID or your Mac password.  The Touch ID check is enforced \
                     by this app, not by the Keychain hardware."
                )),
        };

        let clear_choices = CLIPBOARD_CLEAR_CHOICES
            .iter()
            .map(|&s| {
                let title = if s == 0 { "Never".to_owned() } else { plural(s, "second") };
                MenuItem::new(title, MenuCommand::ClipboardClear(s)).checked(self.prefs.clipboard_clear_seconds == s).into()
            })
            .collect();
        let idle_choices = IDLE_LOCK_CHOICES
            .iter()
            .map(|&m| {
                let title = if m == 0 { "Never".to_owned() } else { plural(m, "minute") };
                MenuItem::new(title, MenuCommand::IdleLock(m)).checked(self.prefs.idle_lock_minutes == m).into()
            })
            .collect();

        let preferences = MenuItem::submenu(
            "Preferences",
            vec![
                open_at_login.into(),
                MenuItem::new("Hide Passwords", MenuCommand::ToggleHidePasswords)
                    .checked(self.prefs.hide_passwords)
                    .tooltip("Don't display the password.  Hold ⌥ to reveal temporarily.")
                    .into(),
                MenuItem::new("Remember Password", MenuCommand::ToggleRememberPassword)
                    .checked(self.prefs.remember_password)
                    .tooltip("Stay unlocked after the window closes, until you lock, sleep or go idle.")
                    .into(),
                save_password.into(),
                MenuEntry::Separator,
                MenuItem::submenu("Clear Clipboard After", clear_choices).into(),
                MenuItem::submenu("Lock When Idle For", idle_choices).into(),
                MenuEntry::Separator,
                MenuItem::new("Show Welcome Window", MenuCommand::ShowWelcome).into(),
            ],
        );

        let export_tip = "Unlock the user to export first.";
        let mut export = MenuItem::submenu(
            "Export Sites",
            vec![
                MenuItem::new("Secure Export…", MenuCommand::ExportSecure)
                    .tooltip("Your passwords are not visible.")
                    .into(),
                MenuItem::new("Reveal Passwords…", MenuCommand::ExportReveal)
                    .tooltip("Keep this file secure or delete it when you're done with it!")
                    .into(),
            ],
        );
        if unlocked.is_none() {
            export = export.enabled(false).tooltip(export_tip);
        }

        let mut entries = vec![
            MenuItem::new("Open", MenuCommand::Open).key("p", ctrl_cmd).into(),
            lock.key("p", ctrl_opt_cmd).into(),
            MenuEntry::Separator,
            users.into(),
            MenuItem::new("New User…", MenuCommand::NewUser).into(),
            match unlocked {
                Some(_) => MenuItem::new("Change Master Password…", MenuCommand::ChangeMasterPassword),
                None => MenuItem::new("Change Master Password…", MenuCommand::ChangeMasterPassword)
                    .enabled(false)
                    .tooltip("Unlock the user first."),
            }
            .into(),
            delete.into(),
            MenuEntry::Separator,
            preferences.into(),
            export.into(),
            MenuItem::new("Import Sites…", MenuCommand::ImportSites).into(),
        ];
        if let Some(e) = &self.last_save_error {
            entries.push(MenuEntry::Separator);
            entries.push(MenuItem::new("⚠ Last save failed", MenuCommand::Open).tooltip(e.clone()).into());
        }
        entries.extend([
            MenuEntry::Separator,
            MenuItem::new("Quit Master Password", MenuCommand::Quit)
                .key("q", Modifiers { command: true, ..Default::default() })
                .into(),
        ]);
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::FakePasteboard;
    use crate::data::{MemoryStore, SaveQueue};
    use crate::keys::MemoryVault;
    use crate::menu::{find, find_title};
    use crate::prefs::MemoryPrefs;
    use crate::view_model::tests::{pw, run, NAME, PASSWORD, SITE, SITE_PASSWORD};
    use crate::view_model::CopyWhat;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct SharedPb(Rc<RefCell<FakePasteboard>>);
    impl Pasteboard for SharedPb {
        fn write_secret(&mut self, text: &str) -> Result<i64, String> {
            self.0.borrow_mut().write_secret(text)
        }
        fn change_count(&self) -> i64 {
            self.0.borrow().change_count()
        }
        fn clear(&mut self) {
            self.0.borrow_mut().clear()
        }
    }

    struct Rig {
        core: AppCore,
        pb: SharedPb,
        store: Arc<MemoryStore>,
        now: Instant,
    }

    fn rig_with(prefs: MemoryPrefs, store: Arc<MemoryStore>) -> Rig {
        let pb = SharedPb::default();
        let now = Instant::now();
        let vm = SitesViewModel::new(SaveQueue::inline(store.clone()));
        let core = AppCore::new(
            vm,
            Box::new(prefs),
            Box::new(pb.clone()),
            Box::new(MemoryVault::default()),
            Ok(()),
            LoginItemState::Unavailable("Run the bundled app.".into()),
            now,
        );
        Rig { core, pb, store, now }
    }

    fn rig(prefs: MemoryPrefs) -> Rig {
        rig_with(prefs, Arc::new(MemoryStore::new()))
    }

    fn remember() -> MemoryPrefs {
        let mut prefs = MemoryPrefs::default();
        prefs.set_bool(crate::prefs::KEY_REMEMBER_PASSWORD, true);
        prefs
    }

    /// Run effects that need no UI: derivations.  Returns the rest.
    fn settle(r: &mut Rig, effects: Vec<UiEffect>) -> Vec<UiEffect> {
        let mut out = Vec::new();
        for e in effects {
            match e {
                UiEffect::Derive(job) => {
                    let more = r.core.derive_finished(job.run(), r.now);
                    out.extend(settle(r, more));
                }
                other => out.push(other),
            }
        }
        out
    }

    fn create(r: &mut Rig, name: &str, password: &str) {
        let effects = r.core.vm_event(r.now, |vm| {
            vm.pick_user(None);
            vm.set_new_name(name);
            vm.set_new_password(pw(password));
            vm.set_new_confirm(pw(password));
            vm.submit_unlock()
        });
        settle(r, effects);
        assert!(r.core.vm().is_unlocked(), "{:?}", r.core.vm().error());
    }

    fn unlock(r: &mut Rig, name: &str, password: &str) {
        let effects = r.core.vm_event(r.now, |vm| {
            vm.pick_user(Some(name));
            vm.set_master_password(pw(password));
            vm.submit_unlock()
        });
        settle(r, effects);
    }

    fn copy_site(r: &mut Rig) -> Vec<UiEffect> {
        r.core.window_did_show(r.now);
        r.core.vm_event(r.now, |vm| {
            vm.set_site_query(SITE);
            vm.copy(CopyWhat::Current)
        })
    }

    fn take_prompt(effects: Vec<UiEffect>) -> Prompt {
        match effects.into_iter().find_map(|e| if let UiEffect::Prompt(p) = e { Some(p) } else { None }) {
            Some(p) => {
                assert!(p.is_well_formed(), "{p:?}");
                p
            }
            None => panic!("no prompt"),
        }
    }

    fn take_file(effects: Vec<UiEffect>) -> FileRequest {
        effects
            .into_iter()
            .find_map(|e| if let UiEffect::ChooseFile(f) = e { Some(f) } else { None })
            .expect("file request")
    }

    fn answer(r: &mut Rig, p: &Prompt, button: &str, values: &[&str]) -> Vec<UiEffect> {
        let i = p.button_index(button).unwrap_or_else(|| panic!("no button {button} in {p:?}"));
        let effects = r.core.prompt_answered(p.id, PromptAnswer::with_values(i, values), r.now);
        settle(r, effects)
    }

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("masterpwd-core-{}-{name}", std::process::id()))
    }

    #[test]
    fn welcome_shows_once() {
        let mut r = rig(MemoryPrefs::default());
        assert!(matches!(r.core.launched().as_slice(), [UiEffect::ShowWelcome]));
        assert!(r.core.launched().is_empty());
    }

    #[test]
    fn copy_closes_hides_and_window_close_locks_without_clearing() {
        let mut r = rig(MemoryPrefs::default());
        create(&mut r, NAME, PASSWORD);
        let effects = copy_site(&mut r);
        assert!(matches!(effects.as_slice(), [UiEffect::CloseSitesWindow, UiEffect::HideApp]), "{effects:?}");
        assert_eq!(r.pb.0.borrow().contents.as_deref(), Some(SITE_PASSWORD));
        r.core.window_did_close();
        assert!(!r.core.vm().is_unlocked());
        assert_eq!(r.pb.0.borrow().contents.as_deref(), Some(SITE_PASSWORD));
        r.core.tick(r.now + Duration::from_secs(61));
        assert_eq!(r.pb.0.borrow().contents, None);
        assert_eq!(r.core.prefs().last_full_name.as_deref(), Some(NAME));
        // The lock flushed the use to the store.
        assert_eq!(r.store.get(NAME).unwrap().site(SITE).unwrap().uses, 1);
    }

    #[test]
    fn lock_events_clear_clipboard_and_drop_the_session() {
        let mut r = rig(remember());
        create(&mut r, NAME, PASSWORD);
        for event in [SystemEvent::WillSleep, SystemEvent::ScreenLocked, SystemEvent::SessionResignedActive] {
            if !r.core.vm().is_unlocked() {
                unlock(&mut r, NAME, PASSWORD);
            }
            copy_site(&mut r);
            r.core.system_event(event);
            assert!(!r.core.vm().is_unlocked() && r.core.vm().user().is_none(), "{event:?}");
            assert_eq!(r.pb.0.borrow().contents, None, "{event:?}");
            r.core.window_did_close();
        }
    }

    #[test]
    fn idle_lock_and_debounced_save() {
        let mut r = rig(remember());
        create(&mut r, NAME, PASSWORD);
        r.core.vm_event(r.now, |vm| {
            vm.set_site_query("x.com");
            vm.set_counter(4);
            Vec::new()
        });
        assert!(r.store.get(NAME).unwrap().site("x.com").is_none(), "not saved yet");
        std::thread::sleep(crate::view_model::SAVE_DELAY);
        r.core.tick(Instant::now());
        assert_eq!(r.store.get(NAME).unwrap().site("x.com").unwrap().counter, 4, "saved after the pause");
        r.core.tick(r.now + Duration::from_secs(16 * 60));
        assert!(!r.core.vm().is_unlocked());
    }

    #[test]
    fn save_failures_are_visible() {
        let mut r = rig(remember());
        create(&mut r, NAME, PASSWORD);
        *r.store.fail_saves.lock().unwrap() = true;
        r.core.vm_event(r.now, |vm| {
            vm.set_site_query("x.com");
            vm.set_counter(2);
            Vec::new()
        });
        r.core.command(MenuCommand::Lock, r.now);
        r.core.tick(r.now);
        assert!(r.core.vm().error().unwrap().contains("Could not save"), "{:?}", r.core.vm().error());
        assert!(r.core.last_save_error().is_some());
        assert!(find_title(&r.core.menu(), "⚠ Last save failed").is_some());
    }

    #[test]
    fn quit_wipes_clipboard_and_keys() {
        let mut r = rig(remember());
        create(&mut r, NAME, PASSWORD);
        copy_site(&mut r);
        assert!(matches!(r.core.command(MenuCommand::Quit, r.now).as_slice(), [UiEffect::Terminate]));
        assert_eq!(r.pb.0.borrow().contents, None);
        assert!(!r.core.vm().is_unlocked());
    }

    #[test]
    fn menu_structure() {
        let mut r = rig(MemoryPrefs::default());
        let menu = r.core.menu();
        assert!(!find(&menu, MenuCommand::Lock).unwrap().enabled);
        assert!(find(&menu, MenuCommand::NewUser).unwrap().enabled);
        assert!(find(&menu, MenuCommand::ImportSites).unwrap().enabled);
        assert!(!find_title(&menu, "Export Sites").unwrap().enabled);
        assert!(!find(&menu, MenuCommand::DeleteUser).unwrap().enabled);
        create(&mut r, NAME, PASSWORD);
        let menu = r.core.menu();
        assert!(find(&menu, MenuCommand::Lock).unwrap().enabled);
        assert!(find_title(&menu, "Export Sites").unwrap().enabled);
        assert_eq!(find(&menu, MenuCommand::DeleteUser).unwrap().title, format!("Delete “{NAME}”…"));
        let user = find(&menu, MenuCommand::SelectUser(0)).unwrap();
        assert!(user.checked && user.title == NAME);
        assert!(find(&menu, MenuCommand::ToggleSavePassword).unwrap().enabled);
    }

    #[test]
    fn delete_user_confirms_with_a_non_default_destructive_button() {
        let mut r = rig(MemoryPrefs::default());
        create(&mut r, NAME, PASSWORD);
        let p = take_prompt(r.core.command(MenuCommand::DeleteUser, r.now));
        assert!(p.title.contains(NAME));
        assert_eq!(p.buttons[0].role, ButtonRole::Cancel);
        assert_eq!(p.buttons[1].role, ButtonRole::Destructive);
        answer(&mut r, &p, "Cancel", &[]);
        assert!(r.store.get(NAME).is_some());
        let p = take_prompt(r.core.command(MenuCommand::DeleteUser, r.now));
        answer(&mut r, &p, &format!("Delete {NAME}"), &[]);
        assert!(r.store.get(NAME).is_none());
        assert!(!r.core.vm().is_unlocked());
    }

    #[test]
    fn save_password_and_quick_unlock() {
        let mut r = rig(remember());
        create(&mut r, NAME, PASSWORD);
        r.core.command(MenuCommand::ToggleSavePassword, r.now);
        assert!(find(&r.core.menu(), MenuCommand::ToggleSavePassword).unwrap().checked);
        assert!(r.store.get(NAME).unwrap().preferences.biometric_lock);
        r.core.command(MenuCommand::Lock, r.now);
        assert!(r.core.vm().view().can_quick_unlock);

        // Device auth refused: nothing happens but a message.
        let effects = r.core.quick_unlock();
        let [UiEffect::DeviceAuth { id, .. }] = effects.as_slice() else { panic!("{effects:?}") };
        r.core.device_auth_finished(*id, Err("cancelled".into()), r.now);
        assert!(!r.core.vm().is_unlocked());

        // Granted: unlocked from the saved keys.
        let effects = r.core.quick_unlock();
        let [UiEffect::DeviceAuth { id, .. }] = effects.as_slice() else { panic!() };
        r.core.device_auth_finished(*id, Ok(()), r.now);
        assert!(r.core.vm().is_unlocked());

        // Turning it off purges the keys.
        r.core.command(MenuCommand::ToggleSavePassword, r.now);
        r.core.command(MenuCommand::Lock, r.now);
        assert!(!r.core.vm().view().can_quick_unlock);
    }

    #[test]
    fn quick_unlock_with_a_stale_key_purges_it() {
        let mut r = rig(remember());
        create(&mut r, NAME, PASSWORD);
        r.core.command(MenuCommand::ToggleSavePassword, r.now);
        r.core.command(MenuCommand::Lock, r.now);
        // Someone replaced the vault's keys with another password's.
        let (mut other, _) = crate::keys::derive_all(NAME, "other").unwrap();
        r.core.vault.store_all(NAME, &mut other).unwrap();
        let effects = r.core.quick_unlock();
        let [UiEffect::DeviceAuth { id, .. }] = effects.as_slice() else { panic!() };
        r.core.device_auth_finished(*id, Ok(()), r.now);
        assert!(!r.core.vm().is_unlocked());
        assert!(r.core.vm().error().unwrap().contains("no longer matches"));
        assert!(r.core.vault.load_all(NAME).unwrap().is_none());
    }

    #[test]
    fn quick_unlock_unavailable_falls_back() {
        let store = Arc::new(MemoryStore::new());
        let mut r = rig_with(remember(), store);
        r.core.quick_unlock = Err("Touch ID and a password are not set up.".into());
        create(&mut r, NAME, PASSWORD);
        let item = find(&r.core.menu(), MenuCommand::ToggleSavePassword).unwrap().clone();
        assert!(!item.enabled && item.tooltip.unwrap().contains("not set up"));
    }

    #[test]
    fn export_redacted_then_import_merge_and_new() {
        let mut r = rig(remember());
        create(&mut r, NAME, PASSWORD);
        copy_site(&mut r);
        r.core.vm_event(r.now, |vm| {
            vm.set_site_query("second.com");
            vm.copy(CopyWhat::Current)
        });
        // Export (secure).
        let req = take_file(r.core.command(MenuCommand::ExportSecure, r.now));
        assert!(req.save && req.suggested_name.ends_with(".mpjson"));
        let path = temp("export.mpjson");
        r.core.file_chosen(req.id, Some(path.clone()), r.now);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        // Delete a site, then merge the export back in.
        r.core.vm_event(r.now, |vm| {
            vm.set_site_query(SITE);
            vm.ask_delete_site()
        });
        let p = take_prompt(r.core.vm_event(r.now, |vm| vm.ask_delete_site()));
        answer(&mut r, &p, "Delete", &[]);
        assert!(r.core.vm().user().unwrap().site(SITE).is_none());

        let choice = take_prompt(r.core.import_path(&path));
        assert_eq!(choice.buttons[0].title, "Merge");
        assert_eq!(choice.buttons[2].role, ButtonRole::Destructive);
        let summary = take_prompt(answer(&mut r, &choice, "Merge", &[]));
        assert!(summary.message.contains(&format!("Added 1: {SITE}")), "{}", summary.message);
        assert!(r.core.vm().user().unwrap().site(SITE).is_some());

        // Import as a new user into a fresh store.
        let mut fresh = rig(MemoryPrefs::default());
        let p = take_prompt(fresh.core.import_path(&path));
        let wrong = take_prompt(answer(&mut fresh, &p, "Import", &["wrong"]));
        assert!(wrong.message.contains("does not match"), "{}", wrong.message);
        assert!(fresh.store.get(NAME).is_none());
        let p = take_prompt(fresh.core.import_path(&path));
        let done = take_prompt(answer(&mut fresh, &p, "Import", &[PASSWORD]));
        assert!(done.title.contains("Imported"));
        assert_eq!(fresh.store.get(NAME).unwrap().sites().len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn replace_requires_the_existing_password() {
        let mut r = rig(remember());
        create(&mut r, NAME, PASSWORD);
        copy_site(&mut r);
        let path = temp("replace.mpjson");
        let req = take_file(r.core.command(MenuCommand::ExportSecure, r.now));
        r.core.file_chosen(req.id, Some(path.clone()), r.now);
        r.core.vm_event(r.now, |vm| {
            vm.set_site_query("extra.com");
            vm.copy(CopyWhat::Current)
        });
        r.core.command(MenuCommand::Lock, r.now);

        let choice = take_prompt(r.core.import_path(&path));
        let ask = take_prompt(answer(&mut r, &choice, "Replace…", &[]));
        assert!(ask.title.contains("current master password"));
        let refused = take_prompt(answer(&mut r, &ask, "Continue", &["wrong"]));
        assert!(refused.message.contains("Incorrect master password"), "{}", refused.message);
        assert!(r.store.get(NAME).unwrap().site("extra.com").is_some(), "nothing replaced");

        let choice = take_prompt(r.core.import_path(&path));
        let ask = take_prompt(answer(&mut r, &choice, "Replace…", &[]));
        let done = take_prompt(answer(&mut r, &ask, "Continue", &[PASSWORD]));
        assert!(done.title.contains("Replaced"), "{done:?}");
        assert!(r.store.get(NAME).unwrap().site("extra.com").is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reveal_export_needs_warning_and_password() {
        let mut r = rig(remember());
        create(&mut r, NAME, PASSWORD);
        copy_site(&mut r);
        let warning = take_prompt(r.core.command(MenuCommand::ExportReveal, r.now));
        assert_eq!(warning.buttons[0].role, ButtonRole::Cancel);
        let ask = take_prompt(answer(&mut r, &warning, "Export Passwords…", &[]));
        let refused = take_prompt(answer(&mut r, &ask, "Continue", &["wrong"]));
        assert!(refused.title.contains("cancelled"));

        let warning = take_prompt(r.core.command(MenuCommand::ExportReveal, r.now));
        let ask = take_prompt(answer(&mut r, &warning, "Export Passwords…", &[]));
        let req = take_file(answer(&mut r, &ask, "Continue", &[PASSWORD]));
        let path = temp("reveal.mpsites");
        r.core.file_chosen(req.id, Some(path.clone()), r.now);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(SITE_PASSWORD), "clear-text export");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn lock_abandons_dialogs() {
        let mut r = rig(remember());
        create(&mut r, NAME, PASSWORD);
        let warning = take_prompt(r.core.command(MenuCommand::ExportReveal, r.now));
        r.core.command(MenuCommand::Lock, r.now);
        assert!(answer(&mut r, &warning, "Export Passwords…", &[]).is_empty());
    }

    #[test]
    fn unlock_with_a_wrong_password_is_rejected() {
        let mut r = rig(remember());
        create(&mut r, NAME, PASSWORD);
        r.core.command(MenuCommand::Lock, r.now);
        unlock(&mut r, NAME, "nope");
        assert!(!r.core.vm().is_unlocked());
        assert!(r.core.vm().error().unwrap().contains("Incorrect master password"));
        let _ = run(Vec::new());
    }

    #[test]
    fn change_master_password() {
        let mut r = rig(remember());
        create(&mut r, NAME, PASSWORD);
        copy_site(&mut r);
        r.core.vm_event(r.now, |vm| {
            vm.set_site_query("own.com");
            vm.choose_type(crate::view_model::TypeChoice::Password(mpw_core::ResultType::StatefulPersonal))
        });
        let p = take_prompt(r.core.vm_event(r.now, |vm| {
            vm.set_site_query("own.com");
            vm.choose_type(crate::view_model::TypeChoice::Password(mpw_core::ResultType::StatefulPersonal))
        }));
        answer(&mut r, &p, "Save", &["kept-secret"]);
        r.core.command(MenuCommand::ToggleSavePassword, r.now);

        let p = take_prompt(r.core.command(MenuCommand::ChangeMasterPassword, r.now));
        assert_eq!(p.buttons[0].role, ButtonRole::Cancel);
        assert!(p.message.contains("EVERY generated password"));
        let refused = take_prompt(answer(&mut r, &p, "Change Master Password", &[PASSWORD, "a", "b"]));
        assert!(refused.message.contains("differ"));
        let p = take_prompt(r.core.command(MenuCommand::ChangeMasterPassword, r.now));
        let wrong = take_prompt(answer(&mut r, &p, "Change Master Password", &["wrong", "new pw", "new pw"]));
        assert!(wrong.message.contains("Incorrect master password"), "{}", wrong.message);
        let p = take_prompt(r.core.command(MenuCommand::ChangeMasterPassword, r.now));
        let done = take_prompt(answer(&mut r, &p, "Change Master Password", &[PASSWORD, "new pw", "new pw"]));
        assert!(done.title.contains("was changed"), "{done:?}");
        assert!(r.core.vm().is_unlocked());
        assert_ne!(r.core.vm().result(), Some(SITE_PASSWORD));
        assert!(r.core.vault.load_all(NAME).unwrap().is_none(), "saved keys purged");

        r.core.command(MenuCommand::Lock, r.now);
        unlock(&mut r, NAME, PASSWORD);
        assert!(!r.core.vm().is_unlocked(), "the old password no longer works");
        unlock(&mut r, NAME, "new pw");
        assert!(r.core.vm().is_unlocked());
        r.core.vm_event(r.now, |vm| {
            vm.set_site_query("own.com");
            Vec::new()
        });
        assert_eq!(r.core.vm().result(), Some("kept-secret"), "stored password re-encrypted");
    }

    #[test]
    fn close_reasons_are_recorded() {
        let mut r = rig(MemoryPrefs::default());
        create(&mut r, NAME, PASSWORD);
        r.core.window_did_show(r.now);
        r.core.app_did_resign_active();
        assert_eq!(r.core.last_close_reason(), Some("keyboard focus moved to another app"));
    }

    #[test]
    fn lock_reasons() {
        assert!(!LockReason::WindowClosed.clears_clipboard());
        assert!(LockReason::Idle.clears_clipboard());
    }
}
