//! The whole app's behaviour, minus AppKit: lock policy, preferences, the
//! clipboard and the menu.  The platform layer owns one [`AppCore`], forwards
//! every event to it and carries out the returned [`UiEffect`]s.

use std::fmt;
use std::time::{Duration, Instant};

use crate::clipboard::{ClipboardGuard, Pasteboard};
use crate::data::DataStore;
use crate::menu::{MenuCommand, MenuEntry, MenuItem, Modifiers};
use crate::prefs::{Preferences, PrefsStore, CLIPBOARD_CLEAR_CHOICES, IDLE_LOCK_CHOICES};
use crate::view_model::{Mode, SitesViewModel, UnlockJob, UnlockOutcome, VmEffect};

/// What the platform layer must do.
pub enum UiEffect {
    ShowSitesWindow,
    CloseSitesWindow,
    /// Give focus back to the previous app (so the user can paste).
    HideApp,
    StartUnlock(UnlockJob),
    ScheduleIdenticon { generation: u64, delay: Duration },
    SetLoginItem(bool),
    ShowWelcome,
    Terminate,
}

impl fmt::Debug for UiEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShowSitesWindow => f.write_str("ShowSitesWindow"),
            Self::CloseSitesWindow => f.write_str("CloseSitesWindow"),
            Self::HideApp => f.write_str("HideApp"),
            Self::StartUnlock(j) => write!(f, "StartUnlock({j:?})"),
            Self::ScheduleIdenticon { generation, .. } => write!(f, "ScheduleIdenticon({generation})"),
            Self::SetLoginItem(on) => write!(f, "SetLoginItem({on})"),
            Self::ShowWelcome => f.write_str("ShowWelcome"),
            Self::Terminate => f.write_str("Terminate"),
        }
    }
}

/// Why the app locks.
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
    /// window-closed lock: that one follows a copy, and clearing there would
    /// make copying useless with "Remember Password" off.
    pub fn clears_clipboard(self) -> bool {
        self != Self::WindowClosed
    }
}

/// System events that lock the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemEvent {
    WillSleep,
    ScreensDidSleep,
    ScreenLocked,
    ScreensaverStarted,
    /// Fast user switching away from this session.
    SessionResignedActive,
}

/// State of the "Open at Login" registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginItemState {
    /// Not possible here (e.g. running unbundled); the reason is shown.
    Unavailable(String),
    Disabled,
    Enabled,
    /// Registered, but the user must approve it in System Settings.
    RequiresApproval,
}

pub struct AppCore<S: DataStore> {
    vm: SitesViewModel<S>,
    prefs: Preferences,
    prefs_store: Box<dyn PrefsStore>,
    pasteboard: Box<dyn Pasteboard>,
    clipboard: ClipboardGuard,
    last_activity: Instant,
    window_open: bool,
    login_item: LoginItemState,
}

fn plural(n: u32, unit: &str) -> String {
    if n == 1 { format!("1 {unit}") } else { format!("{n} {unit}s") }
}

impl<S: DataStore> AppCore<S> {
    pub fn new(
        store: S,
        prefs_store: Box<dyn PrefsStore>,
        pasteboard: Box<dyn Pasteboard>,
        login_item: LoginItemState,
        now: Instant,
    ) -> Self {
        let prefs = Preferences::load(prefs_store.as_ref());
        let mut vm = SitesViewModel::new(store);
        vm.set_hide_passwords(prefs.hide_passwords);
        if let Some(name) = &prefs.last_full_name {
            vm.set_full_name(name);
        }
        Self {
            vm,
            clipboard: ClipboardGuard::new(prefs.clipboard_timeout()),
            prefs,
            prefs_store,
            pasteboard,
            last_activity: now,
            window_open: false,
            login_item,
        }
    }

    pub fn vm(&self) -> &SitesViewModel<S> {
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

    fn save_prefs(&mut self) {
        self.prefs.save(self.prefs_store.as_mut());
    }

    /// Effects to run once the app finished launching.
    pub fn launched(&mut self) -> Vec<UiEffect> {
        if self.prefs.welcome_shown {
            return Vec::new();
        }
        self.prefs.welcome_shown = true;
        self.save_prefs();
        vec![UiEffect::ShowWelcome]
    }

    /// Forward a sites-window interaction to the view-model.
    pub fn vm_event(
        &mut self,
        now: Instant,
        f: impl FnOnce(&mut SitesViewModel<S>) -> Vec<VmEffect>,
    ) -> Vec<UiEffect> {
        self.last_activity = now;
        let effects = f(&mut self.vm);
        self.map_vm_effects(effects, now)
    }

    fn map_vm_effects(&mut self, effects: Vec<VmEffect>, now: Instant) -> Vec<UiEffect> {
        let mut out = Vec::new();
        for effect in effects {
            match effect {
                VmEffect::StartUnlock(job) => out.push(UiEffect::StartUnlock(job)),
                VmEffect::ScheduleIdenticon { generation, delay } => {
                    out.push(UiEffect::ScheduleIdenticon { generation, delay })
                }
                VmEffect::CloseWindow => out.push(UiEffect::CloseSitesWindow),
                VmEffect::Copy { text } => {
                    match self.clipboard.copy(self.pasteboard.as_mut(), &text, now) {
                        Ok(()) => out.extend([UiEffect::CloseSitesWindow, UiEffect::HideApp]),
                        Err(e) => self.vm.set_error(format!("Could not copy: {e}")),
                    }
                }
            }
        }
        out
    }

    pub fn unlock_finished(&mut self, outcome: UnlockOutcome, now: Instant) {
        self.last_activity = now;
        self.vm.unlock_finished(outcome);
        if self.vm.is_unlocked() {
            let name = self.vm.full_name().to_owned();
            if self.prefs.last_full_name.as_deref() != Some(name.as_str()) {
                self.prefs.last_full_name = Some(name);
                self.save_prefs();
            }
        }
    }

    pub fn lock(&mut self, reason: LockReason) {
        self.vm.lock();
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
        if !self.prefs.remember_password {
            self.lock(LockReason::WindowClosed);
        }
    }

    pub fn is_window_open(&self) -> bool {
        self.window_open
    }

    /// The app lost focus: dismiss the sites window, as the original did.
    pub fn app_did_resign_active(&mut self) -> Vec<UiEffect> {
        if self.window_open {
            vec![UiEffect::CloseSitesWindow]
        } else {
            Vec::new()
        }
    }

    pub fn system_event(&mut self, event: SystemEvent) -> Vec<UiEffect> {
        let reason = match event {
            SystemEvent::WillSleep | SystemEvent::ScreensDidSleep => LockReason::Sleep,
            SystemEvent::ScreenLocked | SystemEvent::ScreensaverStarted => LockReason::ScreenLocked,
            SystemEvent::SessionResignedActive => LockReason::SessionSwitched,
        };
        self.lock(reason);
        if self.window_open {
            vec![UiEffect::CloseSitesWindow]
        } else {
            Vec::new()
        }
    }

    /// Call about once a second: clipboard timeout and idle lock.
    pub fn tick(&mut self, now: Instant) {
        self.clipboard.tick(self.pasteboard.as_mut(), now);
        if let Some(idle) = self.prefs.idle_timeout() {
            if self.vm.mode() != Mode::Locked && now.saturating_duration_since(self.last_activity) >= idle {
                self.lock(LockReason::Idle);
            }
        }
    }

    /// The global "lock" hotkey (⌃⌥⌘P).
    pub fn lock_hotkey(&mut self) -> Vec<UiEffect> {
        self.lock(LockReason::Hotkey);
        Vec::new()
    }

    /// Quit: wipe our clipboard secret and keys, persist, terminate.
    pub fn quit(&mut self) -> Vec<UiEffect> {
        self.lock(LockReason::Quit);
        if let Err(e) = self.vm.store_mut().persist() {
            // Not fatal; nothing secret in the message.
            eprintln!("MasterPwd: could not save on quit: {e}");
        }
        self.save_prefs();
        vec![UiEffect::Terminate]
    }

    pub fn command(&mut self, command: MenuCommand, now: Instant) -> Vec<UiEffect> {
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
                self.last_activity = now;
                self.save_prefs();
                Vec::new()
            }
            MenuCommand::ToggleOpenAtLogin => match self.login_item {
                LoginItemState::Unavailable(_) => Vec::new(),
                LoginItemState::Disabled => vec![UiEffect::SetLoginItem(true)],
                LoginItemState::Enabled | LoginItemState::RequiresApproval => {
                    vec![UiEffect::SetLoginItem(false)]
                }
            },
            MenuCommand::ShowWelcome => vec![UiEffect::ShowWelcome],
            // Next round (need mpw-model / keychain integration).
            MenuCommand::ToggleSavePassword
            | MenuCommand::NewUser
            | MenuCommand::DeleteUser
            | MenuCommand::ImportSites
            | MenuCommand::ExportSecure
            | MenuCommand::ExportReveal => Vec::new(),
        }
    }

    /// The status menu, modelled on the original `MainMenu.xib`.
    pub fn menu(&self) -> Vec<MenuEntry> {
        let ctrl_cmd = Modifiers { command: true, control: true, option: false };
        let ctrl_opt_cmd = Modifiers { command: true, control: true, option: true };
        let locked = self.vm.mode() == Mode::Locked;
        let lock = if locked {
            MenuItem::new("Lock (Locked)", MenuCommand::Lock)
                .enabled(false)
                .tooltip("Master Password is currently locked.")
        } else {
            MenuItem::new("Lock", MenuCommand::Lock)
        };

        let users = MenuItem::submenu(
            "Users",
            self.vm
                .store()
                .users()
                .into_iter()
                .map(|u| {
                    let current = self.vm.unlocked_user() == Some(&u.id);
                    MenuItem::new(u.full_name, MenuCommand::Open).checked(current).later().into()
                })
                .collect::<Vec<_>>(),
        )
        .later();

        let (login_enabled, login_checked, login_tip) = match &self.login_item {
            LoginItemState::Unavailable(why) => (false, false, Some(why.clone())),
            LoginItemState::Disabled => (true, false, None),
            LoginItemState::Enabled => (true, true, None),
            LoginItemState::RequiresApproval => (
                true,
                true,
                Some("Allow Master Password in System Settings ▸ General ▸ Login Items.".to_owned()),
            ),
        };
        let mut open_at_login = MenuItem::new("Open at Login", MenuCommand::ToggleOpenAtLogin)
            .enabled(login_enabled)
            .checked(login_checked);
        open_at_login.tooltip = login_tip.or_else(|| Some("Open Master Password when you log in.".into()));

        let clear_choices = CLIPBOARD_CLEAR_CHOICES
            .iter()
            .map(|&s| {
                let title = if s == 0 { "Never".to_owned() } else { plural(s, "second") };
                MenuItem::new(title, MenuCommand::ClipboardClear(s))
                    .checked(self.prefs.clipboard_clear_seconds == s)
                    .into()
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
                MenuItem::new("Save Password in Keychain", MenuCommand::ToggleSavePassword).later().into(),
                MenuEntry::Separator,
                MenuItem::submenu("Clear Clipboard After", clear_choices).into(),
                MenuItem::submenu("Lock When Idle For", idle_choices).into(),
                MenuEntry::Separator,
                MenuItem::new("Show Welcome Window", MenuCommand::ShowWelcome).into(),
            ],
        );

        vec![
            MenuItem::new("Open", MenuCommand::Open).key("p", ctrl_cmd).into(),
            lock.key("p", ctrl_opt_cmd).into(),
            MenuEntry::Separator,
            users.into(),
            MenuItem::new("New User…", MenuCommand::NewUser).later().into(),
            MenuItem::new("Delete User…", MenuCommand::DeleteUser).later().into(),
            MenuEntry::Separator,
            preferences.into(),
            MenuItem::submenu(
                "Export Sites",
                vec![
                    MenuItem::new("Secure Export…", MenuCommand::ExportSecure).later().into(),
                    MenuItem::new("Reveal Passwords…", MenuCommand::ExportReveal).later().into(),
                ],
            )
            .later()
            .into(),
            MenuItem::new("Import Sites…", MenuCommand::ImportSites).later().into(),
            MenuEntry::Separator,
            MenuItem::new("Quit Master Password", MenuCommand::Quit).key("q", Modifiers { command: true, ..Default::default() }).into(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::FakePasteboard;
    use crate::data::MemoryStore;
    use crate::menu::{find, find_title};
    use crate::prefs::MemoryPrefs;
    use crate::view_model::tests::{NAME, PASSWORD, SITE, SITE_PASSWORD};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A pasteboard the test can inspect after handing it to the core.
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

    fn core(prefs: MemoryPrefs) -> (AppCore<MemoryStore>, SharedPb, Instant) {
        let pb = SharedPb::default();
        let now = Instant::now();
        let core = AppCore::new(
            MemoryStore::new(),
            Box::new(prefs),
            Box::new(pb.clone()),
            LoginItemState::Unavailable("Run the bundled app.".into()),
            now,
        );
        (core, pb, now)
    }

    fn unlock_core(core: &mut AppCore<MemoryStore>, now: Instant) {
        let mut effects = core.vm_event(now, |vm| {
            vm.set_full_name(NAME);
            vm.set_master_password(mpw_core::Zeroizing::new(PASSWORD.to_owned()));
            vm.submit_unlock()
        });
        let Some(UiEffect::StartUnlock(job)) = effects.pop() else { panic!("{effects:?}") };
        core.unlock_finished(job.run(), now);
        assert!(core.vm().is_unlocked());
    }

    fn copy_site(core: &mut AppCore<MemoryStore>, now: Instant) -> Vec<UiEffect> {
        core.window_did_show(now);
        core.vm_event(now, |vm| {
            vm.set_site_query(SITE);
            vm.copy()
        })
    }

    #[test]
    fn welcome_shows_once() {
        let (mut core, _, _) = core(MemoryPrefs::default());
        assert!(matches!(core.launched().as_slice(), [UiEffect::ShowWelcome]));
        assert!(core.launched().is_empty());
        assert!(core.prefs().welcome_shown);
    }

    #[test]
    fn copy_closes_hides_and_window_close_locks_without_clearing() {
        let (mut core, pb, now) = core(MemoryPrefs::default());
        unlock_core(&mut core, now);
        let effects = copy_site(&mut core, now);
        assert!(matches!(effects.as_slice(), [UiEffect::CloseSitesWindow, UiEffect::HideApp]), "{effects:?}");
        assert_eq!(pb.0.borrow().contents.as_deref(), Some(SITE_PASSWORD));
        // Remember Password is off: closing locks, but keeps the clipboard.
        core.window_did_close();
        assert!(!core.vm().is_unlocked());
        assert_eq!(pb.0.borrow().contents.as_deref(), Some(SITE_PASSWORD));
        // ... until the timeout.
        core.tick(now + Duration::from_secs(61));
        assert_eq!(pb.0.borrow().contents, None);
        // The name is remembered for next time.
        assert_eq!(core.prefs().last_full_name.as_deref(), Some(NAME));
    }

    #[test]
    fn remember_password_keeps_the_key_until_a_lock_event() {
        let mut prefs = MemoryPrefs::default();
        prefs.set_bool(crate::prefs::KEY_REMEMBER_PASSWORD, true);
        let (mut core, pb, now) = core(prefs);
        unlock_core(&mut core, now);
        copy_site(&mut core, now);
        core.window_did_close();
        assert!(core.vm().is_unlocked());
        for event in [SystemEvent::WillSleep, SystemEvent::ScreenLocked, SystemEvent::SessionResignedActive] {
            if !core.vm().is_unlocked() {
                unlock_core(&mut core, now);
            }
            copy_site(&mut core, now);
            let effects = core.system_event(event);
            assert!(!core.vm().is_unlocked(), "{event:?}");
            assert!(matches!(effects.as_slice(), [UiEffect::CloseSitesWindow]));
            assert_eq!(pb.0.borrow().contents, None, "{event:?} clears our clipboard");
            core.window_did_close();
        }
    }

    #[test]
    fn lock_clears_only_our_clipboard() {
        let mut prefs = MemoryPrefs::default();
        prefs.set_bool(crate::prefs::KEY_REMEMBER_PASSWORD, true);
        let (mut core, pb, now) = core(prefs);
        unlock_core(&mut core, now);
        copy_site(&mut core, now);
        pb.0.borrow_mut().external_copy("mine");
        core.command(MenuCommand::Lock, now);
        assert_eq!(pb.0.borrow().contents.as_deref(), Some("mine"));
    }

    #[test]
    fn idle_lock() {
        let mut prefs = MemoryPrefs::default();
        prefs.set_bool(crate::prefs::KEY_REMEMBER_PASSWORD, true);
        let (mut core, _, now) = core(prefs);
        unlock_core(&mut core, now);
        core.tick(now + Duration::from_secs(14 * 60));
        assert!(core.vm().is_unlocked());
        // Activity resets the timer.
        core.vm_event(now + Duration::from_secs(14 * 60), |_| Vec::new());
        core.tick(now + Duration::from_secs(28 * 60));
        assert!(core.vm().is_unlocked());
        core.tick(now + Duration::from_secs(29 * 60));
        assert!(!core.vm().is_unlocked());
        // Never.
        unlock_core(&mut core, now);
        core.command(MenuCommand::IdleLock(0), now);
        core.tick(now + Duration::from_secs(1_000_000));
        assert!(core.vm().is_unlocked());
    }

    #[test]
    fn quit_wipes_clipboard_and_keys() {
        let mut prefs = MemoryPrefs::default();
        prefs.set_bool(crate::prefs::KEY_REMEMBER_PASSWORD, true);
        let (mut core, pb, now) = core(prefs);
        unlock_core(&mut core, now);
        copy_site(&mut core, now);
        assert!(core.clipboard_holds_secret());
        assert!(matches!(core.command(MenuCommand::Quit, now).as_slice(), [UiEffect::Terminate]));
        assert_eq!(pb.0.borrow().contents, None);
        assert!(!core.vm().is_unlocked());
    }

    #[test]
    fn preferences_toggle_and_persist() {
        let (mut core, _, now) = core(MemoryPrefs::default());
        core.command(MenuCommand::ToggleHidePasswords, now);
        core.command(MenuCommand::ClipboardClear(15), now);
        assert!(core.prefs().hide_passwords);
        assert_eq!(core.prefs().clipboard_timeout(), Some(Duration::from_secs(15)));
        let menu = core.menu();
        assert!(find(&menu, MenuCommand::ToggleHidePasswords).unwrap().checked);
        assert!(find(&menu, MenuCommand::ClipboardClear(15)).unwrap().checked);
        assert!(!find(&menu, MenuCommand::ClipboardClear(60)).unwrap().checked);
    }

    #[test]
    fn menu_structure_matches_the_original() {
        let (mut core, _, now) = core(MemoryPrefs::default());
        let menu = core.menu();
        let open = find(&menu, MenuCommand::Open).unwrap();
        assert_eq!((open.key, open.modifiers.control, open.modifiers.command), ("p", true, true));
        assert!(!find(&menu, MenuCommand::Lock).unwrap().enabled, "locked at launch");
        for later in [
            MenuCommand::NewUser,
            MenuCommand::DeleteUser,
            MenuCommand::ImportSites,
            MenuCommand::ExportSecure,
            MenuCommand::ExportReveal,
            MenuCommand::ToggleSavePassword,
        ] {
            assert!(!find(&menu, later).unwrap().enabled, "{later:?} should be disabled");
        }
        assert!(!find_title(&menu, "Users").unwrap().enabled);
        assert!(!find_title(&menu, "Export Sites").unwrap().enabled);
        let login = find(&menu, MenuCommand::ToggleOpenAtLogin).unwrap();
        assert!(!login.enabled);
        assert_eq!(login.tooltip.as_deref(), Some("Run the bundled app."));
        assert!(core.command(MenuCommand::ToggleOpenAtLogin, now).is_empty());

        core.set_login_item(LoginItemState::Disabled);
        assert!(matches!(core.command(MenuCommand::ToggleOpenAtLogin, now).as_slice(), [UiEffect::SetLoginItem(true)]));
        unlock_core(&mut core, now);
        assert!(find(&core.menu(), MenuCommand::Lock).unwrap().enabled);
    }

    #[test]
    fn resign_active_closes_an_open_window_only() {
        let (mut core, _, now) = core(MemoryPrefs::default());
        assert!(core.app_did_resign_active().is_empty());
        core.window_did_show(now);
        assert!(matches!(core.app_did_resign_active().as_slice(), [UiEffect::CloseSitesWindow]));
    }

    #[test]
    fn failed_copy_surfaces_in_the_window() {
        let (mut core, pb, now) = core(MemoryPrefs::default());
        pb.0.borrow_mut().fail = true;
        unlock_core(&mut core, now);
        assert!(copy_site(&mut core, now).is_empty());
        assert!(core.vm().error().unwrap().starts_with("Could not copy"));
    }

    #[test]
    fn lock_reasons() {
        assert!(!LockReason::WindowClosed.clears_clipboard());
        for r in [LockReason::Command, LockReason::Sleep, LockReason::Idle, LockReason::Quit, LockReason::SessionSwitched] {
            assert!(r.clears_clipboard());
        }
    }
}
