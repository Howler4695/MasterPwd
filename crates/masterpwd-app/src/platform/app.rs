//! The application delegate and the event loop glue.
//!
//! All state lives in one main-thread-only [`State`] holding the [`AppCore`].
//! Every AppKit callback becomes a call to [`dispatch`], which borrows the
//! core, runs it, *releases the borrow*, then carries out the returned
//! [`UiEffect`]s and re-renders.  Effects may re-enter `dispatch` (closing a
//! window fires `windowWillClose:`, a modal dialog runs a nested run loop),
//! which is why the borrow is never held while talking to AppKit.

use std::cell::{Cell, OnceCell, RefCell};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mpw_core::Zeroizing;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject, Sel};
use objc2::{define_class, msg_send, sel, MainThreadMarker, MainThreadOnly, Message};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSApplicationDelegate, NSControl, NSControlTextEditingDelegate,
    NSMenu, NSMenuDelegate, NSMenuItem, NSTableColumn, NSTableView, NSTableViewDataSource, NSTableViewDelegate,
    NSTextFieldDelegate, NSTextView, NSView, NSWindowDelegate,
};
use objc2_foundation::{NSArray, NSNotification, NSObject, NSObjectProtocol, NSURL};

use super::hotkey::{self, HotKey, HotKeys};
use super::keychain::Keychain;
use super::local_auth::{DeviceAuthenticator, LocalAuth, StubAuth};
use super::pasteboard::SystemPasteboard;
use super::sites_window::{self as sw, Delegates, SitesWindow};
use super::status_item::StatusItem;
use super::welcome_window::{self as ww, WelcomeWindow};
use super::{defaults::UserDefaults, dialogs, login_item, smoke, system_events};
use crate::core::{AppCore, LoginItemState, SystemEvent, UiEffect};
use crate::data::{DataStore, DiskStore, SaveQueue};
use crate::keys::{KeyVault, MemoryVault};
use crate::menu::MenuCommand;
use crate::prefs::{MemoryPrefs, PrefsStore};
use crate::view_model::{CopyWhat, Screen, SitesViewModel};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchMode {
    Normal,
    /// Open the sites window right away (review/debug aid).
    Show,
    /// Build everything, drive the core flows, exit 0 / non-zero.
    SmokeTest,
}

pub type Core = AppCore;

pub(super) struct State {
    pub core: Core,
    pub hotkeys: Option<HotKeys>,
    pub hotkey_errors: Vec<String>,
}

pub(super) struct Ui {
    pub delegate: Retained<AppDelegate>,
    pub status: StatusItem,
    pub sites: SitesWindow,
    pub welcome: WelcomeWindow,
    pub smoke_pasteboard: Option<SystemPasteboard>,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    static UI: OnceCell<Ui> = const { OnceCell::new() };
    static MODE: Cell<LaunchMode> = const { Cell::new(LaunchMode::Normal) };
    static AUTH: RefCell<Option<Box<dyn DeviceAuthenticator>>> = const { RefCell::new(None) };
    /// Files opened (Finder) before launch finished.
    static PENDING_OPEN: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
    /// Our status menu is open (it takes the keyboard from the panel).
    static MENU_OPEN: Cell<bool> = const { Cell::new(false) };
}

pub const SMOKE_DEFAULTS_SUITE: &str = "com.github.howler4695.masterpwd.smoke-test";

fn guard(what: &str, f: impl FnOnce()) {
    if std::panic::catch_unwind(AssertUnwindSafe(f)).is_err() {
        eprintln!("MasterPwd: internal error in {what} (recovered)");
    }
}

pub(super) fn mode() -> LaunchMode {
    MODE.with(Cell::get)
}

pub(super) fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> Option<R> {
    STATE.with(|s| match s.try_borrow_mut() {
        Ok(mut s) => s.as_mut().map(f),
        Err(_) => {
            eprintln!("MasterPwd: re-entrant state access ignored");
            None
        }
    })
}

pub(super) fn with_core<R>(f: impl FnOnce(&mut Core) -> R) -> Option<R> {
    with_state(|s| f(&mut s.core))
}

pub(super) fn with_ui<R>(f: impl FnOnce(&Ui) -> R) -> Option<R> {
    UI.with(|ui| ui.get().map(f))
}

/// Run a core operation, then its effects, then re-render.
pub(super) fn dispatch(f: impl FnOnce(&mut Core, Instant) -> Vec<UiEffect>) {
    let effects = with_core(|c| f(c, Instant::now())).unwrap_or_default();
    run_effects(effects);
    render();
}

pub(super) fn render() {
    let Some((view, screen, login)) = with_core(|c| (c.vm().view(), c.vm().screen(), c.login_item().clone())) else {
        return;
    };
    with_ui(|ui| {
        ui.sites.render(&view);
        ui.status.set_locked(screen != Screen::Unlocked);
        ui.welcome.render(&login);
    });
    update_focus_state();
}

/// Secure Event Input and the debug state file follow the keyboard focus.
pub(super) fn update_focus_state() {
    let Some(mtm) = MainThreadMarker::new() else { return };
    let Some((visible, key, sheet_key, first_responder)) = with_ui(|ui| {
        let sheet_key = ui.sites.sheet().is_some_and(|s| s.isKeyWindow());
        (ui.sites.is_visible(), ui.sites.is_key(), sheet_key, ui.sites.first_responder_class())
    }) else {
        return;
    };
    let core_state = with_core(|c| {
        let v = c.vm().view();
        (
            c.vm().screen(),
            v.picked_name.clone(),
            v.users.len(),
            v.selection.and_then(|i| v.candidates.get(i)).map(|c| c.name.clone()).unwrap_or_default(),
            v.result_display.chars().count(),
            v.result_masked,
            v.error.clone().unwrap_or_default(),
            c.last_close_reason().unwrap_or("").to_owned(),
            c.is_busy(),
        )
    });
    let Some((screen, picked, users, site, result_len, masked, error, close_reason, busy)) = core_state else {
        return;
    };
    let password_screen = matches!(screen, Screen::Pick | Screen::NewUser | Screen::Unlocking);
    super::secure_input::set(visible && ((key && password_screen) || sheet_key));
    if !super::debug_state::enabled() {
        return;
    }
    let app = NSApplication::sharedApplication(mtm);
    let app_key = app.keyWindow().map(|w| w.title().to_string()).unwrap_or_else(|| "none".into());
    let frontmost = objc2_app_kit::NSWorkspace::sharedWorkspace()
        .frontmostApplication()
        .and_then(|a| a.localizedName())
        .map(|n| n.to_string())
        .unwrap_or_default();
    super::debug_state::write(&[
        ("window_visible", visible.to_string()),
        ("window_is_key", key.to_string()),
        ("sheet_is_key", sheet_key.to_string()),
        ("app_key_window", app_key),
        ("first_responder", first_responder),
        ("app_active", app.isActive().to_string()),
        ("frontmost_app", frontmost),
        ("secure_input_ours", super::secure_input::ours().to_string()),
        ("secure_input_system", super::secure_input::system().to_string()),
        ("screen", format!("{screen:?}")),
        ("picked_user", picked),
        ("users", users.to_string()),
        ("selected_site", site),
        ("result_len", result_len.to_string()),
        ("result_masked", masked.to_string()),
        ("dialog_pending", busy.to_string()),
        ("error", error),
        ("last_close_reason", close_reason),
        ("menu_open", MENU_OPEN.with(Cell::get).to_string()),
    ]);
}

/// The sites panel lost the keyboard.  If it went to another app (and not to
/// one of our dialogs), dismiss the window like the original did when the app
/// was deactivated.
fn focus_check() {
    let Some(mtm) = MainThreadMarker::new() else { return };
    let ours_still = NSApplication::sharedApplication(mtm).keyWindow().is_some();
    let (visible, key, sheet) = with_ui(|ui| (ui.sites.is_visible(), ui.sites.is_key(), ui.sites.sheet().is_some()))
        .unwrap_or((false, true, false));
    let busy = with_core(|c| c.is_busy()).unwrap_or(true);
    let menu_open = MENU_OPEN.with(Cell::get);
    if visible && !key && !sheet && !ours_still && !busy && !menu_open {
        dispatch(|c, _| c.app_did_resign_active());
    }
    update_focus_state();
}

use super::runloop::{after, main_async};

fn run_effects(effects: Vec<UiEffect>) {
    for effect in effects {
        run_effect(effect);
    }
}

fn run_effect(effect: UiEffect) {
    let Some(mtm) = MainThreadMarker::new() else { return };
    match effect {
        UiEffect::ShowSitesWindow => {
            let was_visible = with_ui(|ui| ui.sites.is_visible()).unwrap_or(true);
            if !was_visible {
                with_core(|c| c.window_did_show(Instant::now()));
                render();
            }
            with_ui(|ui| ui.sites.show());
        }
        UiEffect::CloseSitesWindow => {
            with_ui(|ui| ui.sites.close());
            // If the app did get activated (e.g. opened from Finder), give
            // the keyboard back to the previous app.
            let app = NSApplication::sharedApplication(mtm);
            if app.isActive() && !with_ui(|ui| ui.welcome.is_visible()).unwrap_or(false) {
                app.hide(None);
            }
        }
        UiEffect::HideApp => NSApplication::sharedApplication(mtm).hide(None),
        UiEffect::Derive(job) => {
            // scrypt runs here, never on the main thread.
            let spawned = std::thread::Builder::new().name("mpw-derive".into()).spawn(move || {
                let derived = job.run();
                main_async(move || guard("derive", || dispatch(|c, now| c.derive_finished(derived, now))));
            });
            if spawned.is_err() {
                with_core(|c| c.lock(crate::core::LockReason::Command));
                eprintln!("MasterPwd: could not start the key derivation thread");
            }
        }
        UiEffect::ScheduleIdenticon { generation, delay } => after(delay, move || {
            guard("identicon", || {
                dispatch(|c, now| {
                    c.vm_event(now, |vm| {
                        vm.identicon_due(generation);
                        Vec::new()
                    })
                })
            })
        }),
        UiEffect::SetLoginItem(on) => {
            let (state, error) = login_item::set_enabled(on);
            let needs_approval = state == LoginItemState::RequiresApproval;
            with_core(|c| c.set_login_item(state));
            if let Some(error) = error {
                let p = crate::prompt::Prompt::info("Could not change Open at Login", error);
                dialogs::run_prompt(mtm, &p, None, None);
            } else if on && needs_approval {
                login_item::open_settings();
            }
        }
        UiEffect::ShowWelcome => {
            render();
            with_ui(|ui| ui.welcome.show());
        }
        UiEffect::Terminate => NSApplication::sharedApplication(mtm).terminate(None),
        UiEffect::Prompt(prompt) => {
            let answer = if mode() == LaunchMode::SmokeTest {
                smoke::scripted_prompt(mtm, &prompt)
            } else {
                // A sheet on the (key, non-activating) sites panel.
                let parent = sites_panel_for_sheet();
                dialogs::run_prompt(mtm, &prompt, parent.as_deref(), None)
            };
            let id = prompt.id;
            dispatch(|c, now| c.prompt_answered(id, answer, now));
        }
        UiEffect::ChooseFile(request) => {
            let path = if mode() == LaunchMode::SmokeTest {
                smoke::scripted_file(&request)
            } else {
                let parent = sites_panel_for_sheet();
                dialogs::run_file_panel(mtm, &request, parent.as_deref())
            };
            let id = request.id;
            dispatch(|c, now| c.file_chosen(id, path, now));
        }
        UiEffect::Work(work) => {
            // Card unwraps (PIN prompt) and scrypt-heavy re-keying run here.
            let id = work.id;
            let task = work.task;
            let spawned = std::thread::Builder::new().name("mpw-work".into()).spawn(move || {
                let output = task();
                main_async(move || guard("work", || dispatch(|c, now| c.work_finished(id, output, now))));
            });
            if spawned.is_err() {
                eprintln!("MasterPwd: could not start a worker thread");
            }
        }
        UiEffect::DeviceAuth { id, reason } => {
            let done: super::local_auth::Done = Box::new(move |result| {
                main_async(move || guard("device auth", || dispatch(|c, now| c.device_auth_finished(id, result, now))));
            });
            AUTH.with(|a| match a.borrow().as_ref() {
                Some(auth) => auth.authenticate(&reason, done),
                None => done(Err("unavailable".into())),
            });
        }
    }
}

/// Show the sites panel (if needed) and return it as the parent for a sheet;
/// `None` if a sheet is already attached.
pub(super) fn sites_panel_for_sheet() -> Option<Retained<objc2_app_kit::NSWindow>> {
    let visible = with_ui(|ui| ui.sites.is_visible()).unwrap_or(false);
    if !visible {
        run_effect(UiEffect::ShowSitesWindow);
    }
    with_ui(|ui| {
        if ui.sites.sheet().is_some() {
            None
        } else {
            let window: &objc2_app_kit::NSWindow = &ui.sites.window;
            Some(window.retain())
        }
    })
    .flatten()
}

pub(super) fn rebuild_menu() {
    let state = login_item::state();
    let Some(entries) = with_core(|c| {
        c.set_login_item(state);
        c.menu()
    }) else {
        return;
    };
    with_ui(|ui| ui.status.rebuild(&entries, &ui.delegate));
}

fn schedule_tick() {
    after(Duration::from_secs(1), || {
        guard("tick", || {
            dispatch(|c, now| c.tick(now));
        });
        schedule_tick();
    });
}

fn hotkey_pressed(key: HotKey) {
    match key {
        HotKey::Show => dispatch(|c, now| c.command(MenuCommand::Open, now)),
        HotKey::Lock => dispatch(|c, _| c.lock_hotkey()),
    }
}

fn option_changed(down: bool) {
    guard("flagsChanged", || {
        dispatch(|c, now| {
            c.vm_event(now, |vm| {
                vm.set_reveal(down);
                Vec::new()
            })
        })
    });
}

fn escape_pressed() {
    guard("cancel", || dispatch(|c, now| c.vm_event(now, |vm| vm.cancel())));
}

/// A text field changed: forward its contents.
pub(super) fn field_changed(tag: isize) {
    if with_ui(|ui| ui.sites.is_rendering()).unwrap_or(true) {
        return;
    }
    let Some(text) = with_ui(|ui| ui.sites.text_of(tag)).flatten() else { return };
    // Secrets go straight into zeroizing buffers.  (The NSString AppKit keeps
    // is outside our control; fields are cleared on every screen change.)
    let secret = || Zeroizing::new(text.to_string());
    match tag {
        sw::TAG_MASTER_PASSWORD => {
            let pw = secret();
            dispatch(|c, now| c.vm_event(now, |vm| vm.set_master_password(pw)));
        }
        sw::TAG_NEW_PASSWORD => {
            let pw = secret();
            dispatch(|c, now| c.vm_event(now, |vm| vm.set_new_password(pw)));
        }
        sw::TAG_NEW_CONFIRM => {
            let pw = secret();
            dispatch(|c, now| {
                c.vm_event(now, |vm| {
                    vm.set_new_confirm(pw);
                    Vec::new()
                })
            });
        }
        sw::TAG_NEW_NAME => {
            let text = text.to_string();
            dispatch(|c, now| c.vm_event(now, |vm| vm.set_new_name(&text)));
        }
        sw::TAG_SITE => {
            let text = text.to_string();
            dispatch(|c, now| {
                c.vm_event(now, |vm| {
                    vm.set_site_query(&text);
                    Vec::new()
                })
            });
        }
        _ => {}
    }
}

/// A key command in one of our text fields.  Returns whether we handled it.
pub(super) fn text_command(tag: isize, command: Sel) -> bool {
    if command == sel!(insertNewline:) {
        match tag {
            sw::TAG_NEW_NAME => {
                with_ui(|ui| ui.sites.focus_field(sw::TAG_NEW_PASSWORD));
            }
            sw::TAG_NEW_PASSWORD => {
                with_ui(|ui| ui.sites.focus_field(sw::TAG_NEW_CONFIRM));
            }
            sw::TAG_SITE => {
                let what = if sw::shift_down() { CopyWhat::Login } else { CopyWhat::Current };
                dispatch(|c, now| c.vm_event(now, |vm| vm.copy(what)));
            }
            _ => dispatch(|c, now| c.vm_event(now, |vm| vm.submit_unlock())),
        }
        true
    } else if command == sel!(cancelOperation:) {
        dispatch(|c, now| c.vm_event(now, |vm| vm.cancel()));
        true
    } else if tag == sw::TAG_SITE && (command == sel!(moveUp:) || command == sel!(moveDown:)) {
        let delta = if command == sel!(moveUp:) { -1 } else { 1 };
        dispatch(|c, now| {
            c.vm_event(now, |vm| {
                vm.move_selection(delta);
                Vec::new()
            })
        });
        true
    } else {
        false
    }
}

fn vm_do(f: impl FnOnce(&mut SitesViewModel)) {
    dispatch(|c, now| {
        c.vm_event(now, |vm| {
            f(vm);
            Vec::new()
        })
    });
}

pub(super) fn control_action(tag: isize) {
    match tag {
        sw::TAG_UNLOCK | sw::TAG_CREATE => dispatch(|c, now| c.vm_event(now, |vm| vm.submit_unlock())),
        sw::TAG_QUICK_UNLOCK => dispatch(|c, _| c.quick_unlock()),
        sw::TAG_CARD_RETRY => dispatch(|c, _| c.retry_card()),
        sw::TAG_RECOVERY_CODE => dispatch(|c, _| c.use_recovery_code()),
        sw::TAG_CARD_CANCEL => dispatch(|c, _| {
            c.cancel_card();
            Vec::new()
        }),
        sw::TAG_CANCEL_NEW => vm_do(|vm| vm.cancel_new_user()),
        sw::TAG_AVATAR_PREV => vm_do(|vm| vm.cycle_new_avatar(-1)),
        sw::TAG_AVATAR_NEXT => vm_do(|vm| vm.cycle_new_avatar(1)),
        sw::TAG_COPY => dispatch(|c, now| c.vm_event(now, |vm| vm.copy(CopyWhat::Current))),
        sw::TAG_LOCK => dispatch(|c, now| c.command(MenuCommand::Lock, now)),
        sw::TAG_PURPOSE => {
            if let Some(p) = with_ui(|ui| ui.sites.selected_purpose()).flatten() {
                vm_do(|vm| vm.set_purpose(p));
            }
        }
        sw::TAG_TYPE => {
            if let Some(t) = with_ui(|ui| ui.sites.selected_type()).flatten() {
                dispatch(|c, now| c.vm_event(now, |vm| vm.choose_type(t)));
            }
        }
        sw::TAG_COUNTER => {
            if let Some(n) = with_ui(|ui| ui.sites.counter_value()) {
                vm_do(|vm| vm.set_counter(n));
            }
        }
        sw::TAG_QUESTION => {
            if let Some(q) = with_ui(|ui| ui.sites.selected_question()).flatten() {
                vm_do(|vm| vm.select_question(&q));
            }
        }
        sw::TAG_ADD_QUESTION => dispatch(|c, now| c.vm_event(now, |vm| vm.ask_add_question())),
        sw::TAG_REMOVE_QUESTION => dispatch(|c, now| c.vm_event(now, |vm| vm.ask_remove_question())),
        sw::TAG_UPGRADE => dispatch(|c, now| c.vm_event(now, |vm| vm.ask_upgrade_site())),
        sw::TAG_DELETE_SITE => dispatch(|c, now| c.vm_event(now, |vm| vm.ask_delete_site())),
        ww::TAG_WELCOME_LOGIN => dispatch(|c, now| c.command(MenuCommand::ToggleOpenAtLogin, now)),
        ww::TAG_WELCOME_DONE => {
            with_ui(|ui| ui.welcome.close());
        }
        ww::TAG_WELCOME_OPEN => {
            with_ui(|ui| ui.welcome.close());
            dispatch(|c, now| c.command(MenuCommand::Open, now));
        }
        _ => {}
    }
}

/// A row was selected (by the user) in one of the tables.
pub(super) fn table_selected(tag: isize, row: Option<usize>) {
    if with_ui(|ui| ui.sites.is_rendering()).unwrap_or(true) {
        return;
    }
    let Some(row) = row else { return };
    match tag {
        sw::TAG_USERS_TABLE => {
            let name = with_core(|c| c.vm().users().get(row).map(|u| u.full_name.clone())).flatten();
            vm_do(|vm| vm.pick_user(name.as_deref()));
            let field = if name.is_some() { sw::TAG_MASTER_PASSWORD } else { sw::TAG_NEW_NAME };
            with_ui(|ui| ui.sites.focus_field(field));
        }
        sw::TAG_SITES_TABLE => vm_do(|vm| vm.select(row)),
        _ => {}
    }
}

fn open_paths(paths: Vec<PathBuf>) {
    for path in paths {
        dispatch(|c, _| {
            let mut effects = vec![UiEffect::ShowSitesWindow];
            effects.extend(c.import_path(&path));
            effects
        });
    }
}

fn system_event(event: SystemEvent) {
    guard("system event", || dispatch(|c, _| c.system_event(event)));
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; no Drop impl.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "MPWAppDelegate"]
    pub struct AppDelegate;

    // SAFETY: no requirements.
    unsafe impl NSObjectProtocol for AppDelegate {}

    // SAFETY: method signatures match the protocol.
    unsafe impl NSApplicationDelegate for AppDelegate {
        #[unsafe(method(applicationDidFinishLaunching:))]
        fn did_finish_launching(&self, _notification: &NSNotification) {
            guard("launch", || launch(self));
        }

        #[unsafe(method(applicationWillResignActive:))]
        fn will_resign_active(&self, _notification: &NSNotification) {
            guard("resign active", || dispatch(|c, _| c.app_did_resign_active()));
        }

        #[unsafe(method(applicationWillTerminate:))]
        fn will_terminate(&self, _notification: &NSNotification) {
            guard("terminate", || {
                // Save, clear our clipboard secret and keys; the Terminate
                // effect is ignored (we are already terminating).
                with_core(|c| drop(c.quit()));
                super::secure_input::set(false);
                STATE.with(|s| s.borrow_mut().take());
            });
        }

        #[unsafe(method(application:openURLs:))]
        fn open_urls(&self, _application: &NSApplication, urls: &NSArray<NSURL>) {
            let paths: Vec<PathBuf> =
                urls.iter().filter_map(|u| u.path()).map(|p| PathBuf::from(p.to_string())).collect();
            guard("open", || {
                if STATE.with(|s| s.borrow().is_some()) {
                    open_paths(paths);
                } else {
                    PENDING_OPEN.with(|p| p.borrow_mut().extend(paths));
                }
            });
        }
    }

    // SAFETY: method signatures match the protocol.
    unsafe impl NSMenuDelegate for AppDelegate {
        #[unsafe(method(menuNeedsUpdate:))]
        fn menu_needs_update(&self, _menu: &NSMenu) {
            guard("menu", rebuild_menu);
        }

        #[unsafe(method(menuWillOpen:))]
        fn menu_will_open(&self, _menu: &NSMenu) {
            MENU_OPEN.with(|m| m.set(true));
            guard("menu open", update_focus_state);
        }

        #[unsafe(method(menuDidClose:))]
        fn menu_did_close(&self, _menu: &NSMenu) {
            MENU_OPEN.with(|m| m.set(false));
            guard("menu close", update_focus_state);
            // Re-check once the chosen command (if any) has run.
            after(Duration::from_millis(400), || guard("focus check", focus_check));
        }
    }

    // SAFETY: method signatures match the protocol.
    unsafe impl NSWindowDelegate for AppDelegate {
        #[unsafe(method(windowWillClose:))]
        fn window_will_close(&self, notification: &NSNotification) {
            guard("window close", || {
                let object = notification.object();
                let is_sites = with_ui(|ui| {
                    object.as_deref().is_some_and(|o| std::ptr::eq(o, &*ui.sites.window as &AnyObject))
                })
                .unwrap_or(false);
                if is_sites {
                    dispatch(|c, _| {
                        c.window_did_close();
                        Vec::new()
                    });
                }
            });
        }

        #[unsafe(method(windowDidBecomeKey:))]
        fn window_did_become_key(&self, _notification: &NSNotification) {
            guard("become key", update_focus_state);
        }

        #[unsafe(method(windowDidResignKey:))]
        fn window_did_resign_key(&self, _notification: &NSNotification) {
            guard("resign key", || {
                update_focus_state();
                // Decide a moment later: a sheet of ours may be taking over.
                after(Duration::from_millis(250), || guard("focus check", focus_check));
            });
        }
    }

    // SAFETY: method signatures match the protocol.
    unsafe impl NSControlTextEditingDelegate for AppDelegate {
        #[unsafe(method(controlTextDidBeginEditing:))]
        fn control_text_did_begin_editing(&self, _notification: &NSNotification) {
            guard("begin editing", update_focus_state);
        }

        #[unsafe(method(controlTextDidChange:))]
        fn control_text_did_change(&self, notification: &NSNotification) {
            guard("text change", || {
                if let Some(control) = notification.object().and_then(|o| o.downcast::<NSControl>().ok()) {
                    field_changed(control.tag());
                }
            });
        }

        #[unsafe(method(control:textView:doCommandBySelector:))]
        fn do_command(&self, control: &NSControl, _text_view: &NSTextView, command: Sel) -> bool {
            let mut handled = false;
            guard("key command", || handled = text_command(control.tag(), command));
            handled
        }
    }

    // SAFETY: no required methods.
    unsafe impl NSTextFieldDelegate for AppDelegate {}

    // SAFETY: method signatures match the protocol.
    unsafe impl NSTableViewDataSource for AppDelegate {
        #[unsafe(method(numberOfRowsInTableView:))]
        fn number_of_rows(&self, table: &NSTableView) -> isize {
            with_ui(|ui| ui.sites.row_count(table.tag())).unwrap_or(0) as isize
        }
    }

    // SAFETY: method signatures match the protocol.
    unsafe impl NSTableViewDelegate for AppDelegate {
        #[unsafe(method_id(tableView:viewForTableColumn:row:))]
        fn view_for_row(
            &self,
            table: &NSTableView,
            _column: Option<&NSTableColumn>,
            row: isize,
        ) -> Option<Retained<NSView>> {
            let row = usize::try_from(row).ok();
            row.and_then(|row| with_ui(|ui| ui.sites.row_view(table.tag(), row)).flatten())
        }

        #[unsafe(method(tableViewSelectionDidChange:))]
        fn selection_did_change(&self, notification: &NSNotification) {
            guard("table selection", || {
                if let Some(table) = notification.object().and_then(|o| o.downcast::<NSTableView>().ok()) {
                    let tag = table.tag();
                    table_selected(tag, with_ui(|ui| ui.sites.selected_row(tag)).flatten());
                }
            });
        }
    }

    impl AppDelegate {
        // SAFETY: `-(void)menuAction:(NSMenuItem *)sender`.
        #[unsafe(method(menuAction:))]
        fn menu_action(&self, sender: &NSMenuItem) {
            let tag = sender.tag();
            guard("menu action", || {
                if let Some(command) = MenuCommand::from_tag(tag) {
                    dispatch(|c, now| c.command(command, now));
                }
            });
        }

        // SAFETY: `-(void)uiAction:(NSControl *)sender`.
        #[unsafe(method(uiAction:))]
        fn ui_action(&self, sender: &NSControl) {
            let tag = sender.tag();
            guard("control action", || control_action(tag));
        }

        // SAFETY: `-(void)tableDoubleClick:(NSTableView *)sender`.
        #[unsafe(method(tableDoubleClick:))]
        fn table_double_click(&self, sender: &NSTableView) {
            let tag = sender.tag();
            guard("double click", || {
                if with_ui(|ui| ui.sites.clicked_row(tag)).flatten().is_none() {
                    return;
                }
                if tag == sw::TAG_SITES_TABLE {
                    dispatch(|c, now| c.vm_event(now, |vm| vm.copy(CopyWhat::Current)));
                }
            });
        }

        // SAFETY: `-(void)x:(NSNotification *)n` for each observer below.
        #[unsafe(method(systemWillSleep:))]
        fn system_will_sleep(&self, _n: &NSNotification) {
            system_event(SystemEvent::WillSleep);
        }

        #[unsafe(method(screensDidSleep:))]
        fn screens_did_sleep(&self, _n: &NSNotification) {
            system_event(SystemEvent::ScreensDidSleep);
        }

        #[unsafe(method(sessionDidResignActive:))]
        fn session_did_resign_active(&self, _n: &NSNotification) {
            system_event(SystemEvent::SessionResignedActive);
        }

        #[unsafe(method(screenLocked:))]
        fn screen_locked(&self, _n: &NSNotification) {
            system_event(SystemEvent::ScreenLocked);
        }

        #[unsafe(method(screensaverStarted:))]
        fn screensaver_started(&self, _n: &NSNotification) {
            system_event(SystemEvent::ScreensaverStarted);
        }
    }
);

impl AppDelegate {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(());
        // SAFETY: NSObject's designated initializer.
        unsafe { msg_send![super(this), init] }
    }
}

/// Everything that differs between a real run and the smoke test.
struct Environment {
    prefs: Box<dyn PrefsStore>,
    pasteboard: SystemPasteboard,
    smoke_pasteboard: Option<SystemPasteboard>,
    store: Result<Arc<dyn DataStore>, String>,
    vault: Box<dyn KeyVault>,
    auth: Box<dyn DeviceAuthenticator>,
    cards: Arc<dyn crate::card::SmartCards>,
}

fn environment(mode: LaunchMode) -> Environment {
    if mode == LaunchMode::SmokeTest {
        let prefs: Box<dyn PrefsStore> = match UserDefaults::throwaway(SMOKE_DEFAULTS_SUITE) {
            Some(d) => Box::new(d),
            None => Box::new(MemoryPrefs::default()),
        };
        let private = SystemPasteboard::private();
        let store = DiskStore::open(smoke::store_dir())
            .map(|s| Arc::new(s) as Arc<dyn DataStore>)
            .map_err(|e| e.to_string());
        return Environment {
            prefs,
            pasteboard: private.shared(),
            smoke_pasteboard: Some(private),
            store,
            vault: Box::new(Keychain::with_service(&smoke::keychain_service())),
            auth: Box::new(StubAuth(Ok(()))),
            cards: smoke::software_cards(),
        };
    }
    Environment {
        prefs: Box::new(UserDefaults::app()),
        pasteboard: SystemPasteboard::general(),
        smoke_pasteboard: None,
        store: DiskStore::open_default().map(|s| Arc::new(s) as Arc<dyn DataStore>).map_err(|e| e.to_string()),
        vault: Box::new(Keychain::app()),
        auth: Box::new(LocalAuth),
        cards: Arc::new(super::smart_card::SystemCards),
    }
}

fn launch(delegate: &AppDelegate) {
    let Some(mtm) = MainThreadMarker::new() else { return };
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    let mode = mode();
    let env = environment(mode);

    let (store, store_error): (Arc<dyn DataStore>, Option<String>) = match env.store {
        Ok(s) => (s, None),
        Err(e) => {
            // Keep running (the menu, the clipboard hygiene) but say so.
            eprintln!("MasterPwd: cannot open the user store: {e}");
            (Arc::new(crate::data::MemoryStore::new()), Some(e))
        }
    };
    let quick_unlock = env.auth.availability();
    AUTH.with(|a| *a.borrow_mut() = Some(env.auth));
    let vault: Box<dyn KeyVault> = if store_error.is_some() { Box::new(MemoryVault::default()) } else { env.vault };
    let mut vm = SitesViewModel::new(SaveQueue::threaded(store));
    if let Some(e) = &store_error {
        vm.set_error(format!("Your users could not be loaded ({e}); changes are NOT being saved."));
    }
    let core = AppCore::new(
        vm,
        env.prefs,
        Box::new(env.pasteboard),
        vault,
        quick_unlock,
        login_item::state(),
        Instant::now(),
    )
    .with_cards(env.cards);

    let retained: Retained<AppDelegate> = delegate.retain();
    let target: &AnyObject = delegate;
    let ui = Ui {
        status: StatusItem::new(mtm, ProtocolObject::from_ref(delegate)),
        sites: SitesWindow::new(
            mtm,
            Delegates {
                target,
                text: ProtocolObject::from_ref(delegate),
                window: ProtocolObject::from_ref(delegate),
                source: ProtocolObject::from_ref(delegate),
                table: ProtocolObject::from_ref(delegate),
            },
            option_changed,
            escape_pressed,
        ),
        welcome: WelcomeWindow::new(mtm, target, ProtocolObject::from_ref(delegate)),
        delegate: retained,
        smoke_pasteboard: env.smoke_pasteboard,
    };
    UI.with(|cell| {
        let _ = cell.set(ui);
    });

    let (hotkeys, hotkey_errors) = hotkey::register(hotkey_pressed);
    for e in &hotkey_errors {
        eprintln!("MasterPwd: {e}");
    }
    system_events::observe(target);
    STATE.with(|s| *s.borrow_mut() = Some(State { core, hotkeys: Some(hotkeys), hotkey_errors }));

    rebuild_menu();
    render();
    dispatch(|c, _| c.launched());
    if mode == LaunchMode::Show {
        dispatch(|c, now| c.command(MenuCommand::Open, now));
    }
    let pending = PENDING_OPEN.with(|p| std::mem::take(&mut *p.borrow_mut()));
    if !pending.is_empty() {
        open_paths(pending);
    }
    schedule_tick();
    if mode == LaunchMode::SmokeTest {
        smoke::start();
    }
}

pub fn run(mode: LaunchMode) -> i32 {
    let Some(mtm) = MainThreadMarker::new() else {
        eprintln!("MasterPwd: must start on the main thread");
        return 1;
    };
    MODE.with(|m| m.set(mode));
    let app = NSApplication::sharedApplication(mtm);
    let delegate = AppDelegate::new(mtm);
    app.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
    app.run();
    drop(delegate);
    0
}

/// Run the main run loop for `duration` (smoke-test review aid only).
pub(super) fn pump_run_loop(duration: Duration) {
    let until = objc2_foundation::NSDate::dateWithTimeIntervalSinceNow(duration.as_secs_f64());
    objc2_foundation::NSRunLoop::currentRunLoop().runUntilDate(&until);
}

/// Tear down without going through `terminate:` (smoke test exit).
pub(super) fn shutdown() {
    with_ui(|ui| {
        ui.sites.close();
        ui.welcome.close();
    });
    super::secure_input::set(false);
    // Dropping the core flushes pending saves (SaveQueue's Drop).
    STATE.with(|s| s.borrow_mut().take());
}

/// Replace the core (smoke test: "relaunch" against the same store).
pub(super) fn replace_core(core: AppCore) {
    with_state(|s| s.core = core);
    render();
}
