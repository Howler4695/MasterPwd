//! The application delegate and the event loop glue.
//!
//! All state lives in one main-thread-only [`State`] holding the
//! [`AppCore`].  Every AppKit callback becomes a call to [`dispatch`], which
//! borrows the core, runs it, *releases the borrow*, then carries out the
//! returned [`UiEffect`]s and re-renders.  Effects may re-enter `dispatch`
//! (closing a window fires `windowWillClose:`), which is why the borrow is
//! never held while talking to AppKit.

use std::cell::{Cell, OnceCell, RefCell};
use std::panic::AssertUnwindSafe;
use std::time::{Duration, Instant};

use dispatch2::{DispatchQueue, DispatchTime};
use mpw_core::Zeroizing;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject, Sel};
use objc2::{define_class, msg_send, sel, MainThreadMarker, MainThreadOnly, Message};
use objc2_app_kit::{
    NSAlert, NSApplication, NSApplicationActivationPolicy, NSApplicationDelegate, NSControl,
    NSControlTextEditingDelegate, NSMenu, NSMenuDelegate, NSMenuItem, NSTextFieldDelegate, NSTextView,
    NSWindowDelegate,
};
use objc2_foundation::{NSNotification, NSObject, NSObjectProtocol};

use super::hotkey::{self, HotKey, HotKeys};
use super::pasteboard::SystemPasteboard;
use super::sites_window::{self as sw, SitesWindow};
use super::status_item::StatusItem;
use super::welcome_window::{self as ww, WelcomeWindow};
use super::{defaults::UserDefaults, login_item, ns, smoke, system_events};
use crate::core::{AppCore, LoginItemState, SystemEvent, UiEffect};
use crate::data::MemoryStore;
use crate::menu::MenuCommand;
use crate::prefs::{MemoryPrefs, PrefsStore};
use crate::view_model::Mode;

/// How the process was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchMode {
    Normal,
    /// Open the sites window right away (review/debug aid).
    Show,
    /// Build everything, drive the core flow, exit 0 / non-zero.
    SmokeTest,
}

pub type Core = AppCore<MemoryStore>;

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
    /// Second handle on the smoke test's private pasteboard, for checks.
    pub smoke_pasteboard: Option<SystemPasteboard>,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    static UI: OnceCell<Ui> = const { OnceCell::new() };
    static MODE: Cell<LaunchMode> = const { Cell::new(LaunchMode::Normal) };
}

pub const SMOKE_DEFAULTS_SUITE: &str = "com.github.howler4695.masterpwd.smoke-test";

/// Run `f` and swallow (log) a panic: unwinding into AppKit or Carbon is
/// undefined behaviour, and a password manager must not just vanish.
fn guard(what: &str, f: impl FnOnce()) {
    if std::panic::catch_unwind(AssertUnwindSafe(f)).is_err() {
        eprintln!("MasterPwd: internal error in {what} (recovered)");
    }
}

/// Borrow the state.  `None` if not launched yet, or on re-entrancy (which
/// `dispatch` is designed to avoid; we log rather than panic).
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
    let Some((view, mode, login)) =
        with_core(|c| (c.vm().view(), c.vm().mode(), c.login_item().clone()))
    else {
        return;
    };
    with_ui(|ui| {
        ui.sites.render(&view);
        ui.status.set_locked(mode == Mode::Locked);
        ui.welcome.render(&login);
    });
}

fn show_alert(message: &str, info: &str) {
    let Some(mtm) = MainThreadMarker::new() else { return };
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&ns(message));
    alert.setInformativeText(&ns(info));
    alert.runModal();
}

fn run_effects(effects: Vec<UiEffect>) {
    for effect in effects {
        match effect {
            UiEffect::ShowSitesWindow => {
                let was_visible = with_ui(|ui| ui.sites.is_visible()).unwrap_or(true);
                if !was_visible {
                    with_core(|c| c.window_did_show(Instant::now()));
                    render();
                }
                with_ui(|ui| ui.sites.show());
            }
            // `windowWillClose:` reports back to the core.
            UiEffect::CloseSitesWindow => {
                with_ui(|ui| ui.sites.close());
            }
            UiEffect::HideApp => {
                if let Some(mtm) = MainThreadMarker::new() {
                    NSApplication::sharedApplication(mtm).hide(None);
                }
            }
            UiEffect::StartUnlock(job) => {
                // scrypt runs here, never on the main thread.
                let spawned = std::thread::Builder::new().name("mpw-unlock".into()).spawn(move || {
                    let outcome = job.run();
                    DispatchQueue::main().exec_async(move || {
                        guard("unlock", || {
                            dispatch(|c, now| {
                                c.unlock_finished(outcome, now);
                                Vec::new()
                            })
                        })
                    });
                });
                if spawned.is_err() {
                    with_core(|c| c.lock(crate::core::LockReason::Command));
                    eprintln!("MasterPwd: could not start the unlock thread");
                }
            }
            UiEffect::ScheduleIdenticon { generation, delay } => {
                let when = DispatchTime::try_from(delay).unwrap_or(DispatchTime::NOW);
                let _ = DispatchQueue::main().after(when, move || {
                    guard("identicon", || {
                        dispatch(|c, now| {
                            c.vm_event(now, |vm| {
                                vm.identicon_due(generation);
                                Vec::new()
                            })
                        })
                    })
                });
            }
            UiEffect::SetLoginItem(on) => {
                let (state, error) = login_item::set_enabled(on);
                let needs_approval = state == LoginItemState::RequiresApproval;
                with_core(|c| c.set_login_item(state));
                if let Some(error) = error {
                    show_alert("Could not change Open at Login", &error);
                } else if on && needs_approval {
                    login_item::open_settings();
                }
            }
            UiEffect::ShowWelcome => {
                render();
                with_ui(|ui| ui.welcome.show());
            }
            UiEffect::Terminate => {
                if let Some(mtm) = MainThreadMarker::new() {
                    NSApplication::sharedApplication(mtm).terminate(None);
                }
            }
        }
    }
}

/// Refresh the login item state and rebuild the status menu.
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
    let when = DispatchTime::try_from(Duration::from_secs(1)).unwrap_or(DispatchTime::NOW);
    let _ = DispatchQueue::main().after(when, || {
        guard("tick", || {
            with_core(|c| c.tick(Instant::now()));
            render();
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
    let Some(text) = with_ui(|ui| ui.sites.text_of(tag)).flatten() else { return };
    match tag {
        sw::TAG_MASTER_PASSWORD => {
            // Copy straight into a zeroizing buffer.  (The NSString AppKit
            // keeps is outside our control; the field is cleared on unlock.)
            let password = Zeroizing::new(text.to_string());
            dispatch(|c, now| c.vm_event(now, |vm| vm.set_master_password(password)));
        }
        sw::TAG_FULL_NAME => {
            let text = text.to_string();
            dispatch(|c, now| c.vm_event(now, |vm| vm.set_full_name(&text)));
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
        sw::TAG_QUESTION => {
            let text = text.to_string();
            dispatch(|c, now| {
                c.vm_event(now, |vm| {
                    vm.set_question(&text);
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
        if tag == sw::TAG_FULL_NAME {
            let next = with_core(|c| c.vm().view().can_unlock).unwrap_or(false);
            if !next {
                // Enter in the name field moves on to the password.
                with_ui(|ui| ui.sites.focus_password());
                return true;
            }
        }
        dispatch(|c, now| c.vm_event(now, |vm| vm.copy()));
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

fn control_action(tag: isize) {
    match tag {
        sw::TAG_UNLOCK => dispatch(|c, now| c.vm_event(now, |vm| vm.submit_unlock())),
        sw::TAG_COPY => dispatch(|c, now| c.vm_event(now, |vm| vm.copy())),
        sw::TAG_LOCK => dispatch(|c, now| c.command(MenuCommand::Lock, now)),
        sw::TAG_PURPOSE => {
            if let Some(p) = with_ui(|ui| ui.sites.selected_purpose()).flatten() {
                dispatch(|c, now| {
                    c.vm_event(now, |vm| {
                        vm.set_purpose(p);
                        Vec::new()
                    })
                });
            }
        }
        sw::TAG_TYPE => {
            if let Some(t) = with_ui(|ui| ui.sites.selected_type()).flatten() {
                dispatch(|c, now| {
                    c.vm_event(now, |vm| {
                        vm.set_result_type(t);
                        Vec::new()
                    })
                });
            }
        }
        sw::TAG_COUNTER => {
            if let Some(n) = with_ui(|ui| ui.sites.counter_value()) {
                dispatch(|c, now| {
                    c.vm_event(now, |vm| {
                        vm.set_counter(n);
                        Vec::new()
                    })
                });
            }
        }
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
                // Clear our clipboard secret and keys; ignore the Terminate
                // effect (we are already terminating).
                with_core(|c| drop(c.quit()));
                STATE.with(|s| s.borrow_mut().take());
            });
        }
    }

    // SAFETY: method signatures match the protocol.
    unsafe impl NSMenuDelegate for AppDelegate {
        #[unsafe(method(menuNeedsUpdate:))]
        fn menu_needs_update(&self, _menu: &NSMenu) {
            guard("menu", rebuild_menu);
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
    }

    // SAFETY: method signatures match the protocol.
    unsafe impl NSControlTextEditingDelegate for AppDelegate {
        #[unsafe(method(controlTextDidChange:))]
        fn control_text_did_change(&self, notification: &NSNotification) {
            guard("text change", || {
                let object = notification.object();
                if let Some(control) = object.and_then(|o| o.downcast::<NSControl>().ok()) {
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

fn launch(delegate: &AppDelegate) {
    let Some(mtm) = MainThreadMarker::new() else { return };
    let app = NSApplication::sharedApplication(mtm);
    // LSUIElement does this for the bundle; needed for `cargo run`.
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    let mode = MODE.with(Cell::get);

    let (prefs, pasteboard, smoke_pasteboard): (Box<dyn PrefsStore>, SystemPasteboard, Option<SystemPasteboard>) =
        if mode == LaunchMode::SmokeTest {
            let prefs: Box<dyn PrefsStore> = match UserDefaults::throwaway(SMOKE_DEFAULTS_SUITE) {
                Some(d) => Box::new(d),
                None => Box::new(MemoryPrefs::default()),
            };
            let private = SystemPasteboard::private();
            let shared = private.shared();
            (prefs, shared, Some(private))
        } else {
            (Box::new(UserDefaults::app()), SystemPasteboard::general(), None)
        };
    let core = AppCore::new(MemoryStore::new(), prefs, Box::new(pasteboard), login_item::state(), Instant::now());

    let retained: Retained<AppDelegate> = delegate.retain();
    let target: &AnyObject = delegate;
    let ui = Ui {
        status: StatusItem::new(mtm, ProtocolObject::from_ref(delegate)),
        sites: SitesWindow::new(
            mtm,
            target,
            ProtocolObject::from_ref(delegate),
            ProtocolObject::from_ref(delegate),
            option_changed,
            escape_pressed,
        ),
        welcome: WelcomeWindow::new(mtm, target, ProtocolObject::from_ref(delegate)),
        delegate: retained,
        smoke_pasteboard,
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
    schedule_tick();
    if mode == LaunchMode::SmokeTest {
        smoke::start();
    }
}

/// Run the app.  Must be called on the main thread; returns only on failure.
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
    STATE.with(|s| s.borrow_mut().take());
}
