//! `--smoke-test`: build the real status item, menus and windows, pump the
//! run loop, drive unlock → site → result → copy → lock through the same
//! handlers the UI uses (real algorithm, real `NSPasteboard` — a private one,
//! so the user's clipboard is untouched), then exit 0, or 1 with a message.

use std::cell::RefCell;
use std::time::{Duration, Instant};

use dispatch2::{DispatchQueue, DispatchTime};
use objc2::sel;

use super::app::{dispatch, field_changed, rebuild_menu, shutdown, text_command, with_core, with_state, with_ui};
use super::keychain::Keychain;
use super::login_item;
use super::pasteboard::{CONCEALED_TYPE, TRANSIENT_TYPE};
use mpw_core::{AlgorithmVersion, MasterKey};
use super::sites_window as sw;
use crate::clipboard::Pasteboard;
use crate::menu::MenuCommand;
use crate::view_model::Mode;

const NAME: &str = "Robert Lee Mitchell";
const PASSWORD: &str = "banana colored duckling";
const SITE: &str = "masterpasswordapp.com";
/// Reference test vector (v3, counter 1, long).
const EXPECTED: &str = "Jejr5[RepuSosp";

const POLL: Duration = Duration::from_millis(20);
const MIN_RUNTIME: Duration = Duration::from_secs(2);
const TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Structure,
    TypeCredentials,
    WaitUnlock,
    Site,
    Copy,
    Lock,
    Identicon,
    WaitIdenticon,
    System,
    Done,
}

struct Smoke {
    step: Step,
    started: Instant,
    step_started: Instant,
    polls_while_unlocking: u32,
}

thread_local! {
    static SMOKE: RefCell<Option<Smoke>> = const { RefCell::new(None) };
}

enum Outcome {
    Next(Step),
    Wait,
}

fn log(msg: &str) {
    eprintln!("smoke-test: {msg}");
}

pub fn start() {
    let now = Instant::now();
    SMOKE.with(|s| {
        *s.borrow_mut() =
            Some(Smoke { step: Step::Structure, started: now, step_started: now, polls_while_unlocking: 0 })
    });
    log("launched; pumping the run loop");
    // Give the run loop a second to settle (status item, windows on screen).
    schedule(Duration::from_secs(1));
}

fn schedule(delay: Duration) {
    let when = DispatchTime::try_from(delay).unwrap_or(DispatchTime::NOW);
    let _ = DispatchQueue::main().after(when, poll);
}

fn finish(result: Result<(), String>) -> ! {
    shutdown();
    match result {
        Ok(()) => {
            log("PASSED");
            std::process::exit(0)
        }
        Err(e) => {
            log(&format!("FAILED: {e}"));
            std::process::exit(1)
        }
    }
}

fn poll() {
    let Some((step, started, step_started)) =
        SMOKE.with(|s| s.borrow().as_ref().map(|s| (s.step, s.started, s.step_started)))
    else {
        return;
    };
    if started.elapsed() > TIMEOUT {
        finish(Err(format!("timed out in step {step:?}")));
    }
    let result = std::panic::catch_unwind(|| run_step(step, step_started));
    match result {
        Err(_) => finish(Err(format!("panic in step {step:?}"))),
        Ok(Err(e)) => finish(Err(format!("{step:?}: {e}"))),
        Ok(Ok(Outcome::Wait)) => schedule(POLL),
        Ok(Ok(Outcome::Next(Step::Done))) => {
            let remaining = MIN_RUNTIME.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                finish(Ok(()));
            }
            SMOKE.with(|s| {
                if let Some(s) = s.borrow_mut().as_mut() {
                    s.step = Step::Done;
                }
            });
            schedule(remaining);
        }
        Ok(Ok(Outcome::Next(next))) => {
            log(&format!("{step:?} ok"));
            SMOKE.with(|s| {
                if let Some(s) = s.borrow_mut().as_mut() {
                    s.step = next;
                    s.step_started = Instant::now();
                }
            });
            schedule(POLL);
        }
    }
}

fn check(ok: bool, what: impl Into<String>) -> Result<(), String> {
    if ok { Ok(()) } else { Err(what.into()) }
}

fn mode() -> Mode {
    with_core(|c| c.vm().mode()).unwrap_or(Mode::Locked)
}

fn smoke_pasteboard_string() -> Option<String> {
    with_ui(|ui| ui.smoke_pasteboard.as_ref().and_then(|p| p.string())).flatten()
}

fn run_step(step: Step, step_started: Instant) -> Result<Outcome, String> {
    match step {
        Step::Structure => {
            rebuild_menu();
            let (has_button, items, welcome) = with_ui(|ui| {
                (ui.status.has_button(), ui.status.menu.numberOfItems(), ui.welcome.is_visible())
            })
            .ok_or("no UI")?;
            check(has_button, "status item has no button")?;
            check(items >= 8, format!("status menu has only {items} items"))?;
            check(welcome, "welcome window not shown on first launch")?;
            let (hotkeys, errors) =
                with_state(|s| (s.hotkeys.as_ref().map_or(0, |h| h.count()), s.hotkey_errors.clone()))
                    .ok_or("no state")?;
            if hotkeys == 2 {
                log("both global hotkeys registered");
            } else {
                // Another app (e.g. a running Master Password) may hold them.
                log(&format!("WARNING: {hotkeys}/2 hotkeys registered: {errors:?}"));
            }
            with_ui(|ui| ui.welcome.close());
            dispatch(|c, now| c.command(MenuCommand::Open, now));
            let (visible, excluded) =
                with_ui(|ui| (ui.sites.is_visible(), ui.sites.excluded_from_capture())).ok_or("no UI")?;
            check(visible, "sites window did not open")?;
            let allow = std::env::var(sw::ALLOW_CAPTURE_ENV).is_ok_and(|v| v == "1");
            check(excluded != allow, format!("sharingType none = {excluded}, override = {allow}"))?;
            log(&format!("sites window excluded from screen capture: {excluded}"));
            Ok(Outcome::Next(Step::TypeCredentials))
        }
        Step::TypeCredentials => {
            with_ui(|ui| {
                ui.sites.set_field(sw::TAG_FULL_NAME, NAME);
                ui.sites.set_field(sw::TAG_MASTER_PASSWORD, PASSWORD);
            });
            field_changed(sw::TAG_FULL_NAME);
            field_changed(sw::TAG_MASTER_PASSWORD);
            check(text_command(sw::TAG_MASTER_PASSWORD, sel!(insertNewline:)), "⏎ not handled")?;
            check(mode() == Mode::Unlocking, format!("expected Unlocking, got {:?}", mode()))?;
            let cleared = with_ui(|ui| ui.sites.text_of(sw::TAG_MASTER_PASSWORD))
                .flatten()
                .is_some_and(|s| s.length() == 0);
            check(cleared, "master password field not cleared while unlocking")?;
            Ok(Outcome::Next(Step::WaitUnlock))
        }
        Step::WaitUnlock => match mode() {
            Mode::Unlocking => {
                SMOKE.with(|s| {
                    if let Some(s) = s.borrow_mut().as_mut() {
                        s.polls_while_unlocking += 1;
                    }
                });
                Ok(Outcome::Wait)
            }
            Mode::Unlocked => {
                let polls = SMOKE.with(|s| s.borrow().as_ref().map_or(0, |s| s.polls_while_unlocking));
                log(&format!(
                    "unlocked after {:?}; main thread serviced {polls} timer polls meanwhile",
                    step_started.elapsed()
                ));
                check(polls >= 1, "main thread was blocked during key derivation")?;
                Ok(Outcome::Next(Step::Site))
            }
            Mode::Locked => Err(format!(
                "unlock failed: {}",
                with_core(|c| c.vm().error().map(str::to_owned)).flatten().unwrap_or_default()
            )),
        },
        Step::Site => {
            with_ui(|ui| ui.sites.set_field(sw::TAG_SITE, SITE));
            field_changed(sw::TAG_SITE);
            let result = with_core(|c| c.vm().result().map(str::to_owned)).flatten();
            check(result.as_deref() == Some(EXPECTED), format!("wrong site password {result:?}"))?;
            let shown = with_ui(|ui| ui.sites.displayed_result()).unwrap_or_default();
            check(shown == EXPECTED, "result not rendered")?;
            dispatch(|c, now| c.command(MenuCommand::ToggleHidePasswords, now));
            let masked = with_ui(|ui| ui.sites.displayed_result()).unwrap_or_default();
            check(masked == "●".repeat(EXPECTED.len()), format!("not masked: {}", masked.chars().count()))?;
            dispatch(|c, now| c.command(MenuCommand::ToggleHidePasswords, now));
            // Review aid: hold the unlocked window on screen for a screenshot.
            if let Some(ms) = std::env::var("MASTERPWD_SMOKE_HOLD_MS").ok().and_then(|v| v.parse::<u64>().ok()) {
                let until = Instant::now() + Duration::from_millis(ms.min(30_000));
                while Instant::now() < until {
                    super::app::pump_run_loop(Duration::from_millis(50));
                }
            }
            Ok(Outcome::Next(Step::Copy))
        }
        Step::Copy => {
            check(text_command(sw::TAG_SITE, sel!(insertNewline:)), "⏎ not handled")?;
            let content = smoke_pasteboard_string();
            check(content.as_deref() == Some(EXPECTED), "pasteboard does not hold the password")?;
            let types = with_ui(|ui| ui.smoke_pasteboard.as_ref().map(|p| p.type_names()))
                .flatten()
                .unwrap_or_default();
            check(
                types.iter().any(|t| t == CONCEALED_TYPE) && types.iter().any(|t| t == TRANSIENT_TYPE),
                format!("missing concealed/transient markers: {types:?}"),
            )?;
            check(!with_ui(|ui| ui.sites.is_visible()).unwrap_or(true), "window still open after copy")?;
            check(mode() == Mode::Locked, "Remember Password is off: closing should lock")?;
            check(with_core(|c| c.clipboard_holds_secret()) == Some(true), "clipboard cleared too early")?;
            Ok(Outcome::Next(Step::Lock))
        }
        Step::Lock => {
            dispatch(|c, now| c.command(MenuCommand::Lock, now));
            check(smoke_pasteboard_string().is_none(), "lock did not clear the pasteboard")?;
            let count_ok = with_ui(|ui| ui.smoke_pasteboard.as_ref().map(|p| p.change_count() > 0)).flatten();
            check(count_ok == Some(true), "pasteboard change count")?;
            Ok(Outcome::Next(Step::Identicon))
        }
        Step::Identicon => {
            dispatch(|c, now| c.command(MenuCommand::Open, now));
            with_ui(|ui| ui.sites.set_field(sw::TAG_MASTER_PASSWORD, PASSWORD));
            field_changed(sw::TAG_MASTER_PASSWORD);
            let early = with_core(|c| c.vm().view().identicon.is_some()).unwrap_or(true);
            check(!early, "identicon shown before the typing pause")?;
            Ok(Outcome::Next(Step::WaitIdenticon))
        }
        Step::WaitIdenticon => {
            if with_core(|c| c.vm().view().identicon.is_some()).unwrap_or(false) {
                log("identicon appeared after the typing pause");
                dispatch(|c, now| c.vm_event(now, |vm| vm.cancel()));
                Ok(Outcome::Next(Step::System))
            } else if step_started.elapsed() > Duration::from_secs(5) {
                Err("identicon never appeared".into())
            } else {
                Ok(Outcome::Wait)
            }
        }
        Step::System => {
            // Keychain round trip under this process's signature/sandbox,
            // with a throwaway service that is deleted again.
            let kc = Keychain::with_service(&format!(
                "com.github.howler4695.masterpwd.SMOKE-THROWAWAY-{}",
                std::process::id()
            ));
            let key = MasterKey::from_bytes([42; 64], AlgorithmVersion::V3);
            let backend = kc.store("smoke", &key).map_err(|e| format!("keychain store: {e}"))?;
            let loaded = kc.load("smoke", AlgorithmVersion::V3).map_err(|e| format!("keychain load: {e}"))?;
            let deleted = kc.delete("smoke", AlgorithmVersion::V3).map_err(|e| format!("keychain delete: {e}"))?;
            check(loaded.is_some_and(|k| k.as_bytes() == &[42; 64]) && deleted, "keychain round trip")?;
            log(&format!("keychain round trip ok ({backend:?} keychain)"));
            log(&format!("bundled: {}; login item: {:?}", super::is_bundled(), login_item::state()));
            Ok(Outcome::Next(Step::Done))
        }
        Step::Done => finish(Ok(())),
    }
}
