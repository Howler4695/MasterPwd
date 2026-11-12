//! `--smoke-test`: build the real status item, menus and windows, pump the
//! run loop, and drive the app through the same handlers the UI uses:
//! create a user, copy a password, reload from disk, reject a wrong password,
//! export + import-merge, saved keys with a stubbed Touch ID prompt.  Exits 0,
//! or 1 with a message.
//!
//! It never touches the real user store (a temporary directory, or
//! `$MASTERPWD_STORE_DIR` if set, which is then kept), the real clipboard (a
//! private pasteboard), the real preferences (a throwaway defaults suite) or
//! the real Keychain service (a throwaway one, verified empty at the end).
//!
//! Review aid: with `MASTERPWD_SMOKE_HOLD_MS=n` it pauses for `n` ms at the
//! user picker, the unlocked window and the import dialog (shown for real),
//! logging `HOLD <what> window=<number>` so they can be screenshot.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use objc2::{sel, MainThreadMarker};

use super::app::{
    control_action, dispatch, field_changed, pump_run_loop, rebuild_menu, replace_core, shutdown, text_command,
    with_core, with_state, with_ui,
};
use super::dialogs::{run_prompt, AutoAnswer};
use super::keychain::Keychain;
use super::pasteboard::{CONCEALED_TYPE, TRANSIENT_TYPE};
use super::sites_window as sw;
use super::{cgwindow, login_item};
use crate::core::{AppCore, LoginItemState};
use crate::data::{DataStore, DiskStore, SaveQueue, STORE_DIR_ENV};
use crate::menu::MenuCommand;
use crate::prefs::MemoryPrefs;
use crate::prompt::{FileRequest, Prompt, PromptAnswer};
use crate::view_model::{Screen, SitesViewModel};

const NAME: &str = "Robert Lee Mitchell";
const PASSWORD: &str = "banana colored duckling";
const SITE: &str = "masterpasswordapp.com";
/// Reference test vector (v3, counter 1, long).
const EXPECTED: &str = "Jejr5[RepuSosp";
const NEW_PASSWORD: &str = "a new smoke-test password";

const POLL: Duration = Duration::from_millis(20);
const MIN_RUNTIME: Duration = Duration::from_secs(2);
const TIMEOUT: Duration = Duration::from_secs(90);
pub const HOLD_ENV: &str = "MASTERPWD_SMOKE_HOLD_MS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Structure,
    CreateUser,
    WaitCreate,
    Site,
    Copy,
    Lock,
    Reload,
    WrongPassword,
    WaitWrong,
    Unlock,
    WaitUnlock,
    AddSites,
    ExportImport,
    SaveKeys,
    WaitQuickUnlock,
    ChangePassword,
    WaitChange,
    WaitNewUnlock,
    SfEnable,
    SfWaitEnable,
    SfCardUnlock,
    SfWaitCardUnlock,
    SfCodeUnlock,
    SfWaitCodeUnlock,
    SfRemoval,
    SfWaitRemovalLock,
    SfAdd,
    SfWaitAdd,
    SfDisable,
    SfWaitDisable,
    Identicon,
    WaitIdenticon,
    Done,
}

/// A scripted answer to the next dialog.
struct Expect {
    title_contains: &'static str,
    button: &'static str,
    values: Vec<String>,
    /// Show this one for real when holding (screenshot).
    show: bool,
}

struct Smoke {
    step: Step,
    started: Instant,
    step_started: Instant,
    polls: u32,
    prompts: VecDeque<Expect>,
    files: VecDeque<Option<PathBuf>>,
    seen: Vec<String>,
    failure: Option<String>,
    /// The recovery code shown by the last "Your recovery code" dialog.
    recovery_code: Option<String>,
    /// The site password before the second factor was enabled.
    before: Option<String>,
}

thread_local! {
    static SMOKE: RefCell<Option<Smoke>> = const { RefCell::new(None) };
    static DIR: RefCell<Option<(PathBuf, bool)>> = const { RefCell::new(None) };
}

fn log(msg: &str) {
    eprintln!("smoke-test: {msg}");
}

fn hold() -> Option<Duration> {
    std::env::var(HOLD_ENV).ok()?.parse::<u64>().ok().map(|ms| Duration::from_millis(ms.min(30_000)))
}

/// The temporary store directory (created on first use).  `$MASTERPWD_STORE_DIR`
/// if set (then kept afterwards), else a fresh directory in the temp dir.
pub fn store_dir() -> PathBuf {
    DIR.with(|d| {
        d.borrow_mut()
            .get_or_insert_with(|| match std::env::var_os(STORE_DIR_ENV).filter(|v| !v.is_empty()) {
                Some(dir) => (PathBuf::from(dir), true),
                None => {
                    let dir = std::env::temp_dir().join(format!("masterpwd-smoke-{}", std::process::id()));
                    let _ = std::fs::remove_dir_all(&dir);
                    (dir, false)
                }
            })
            .0
            .clone()
    })
}

thread_local! {
    static CARD_PRESENCE: RefCell<Option<Arc<std::sync::atomic::AtomicBool>>> = const { RefCell::new(None) };
}

/// Ephemeral software "smart cards" (RSA-2048, P-256, P-384) for the smoke
/// test: the same wrap/unwrap code as real cards, no hardware, no PIN.
pub fn software_cards() -> Arc<dyn crate::card::SmartCards> {
    match super::smart_card::SoftwareCards::generate() {
        Ok(cards) => {
            CARD_PRESENCE.with(|p| *p.borrow_mut() = Some(cards.presence()));
            Arc::new(cards)
        }
        Err(e) => {
            log(&format!("software cards unavailable: {e}"));
            Arc::new(crate::card::NoCards)
        }
    }
}

fn set_card_present(present: bool) {
    CARD_PRESENCE.with(|p| {
        if let Some(p) = p.borrow().as_ref() {
            p.store(present, std::sync::atomic::Ordering::SeqCst);
        }
    });
}

fn card_pulled() -> bool {
    CARD_PRESENCE.with(|p| p.borrow().as_ref().is_some_and(|p| !p.load(std::sync::atomic::Ordering::SeqCst)))
}

/// Wait for a second-factor unlock to finish.
fn wait_for_unlock(started: Instant) -> Result<Option<()>, String> {
    match screen() {
        Screen::Unlocked => Ok(Some(())),
        _ if started.elapsed() > Duration::from_secs(15) => Err(format!("not unlocked: {}", vm_error())),
        Screen::Unlocking => Ok(None),
        s => Err(format!("unlock failed ({s:?}): {} / {:?}", vm_error(), with_core(|c| c.vm().view().card))),
    }
}

pub fn keychain_service() -> String {
    format!("com.github.howler4695.masterpwd.SMOKE-THROWAWAY-{}", std::process::id())
}

fn export_path() -> PathBuf {
    std::env::temp_dir().join(format!("masterpwd-smoke-export-{}.mpjson", std::process::id()))
}

fn with_smoke<R>(f: impl FnOnce(&mut Smoke) -> R) -> Option<R> {
    SMOKE.with(|s| s.borrow_mut().as_mut().map(f))
}

fn expect(title_contains: &'static str, button: &'static str, values: &[&str], show: bool) {
    with_smoke(|s| {
        s.prompts.push_back(Expect { title_contains, button, values: values.iter().map(|v| (*v).to_owned()).collect(), show })
    });
}

/// Answer a dialog from the script (called by the platform in smoke mode).
pub fn scripted_prompt(mtm: MainThreadMarker, prompt: &Prompt) -> PromptAnswer {
    let next = with_smoke(|s| {
        s.seen.push(format!("{} | {}", prompt.title, prompt.message));
        if prompt.title == "Your recovery code" {
            s.recovery_code = prompt.message.lines().next().map(str::to_owned);
        }
        s.prompts.pop_front()
    })
    .flatten();
    let Some(e) = next else {
        with_smoke(|s| s.failure = Some(format!("unexpected dialog: {:?}", prompt.title)));
        return PromptAnswer::button(usize::MAX);
    };
    if !prompt.title.contains(e.title_contains) {
        with_smoke(|s| {
            s.failure = Some(format!("expected a {:?} dialog, got {:?}: {}", e.title_contains, prompt.title, prompt.message))
        });
        return PromptAnswer::button(usize::MAX);
    }
    if !prompt.is_well_formed() {
        with_smoke(|s| s.failure = Some(format!("badly formed dialog {:?}", prompt.title)));
    }
    let Some(button) = prompt.button_index(e.button) else {
        with_smoke(|s| s.failure = Some(format!("no {:?} button in {:?}", e.button, prompt.title)));
        return PromptAnswer::button(usize::MAX);
    };
    log(&format!("dialog {:?} → {}", prompt.title, e.button));
    if let (true, Some(hold)) = (e.show, hold()) {
        log(&format!("HOLD dialog {:?}", prompt.title));
        // Shown for real; dismissed with the scripted button after `hold`.
        let parent = super::app::sites_panel_for_sheet();
        let shown = run_prompt(mtm, prompt, parent.as_deref(), Some(AutoAnswer { hold, button }));
        if shown.button != button {
            with_smoke(|s| s.failure = Some("the held dialog was answered differently".into()));
        }
    }
    // `$CODE` / `$LAST5`: the recovery code shown earlier in this run.
    let code = with_smoke(|s| s.recovery_code.clone()).flatten().unwrap_or_default();
    let values: Vec<String> = e
        .values
        .iter()
        .map(|v| match v.as_str() {
            "$CODE" => code.clone(),
            "$LAST5" => code.rsplit('-').next().unwrap_or("").to_owned(),
            other => other.to_owned(),
        })
        .collect();
    let values: Vec<&str> = values.iter().map(String::as_str).collect();
    PromptAnswer::with_values(button, &values)
}

pub fn scripted_file(request: &FileRequest) -> Option<PathBuf> {
    let next = with_smoke(|s| s.files.pop_front()).flatten();
    match next {
        Some(answer) => {
            log(&format!("file panel {:?} → {answer:?}", request.title));
            answer
        }
        None => {
            with_smoke(|s| s.failure = Some(format!("unexpected file panel {:?}", request.title)));
            None
        }
    }
}

pub fn start() {
    let now = Instant::now();
    SMOKE.with(|s| {
        *s.borrow_mut() = Some(Smoke {
            step: Step::Structure,
            started: now,
            step_started: now,
            polls: 0,
            prompts: VecDeque::new(),
            files: VecDeque::new(),
            seen: Vec::new(),
            failure: None,
            recovery_code: None,
            before: None,
        })
    });
    log(&format!("launched; store {:?}; pumping the run loop", store_dir()));
    schedule(Duration::from_secs(1));
}

fn schedule(delay: Duration) {
    super::runloop::after(delay, poll);
}

fn cleanup() -> Result<(), String> {
    shutdown();
    let kc = Keychain::with_service(&keychain_service());
    let leftover = kc.has_any(NAME);
    let _ = kc.delete_all_versions(NAME);
    let _ = std::fs::remove_file(export_path());
    let (dir, keep) = DIR.with(|d| d.borrow().clone()).unwrap_or_default();
    if !keep && !dir.as_os_str().is_empty() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    if leftover {
        return Err("keychain items were left behind (now removed)".into());
    }
    Ok(())
}

fn finish(result: Result<(), String>) -> ! {
    let cleaned = cleanup();
    match result.and(cleaned) {
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
    let Some((step, started, step_started, failure)) =
        with_smoke(|s| (s.step, s.started, s.step_started, s.failure.take()))
    else {
        return;
    };
    if let Some(f) = failure {
        finish(Err(format!("{step:?}: {f}")));
    }
    if started.elapsed() > TIMEOUT {
        finish(Err(format!("timed out in step {step:?}")));
    }
    let result = std::panic::catch_unwind(|| run_step(step, step_started));
    if let Some(f) = with_smoke(|s| s.failure.take()).flatten() {
        finish(Err(format!("{step:?}: {f}")));
    }
    match result {
        Err(_) => finish(Err(format!("panic in step {step:?}"))),
        Ok(Err(e)) => finish(Err(format!("{step:?}: {e}"))),
        Ok(Ok(None)) => {
            with_smoke(|s| s.polls += 1);
            schedule(POLL);
        }
        Ok(Ok(Some(Step::Done))) => {
            let remaining = MIN_RUNTIME.saturating_sub(started.elapsed());
            with_smoke(|s| s.step = Step::Done);
            schedule(remaining);
        }
        Ok(Ok(Some(next))) => {
            log(&format!("{step:?} ok"));
            with_smoke(|s| {
                s.step = next;
                s.step_started = Instant::now();
                s.polls = 0;
            });
            schedule(POLL);
        }
    }
}

fn check(ok: bool, what: impl Into<String>) -> Result<(), String> {
    if ok { Ok(()) } else { Err(what.into()) }
}

fn screen() -> Screen {
    with_core(|c| c.vm().screen()).unwrap_or(Screen::Pick)
}

fn vm_error() -> String {
    with_core(|c| c.vm().error().map(str::to_owned)).flatten().unwrap_or_default()
}

fn pasteboard_string() -> Option<String> {
    with_ui(|ui| ui.smoke_pasteboard.as_ref().and_then(|p| p.string())).flatten()
}

fn type_into(tag: isize, text: &str) {
    with_ui(|ui| ui.sites.set_field(tag, text));
    field_changed(tag);
}

fn open_window() {
    dispatch(|c, now| c.command(MenuCommand::Open, now));
}

fn hold_here(what: &str) {
    if let Some(hold) = hold() {
        let window = with_ui(|ui| ui.sites.window.windowNumber()).unwrap_or(-1);
        log(&format!("HOLD {what} window={window}"));
        let until = Instant::now() + hold;
        while Instant::now() < until {
            pump_run_loop(Duration::from_millis(50));
        }
    }
}

/// Wait for the unlock screen to settle; `Ok(None)` while still working.
fn wait_for(target: Screen) -> Result<Option<()>, String> {
    match screen() {
        Screen::Unlocking => Ok(None),
        s if s == target => Ok(Some(())),
        s => Err(format!("expected {target:?}, got {s:?}: {}", vm_error())),
    }
}

fn run_step(step: Step, step_started: Instant) -> Result<Option<Step>, String> {
    match step {
        Step::Structure => {
            rebuild_menu();
            let (has_button, items, welcome, placement) = with_ui(|ui| {
                (ui.status.has_button(), ui.status.menu.numberOfItems(), ui.welcome.is_visible(), ui.status.placement())
            })
            .ok_or("no UI")?;
            check(has_button, "status item has no button")?;
            check(items >= 8, format!("status menu has only {items} items"))?;
            let placement = placement.ok_or("status item has no window")?;
            log(&format!("status item placement: {placement:?}"));
            check(
                placement.is_visible(),
                format!("status item is not visible in the menu bar: {placement:?}"),
            )?;
            check(welcome, "welcome window not shown on first launch")?;
            let (hotkeys, errors) =
                with_state(|s| (s.hotkeys.as_ref().map_or(0, |h| h.count()), s.hotkey_errors.clone())).ok_or("no state")?;
            if hotkeys == 2 {
                log("both global hotkeys registered");
            } else {
                log(&format!("WARNING: {hotkeys}/2 hotkeys registered: {errors:?}"));
            }
            with_ui(|ui| ui.welcome.close());
            open_window();
            let (visible, excluded) =
                with_ui(|ui| (ui.sites.is_visible(), ui.sites.excluded_from_capture())).ok_or("no UI")?;
            check(visible, "sites window did not open")?;
            let (can_key, nonactivating, is_key) = with_ui(|ui| {
                let w = &ui.sites.window;
                (
                    w.canBecomeKeyWindow(),
                    w.styleMask().contains(objc2_app_kit::NSWindowStyleMask::NonactivatingPanel),
                    w.isKeyWindow(),
                )
            })
            .ok_or("no UI")?;
            check(can_key && nonactivating, "the sites window is not a non-activating key panel")?;
            check(is_key, "the sites window did not become key after show")?;
            let active = objc2_app_kit::NSApplication::sharedApplication(MainThreadMarker::new().ok_or("not main")?)
                .isActive();
            log(&format!("sites panel is key after show (app active: {active})"));
            let allow = std::env::var(sw::ALLOW_CAPTURE_ENV).is_ok_and(|v| v == "1");
            check(excluded != allow, format!("sharingType none = {excluded}, override = {allow}"))?;
            // WindowServer's own view: sharing state 0 = none (not capturable).
            pump_run_loop(Duration::from_millis(400));
            let number = with_ui(|ui| ui.sites.window.windowNumber() as i64).unwrap_or(-1);
            let info = cgwindow::window(number).ok_or("WindowServer does not know the sites window")?;
            let expected = if allow { 1 } else { 0 };
            check(info.sharing == expected, format!("WindowServer sharing state {} (expected {expected})", info.sharing))?;
            log(&format!("sites window excluded from capture: {excluded} (WindowServer sharing state {})", info.sharing));
            check(screen() == Screen::NewUser, format!("empty store should start at New User, got {:?}", screen()))?;
            Ok(Some(Step::CreateUser))
        }
        Step::CreateUser => {
            type_into(sw::TAG_NEW_NAME, NAME);
            type_into(sw::TAG_NEW_PASSWORD, PASSWORD);
            type_into(sw::TAG_NEW_CONFIRM, "mismatch");
            check(!with_core(|c| c.vm().view().can_create).unwrap_or(true), "mismatched passwords accepted")?;
            type_into(sw::TAG_NEW_CONFIRM, PASSWORD);
            control_action(sw::TAG_AVATAR_NEXT);
            check(text_command(sw::TAG_NEW_CONFIRM, sel!(insertNewline:)), "⏎ not handled")?;
            check(screen() == Screen::Unlocking, format!("expected Unlocking, got {:?}: {}", screen(), vm_error()))?;
            Ok(Some(Step::WaitCreate))
        }
        Step::WaitCreate => match wait_for(Screen::Unlocked)? {
            None => Ok(None),
            Some(()) => {
                let polls = with_smoke(|s| s.polls).unwrap_or(0);
                log(&format!("user created in {:?}; main thread ran {polls} polls meanwhile", step_started.elapsed()));
                check(polls >= 1, "main thread was blocked during key derivation")?;
                let file = with_core(|c| c.vm().store().list()).ok_or("no core")?.map_err(|e| e.to_string())?;
                check(file.len() == 1 && file[0].full_name == NAME && file[0].avatar == 1, format!("store: {file:?}"))?;
                Ok(Some(Step::Site))
            }
        },
        Step::Site => {
            type_into(sw::TAG_SITE, SITE);
            let result = with_core(|c| c.vm().result().map(str::to_owned)).flatten();
            check(result.as_deref() == Some(EXPECTED), format!("wrong site password {result:?}"))?;
            check(with_ui(|ui| ui.sites.displayed_result()).unwrap_or_default() == EXPECTED, "result not rendered")?;
            dispatch(|c, now| c.command(MenuCommand::ToggleHidePasswords, now));
            let masked = with_ui(|ui| ui.sites.displayed_result()).unwrap_or_default();
            check(masked == "●".repeat(EXPECTED.len()), "not masked")?;
            dispatch(|c, now| c.command(MenuCommand::ToggleHidePasswords, now));
            Ok(Some(Step::Copy))
        }
        Step::Copy => {
            check(text_command(sw::TAG_SITE, sel!(insertNewline:)), "⏎ not handled")?;
            check(pasteboard_string().as_deref() == Some(EXPECTED), "pasteboard does not hold the password")?;
            let types =
                with_ui(|ui| ui.smoke_pasteboard.as_ref().map(|p| p.type_names())).flatten().unwrap_or_default();
            check(
                types.iter().any(|t| t == CONCEALED_TYPE) && types.iter().any(|t| t == TRANSIENT_TYPE),
                format!("missing concealed/transient markers: {types:?}"),
            )?;
            check(!with_ui(|ui| ui.sites.is_visible()).unwrap_or(true), "window still open after copy")?;
            check(screen() != Screen::Unlocked, "Remember Password is off: closing should lock")?;
            check(with_core(|c| c.clipboard_holds_secret()) == Some(true), "clipboard cleared too early")?;
            Ok(Some(Step::Lock))
        }
        Step::Lock => {
            dispatch(|c, now| c.command(MenuCommand::Lock, now));
            check(pasteboard_string().is_none(), "lock did not clear the pasteboard")?;
            Ok(Some(Step::Reload))
        }
        Step::Reload => {
            // "Relaunch": flush, drop the core, open the store again from disk.
            with_core(|c| c.vm().saver().flush());
            let dir = store_dir();
            let store: Arc<dyn DataStore> = Arc::new(DiskStore::open(&dir).map_err(|e| e.to_string())?);
            let pasteboard = with_ui(|ui| ui.smoke_pasteboard.as_ref().map(|p| p.shared())).flatten().ok_or("no pb")?;
            let vm = SitesViewModel::new(SaveQueue::threaded(store));
            let core = AppCore::new(
                vm,
                Box::new(MemoryPrefs::default()),
                Box::new(pasteboard),
                Box::new(Keychain::with_service(&keychain_service())),
                Ok(()),
                LoginItemState::Unavailable("smoke test".into()),
                Instant::now(),
            );
            let cards = with_core(|c| c.cards().clone()).ok_or("no core")?;
            replace_core(core.with_cards(cards));
            let users = with_core(|c| c.vm().users().to_vec()).unwrap_or_default();
            check(users.len() == 1 && users[0].full_name == NAME, format!("after reload: {users:?}"))?;
            check(users[0].site_count == 1, format!("site not persisted: {users:?}"))?;
            check(screen() == Screen::Pick, "after reload the picker should show")?;
            open_window();
            hold_here("picker");
            Ok(Some(Step::WrongPassword))
        }
        Step::WrongPassword => {
            type_into(sw::TAG_MASTER_PASSWORD, "not my password");
            check(text_command(sw::TAG_MASTER_PASSWORD, sel!(insertNewline:)), "⏎ not handled")?;
            Ok(Some(Step::WaitWrong))
        }
        Step::WaitWrong => match wait_for(Screen::Pick)? {
            None => Ok(None),
            Some(()) => {
                let e = vm_error();
                check(e.contains("Incorrect master password"), format!("wrong password not rejected: {e:?}"))?;
                check(
                    with_ui(|ui| ui.sites.text_of(sw::TAG_MASTER_PASSWORD)).flatten().is_some_and(|s| s.length() == 0),
                    "password field not cleared",
                )?;
                Ok(Some(Step::Unlock))
            }
        },
        Step::Unlock => {
            type_into(sw::TAG_MASTER_PASSWORD, PASSWORD);
            check(text_command(sw::TAG_MASTER_PASSWORD, sel!(insertNewline:)), "⏎ not handled")?;
            Ok(Some(Step::WaitUnlock))
        }
        Step::WaitUnlock => match wait_for(Screen::Unlocked)? {
            None => Ok(None),
            Some(()) => {
                let uses = with_core(|c| c.vm().user().and_then(|u| u.site(SITE)).map(|s| s.uses)).flatten();
                check(uses == Some(1), format!("use count not persisted: {uses:?}"))?;
                Ok(Some(Step::AddSites))
            }
        },
        Step::AddSites => {
            dispatch(|c, now| c.command(MenuCommand::ToggleRememberPassword, now));
            for site in ["github.com", "apple.com", "news.ycombinator.com"] {
                open_window();
                type_into(sw::TAG_SITE, site);
                check(text_command(sw::TAG_SITE, sel!(insertNewline:)), "⏎ not handled")?;
            }
            check(screen() == Screen::Unlocked, "Remember Password on: still unlocked")?;
            open_window();
            let rows = with_core(|c| c.vm().view().candidates.len()).unwrap_or(0);
            check(rows == 4, format!("site list should list 4 sites, has {rows}"))?;
            // ⇧⏎ path: copy the login name.
            let login = with_core(|c| {
                c.vm_event(Instant::now(), |vm| {
                    vm.set_site_query("github.com");
                    vm.set_purpose(mpw_core::KeyPurpose::Identification);
                    Vec::new()
                });
                c.vm().result().map(str::to_owned)
            })
            .flatten();
            dispatch(|c, now| {
                c.vm_event(now, |vm| {
                    vm.set_purpose(mpw_core::KeyPurpose::Authentication);
                    vm.copy(crate::view_model::CopyWhat::Login)
                })
            });
            check(login.is_some() && pasteboard_string() == login, "⇧⏎ did not copy the login name")?;
            open_window();
            type_into(sw::TAG_SITE, "");
            hold_here("unlocked");
            Ok(Some(Step::ExportImport))
        }
        Step::ExportImport => {
            let path = export_path();
            with_smoke(|s| s.files.push_back(Some(path.clone())));
            dispatch(|c, now| c.command(MenuCommand::ExportSecure, now));
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).map_err(|e| format!("no export: {e}"))?.permissions().mode() & 0o777;
            check(mode == 0o600, format!("export mode {mode:o}"))?;
            // Delete a site, then merge the export back in.
            open_window();
            type_into(sw::TAG_SITE, SITE);
            expect("Delete", "Delete", &[], false);
            control_action(sw::TAG_DELETE_SITE);
            check(with_core(|c| c.vm().user().is_some_and(|u| u.site(SITE).is_none())) == Some(true), "site not deleted")?;
            expect("already exists", "Merge", &[], true);
            expect("Merged into", "OK", &[], false);
            with_smoke(|s| s.files.push_back(Some(path.clone())));
            dispatch(|c, now| c.command(MenuCommand::ImportSites, now));
            let summary = with_smoke(|s| s.seen.last().cloned()).flatten().unwrap_or_default();
            check(summary.contains(&format!("Added 1: {SITE}")), format!("merge summary: {summary:?}"))?;
            check(with_core(|c| c.vm().user().is_some_and(|u| u.site(SITE).is_some())) == Some(true), "site not merged back")?;
            Ok(Some(Step::SaveKeys))
        }
        Step::SaveKeys => {
            let kc = Keychain::with_service(&keychain_service());
            dispatch(|c, now| c.command(MenuCommand::ToggleSavePassword, now));
            check(kc.has_any(NAME), format!("no keys in the keychain: {}", vm_error()))?;
            dispatch(|c, now| c.command(MenuCommand::Lock, now));
            check(with_core(|c| c.vm().view().can_quick_unlock) == Some(true), "no quick unlock offered")?;
            control_action(sw::TAG_QUICK_UNLOCK);
            Ok(Some(Step::WaitQuickUnlock))
        }
        Step::WaitQuickUnlock => {
            if screen() != Screen::Unlocked {
                if step_started.elapsed() > Duration::from_secs(5) {
                    return Err(format!("quick unlock did not unlock: {}", vm_error()));
                }
                return Ok(None);
            }
            log("unlocked from saved keys after the (stubbed) device-owner check");
            dispatch(|c, now| c.command(MenuCommand::ToggleSavePassword, now));
            check(!Keychain::with_service(&keychain_service()).has_any(NAME), "keys not purged")?;
            Ok(Some(Step::ChangePassword))
        }
        Step::ChangePassword => {
            // Save keys again, so we can check the change purges them.
            dispatch(|c, now| c.command(MenuCommand::ToggleSavePassword, now));
            check(Keychain::with_service(&keychain_service()).has_any(NAME), "keys not saved")?;
            expect("Change", "Change Master Password", &[PASSWORD, NEW_PASSWORD, NEW_PASSWORD], false);
            expect("was changed", "OK", &[], false);
            dispatch(|c, now| c.command(MenuCommand::ChangeMasterPassword, now));
            Ok(Some(Step::WaitChange))
        }
        Step::WaitChange => {
            if with_smoke(|s| s.prompts.is_empty()) != Some(true) {
                if step_started.elapsed() > Duration::from_secs(10) {
                    return Err("the change never completed".into());
                }
                return Ok(None);
            }
            check(!Keychain::with_service(&keychain_service()).has_any(NAME), "saved keys not purged by the change")?;
            open_window();
            type_into(sw::TAG_SITE, SITE);
            let result = with_core(|c| c.vm().result().map(str::to_owned)).flatten();
            check(result.is_some() && result.as_deref() != Some(EXPECTED), "the password did not change")?;
            dispatch(|c, now| c.command(MenuCommand::Lock, now));
            open_window();
            type_into(sw::TAG_MASTER_PASSWORD, NEW_PASSWORD);
            check(text_command(sw::TAG_MASTER_PASSWORD, sel!(insertNewline:)), "⏎ not handled")?;
            Ok(Some(Step::WaitNewUnlock))
        }
        Step::WaitNewUnlock => match wait_for(Screen::Unlocked)? {
            None => Ok(None),
            Some(()) => {
                log("unlocked with the new master password after reload from disk");
                Ok(Some(Step::SfEnable))
            }
        },
        Step::SfEnable => {
            open_window();
            type_into(sw::TAG_SITE, SITE);
            let before = with_core(|c| c.vm().result().map(str::to_owned)).flatten();
            with_smoke(|s| s.before = before);
            expect("Require a smart card", "Continue…", &[], true);
            expect("Use this smart card", "Use This Card", &[], false);
            expect("Your recovery code", "I Have Saved It", &[], true);
            expect("Confirm and turn on", "Turn On Second Factor", &["$LAST5", NEW_PASSWORD], false);
            expect("Second factor turned on", "OK", &[], false);
            dispatch(|c, now| c.command(MenuCommand::EnableSecondFactor, now));
            Ok(Some(Step::SfWaitEnable))
        }
        Step::SfWaitEnable => {
            let enabled = with_core(|c| c.session_has_second_factor()).unwrap_or(false);
            if !enabled || with_smoke(|s| !s.prompts.is_empty()).unwrap_or(true) {
                return if step_started.elapsed() > Duration::from_secs(15) {
                    Err(format!("second factor not enabled: {:?}", with_smoke(|s| s.seen.last().cloned())))
                } else {
                    Ok(None)
                };
            }
            let code = with_smoke(|s| s.recovery_code.clone()).flatten().unwrap_or_default();
            check(code.len() == 41 && code.matches('-').count() == 6, format!("recovery code format: {} chars", code.len()))?;
            open_window();
            type_into(sw::TAG_SITE, SITE);
            let after = with_core(|c| c.vm().result().map(str::to_owned)).flatten();
            let before = with_smoke(|s| s.before.clone()).flatten();
            check(after.is_some() && after != before, "enabling did not change the generated password")?;
            check(!Keychain::with_service(&keychain_service()).has_any(NAME), "saved keys not purged")?;
            let slots = with_core(|c| c.vm().user().and_then(|u| u.second_factor_status().second_factor().map(|f| f.slots().len())))
                .flatten();
            check(slots == Some(1), format!("slots after enable: {slots:?}"))?;
            log("second factor enabled with the software card (verified by one unwrap); password changed");
            Ok(Some(Step::SfCardUnlock))
        }
        Step::SfCardUnlock => {
            dispatch(|c, now| c.command(MenuCommand::Lock, now));
            open_window();
            let row = with_core(|c| c.vm().view().users.first().map(|u| u.second_factor)).flatten();
            check(row == Some(true), "the user picker does not show that a card is required")?;
            type_into(sw::TAG_MASTER_PASSWORD, NEW_PASSWORD);
            check(text_command(sw::TAG_MASTER_PASSWORD, sel!(insertNewline:)), "⏎ not handled")?;
            Ok(Some(Step::SfWaitCardUnlock))
        }
        Step::SfWaitCardUnlock => match wait_for_unlock(step_started)? {
            None => Ok(None),
            Some(()) => {
                type_into(sw::TAG_SITE, SITE);
                let r = with_core(|c| c.vm().result().map(str::to_owned)).flatten();
                check(r.is_some() && r != with_smoke(|s| s.before.clone()).flatten(), "wrong keys after card unlock")?;
                log("unlocked with password + software card");
                Ok(Some(Step::SfCodeUnlock))
            }
        },
        Step::SfCodeUnlock => {
            dispatch(|c, now| c.command(MenuCommand::Lock, now));
            set_card_present(false);
            open_window();
            type_into(sw::TAG_MASTER_PASSWORD, NEW_PASSWORD);
            check(text_command(sw::TAG_MASTER_PASSWORD, sel!(insertNewline:)), "⏎ not handled")?;
            let waiting = with_core(|c| c.vm().view().card.map(|p| p.note)).flatten().unwrap_or_default();
            check(waiting.contains("Insert your smart card"), format!("no 'insert your card' state: {waiting:?}"))?;
            hold_here("insert-card");
            expect("Recovery code", "Continue", &["00000-00000-00000-00000-00000-00000-00000"], false);
            expect("Recovery code", "Continue", &["$CODE"], false);
            control_action(sw::TAG_RECOVERY_CODE);
            let seen = with_smoke(|s| s.seen.last().cloned()).flatten().unwrap_or_default();
            check(seen.contains("mistyped") || seen.contains("checksum"), format!("wrong code not rejected: {seen:?}"))?;
            Ok(Some(Step::SfWaitCodeUnlock))
        }
        Step::SfWaitCodeUnlock => match wait_for_unlock(step_started)? {
            None => Ok(None),
            Some(()) => {
                log("unlocked with password + recovery code (a wrong code was rejected first)");
                Ok(Some(Step::SfRemoval))
            }
        },
        Step::SfRemoval => {
            set_card_present(true);
            dispatch(|c, now| c.command(MenuCommand::Lock, now));
            open_window();
            type_into(sw::TAG_MASTER_PASSWORD, NEW_PASSWORD);
            check(text_command(sw::TAG_MASTER_PASSWORD, sel!(insertNewline:)), "⏎ not handled")?;
            Ok(Some(Step::SfWaitRemovalLock))
        }
        Step::SfWaitRemovalLock => {
            match screen() {
                Screen::Unlocked if !card_pulled() => {
                    set_card_present(false);
                    with_smoke(|s| s.polls = 0);
                    Ok(None)
                }
                Screen::Unlocked => {
                    if step_started.elapsed() > Duration::from_secs(10) {
                        Err("not locked after the card was removed".into())
                    } else {
                        Ok(None)
                    }
                }
                Screen::Unlocking if !card_pulled() => Ok(None),
                Screen::Pick if card_pulled() => {
                    log("locked when the software card was removed");
                    set_card_present(true);
                    Ok(Some(Step::SfAdd))
                }
                s => Err(format!("unexpected screen {s:?}: {}", vm_error())),
            }
        }
        Step::SfAdd => {
            open_window();
            type_into(sw::TAG_MASTER_PASSWORD, NEW_PASSWORD);
            check(text_command(sw::TAG_MASTER_PASSWORD, sel!(insertNewline:)), "⏎ not handled")?;
            Ok(Some(Step::SfWaitAdd))
        }
        Step::SfWaitAdd => {
            let slots = || {
                with_core(|c| c.vm().user().and_then(|u| u.second_factor_status().second_factor().map(|f| f.slots().len())))
                    .flatten()
            };
            if screen() != Screen::Unlocked {
                return wait_for_unlock(step_started).map(|_| None);
            }
            if with_smoke(|s| s.prompts.is_empty() && s.recovery_code.is_some() && s.before.is_some()) == Some(true)
                && slots() == Some(1)
                && with_smoke(|s| !s.seen.iter().any(|m| m.starts_with("Add this smart card"))) == Some(true)
            {
                expect("Add this smart card", "Add This Card", &[], false);
                dispatch(|c, now| c.command(MenuCommand::AddSmartCard, now));
                return Ok(None);
            }
            match slots() {
                Some(2) => {
                    log("second card added (verified by one unwrap)");
                    expect("Remove", "Remove", &[], false);
                    dispatch(|c, now| c.command(MenuCommand::RemoveSlot(1), now));
                    check(slots() == Some(1), "card not removed")?;
                    log("second card removed");
                    Ok(Some(Step::SfDisable))
                }
                _ if step_started.elapsed() > Duration::from_secs(15) => Err(format!("card not added: {}", vm_error())),
                _ => Ok(None),
            }
        }
        Step::SfDisable => {
            expect("Turn off the second factor", "Turn Off…", &[NEW_PASSWORD], false);
            expect("Second factor turned off", "OK", &[], false);
            dispatch(|c, now| c.command(MenuCommand::DisableSecondFactor, now));
            Ok(Some(Step::SfWaitDisable))
        }
        Step::SfWaitDisable => {
            if with_core(|c| c.session_has_second_factor()).unwrap_or(true) {
                return if step_started.elapsed() > Duration::from_secs(15) {
                    Err(format!("not disabled: {:?}", with_smoke(|s| s.seen.last().cloned())))
                } else {
                    Ok(None)
                };
            }
            open_window();
            type_into(sw::TAG_SITE, SITE);
            let r = with_core(|c| c.vm().result().map(str::to_owned)).flatten();
            check(r.is_some() && r == with_smoke(|s| s.before.clone()).flatten(), "passwords did not change back")?;
            log("second factor turned off; passwords are back");
            Ok(Some(Step::Identicon))
        }
        Step::Identicon => {
            dispatch(|c, now| c.command(MenuCommand::Lock, now));
            open_window();
            type_into(sw::TAG_MASTER_PASSWORD, PASSWORD);
            check(with_core(|c| c.vm().view().identicon.is_none()) == Some(true), "identicon before the pause")?;
            Ok(Some(Step::WaitIdenticon))
        }
        Step::WaitIdenticon => {
            if with_core(|c| c.vm().view().identicon.is_some()).unwrap_or(false) {
                log("identicon appeared after the typing pause");
                log(&format!("bundled: {}; login item: {:?}", super::is_bundled(), login_item::state()));
                {
                    use super::local_auth::{DeviceAuthenticator, LocalAuth};
                    log(&format!("real LocalAuthentication availability (not prompted): {:?}", LocalAuth.availability()));
                }
                let pending = with_smoke(|s| s.prompts.len()).unwrap_or(0);
                check(pending == 0, format!("{pending} scripted dialogs never appeared"))?;
                Ok(Some(Step::Done))
            } else if step_started.elapsed() > Duration::from_secs(5) {
                Err("identicon never appeared".into())
            } else {
                Ok(None)
            }
        }
        Step::Done => finish(Ok(())),
    }
}
