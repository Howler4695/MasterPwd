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
        s.prompts.pop_front()
    })
    .flatten();
    let Some(e) = next else {
        with_smoke(|s| s.failure = Some(format!("unexpected dialog: {:?}", prompt.title)));
        return PromptAnswer::button(usize::MAX);
    };
    if !prompt.title.contains(e.title_contains) {
        with_smoke(|s| s.failure = Some(format!("expected a {:?} dialog, got {:?}", e.title_contains, prompt.title)));
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
        let shown = run_prompt(mtm, prompt, Some(AutoAnswer { hold, button }));
        if shown.button != button {
            with_smoke(|s| s.failure = Some("the held dialog was answered differently".into()));
        }
    }
    let values: Vec<&str> = e.values.iter().map(String::as_str).collect();
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
            replace_core(core);
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
