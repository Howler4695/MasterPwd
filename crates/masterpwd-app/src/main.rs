//! Master Password for macOS.
//!
//! Hidden flags: `--smoke-test` (self-test, exits 0/1) and `--show` (open the
//! sites window at launch).  Anything else is ignored (macOS may pass its own
//! arguments, e.g. `-psn_…` or `-NSDocumentRevisionsDebugMode`).
//!
//! Test/review-only environment variables:
//! - `MASTERPWD_STORE_DIR=<dir>`: use `<dir>` as the user store instead of
//!   `~/Library/Application Support/MasterPwd/Users` (the container's when
//!   sandboxed).  The smoke test uses a fresh temporary directory unless this
//!   is set, in which case it uses (and keeps) `<dir>`.
//! - `MASTERPWD_ALLOW_SCREEN_CAPTURE=1`: don't exclude the sites window from
//!   screenshots / screen sharing.
//! - `MASTERPWD_SMOKE_HOLD_MS=<ms>`: the smoke test pauses at the user picker,
//!   the unlocked window and the import dialog, for screenshots.

#[cfg(target_os = "macos")]
fn main() {
    use masterpwd_app::platform::app::{run, LaunchMode};
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = if args.iter().any(|a| a == "--smoke-test") {
        LaunchMode::SmokeTest
    } else if args.iter().any(|a| a == "--show") {
        LaunchMode::Show
    } else {
        LaunchMode::Normal
    };
    std::process::exit(run(mode));
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("MasterPwd is a macOS app.");
    std::process::exit(1);
}
