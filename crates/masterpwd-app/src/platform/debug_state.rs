//! Debug/test aid: with `MASTERPWD_DEBUG_STATE_FILE=<path>` the app writes its
//! focus and screen state to `<path>` on every change, so an external test
//! can check that our window really has the keyboard *before* it types
//! anything.  Nothing secret is written (the result only as its length).

use std::cell::RefCell;
use std::path::PathBuf;

pub const ENV: &str = "MASTERPWD_DEBUG_STATE_FILE";

thread_local! {
    static PATH: Option<PathBuf> = std::env::var_os(ENV).filter(|v| !v.is_empty()).map(PathBuf::from);
    static LAST: RefCell<String> = const { RefCell::new(String::new()) };
}

pub fn enabled() -> bool {
    PATH.with(Option::is_some)
}

/// Write `lines` (key=value) if they changed.  Atomic (temp file + rename).
pub fn write(lines: &[(&str, String)]) {
    let Some(path) = PATH.with(Clone::clone) else { return };
    let text: String = lines.iter().map(|(k, v)| format!("{k}={}\n", v.replace('\n', " "))).collect();
    let changed = LAST.with(|last| {
        let mut last = last.borrow_mut();
        if *last == text {
            false
        } else {
            last.clone_from(&text);
            true
        }
    });
    if changed {
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, &text).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}
