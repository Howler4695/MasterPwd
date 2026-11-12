//! Secure Event Input (`EnableSecureEventInput`): while it is on, no other
//! process can read keystrokes (event taps / keyloggers get nothing).
//!
//! `NSSecureTextField` turns it on by itself only while its app is *active*.
//! Our sites panel takes the keyboard without activating the app, so we turn
//! it on ourselves while the panel (or a sheet on it) has the keyboard on a
//! screen where passwords are typed, and off again as soon as it doesn't.
//! The calls are reference-counted by the system; we keep ours balanced.

use std::cell::Cell;

#[link(name = "Carbon", kind = "framework")]
extern "C" {
    fn EnableSecureEventInput() -> i32;
    fn DisableSecureEventInput() -> i32;
    fn IsSecureEventInputEnabled() -> u8;
}

thread_local! {
    static ON: Cell<bool> = const { Cell::new(false) };
}

/// Turn our secure input on or off (idempotent).
pub fn set(wanted: bool) {
    ON.with(|on| {
        if on.get() == wanted {
            return;
        }
        // SAFETY: plain Carbon calls without arguments; balanced by `ON`.
        unsafe {
            if wanted {
                EnableSecureEventInput();
            } else {
                DisableSecureEventInput();
            }
        }
        on.set(wanted);
    });
}

/// Whether we hold secure input.
pub fn ours() -> bool {
    ON.with(Cell::get)
}

/// Whether secure input is on system-wide (by us or anyone).
pub fn system() -> bool {
    // SAFETY: plain Carbon call without arguments.
    unsafe { IsSecureEventInputEnabled() != 0 }
}
