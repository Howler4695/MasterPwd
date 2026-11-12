//! Master Password for macOS: a native AppKit menu-bar app.
//!
//! Layout:
//! - Safe, unit-tested logic with no AppKit types: [`data`] (the storage
//!   seam over `mpw-model`), [`keys`] (off-thread key derivation, saved-key
//!   vault seam), [`view_model`] (the sites window state machine), [`core`]
//!   (lock policy, preferences, clipboard, menu, import/export/keychain
//!   flows), [`prompt`] (dialogs as data), [`clipboard`], [`prefs`], [`menu`].
//! - [`platform`]: the thin AppKit/Carbon/Security layer.  All `unsafe` lives
//!   there; it renders state and forwards events, it decides nothing.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod clipboard;
pub mod core;
pub mod data;
pub mod keys;
pub mod menu;
pub mod prefs;
pub mod prompt;
pub mod view_model;

#[cfg(target_os = "macos")]
pub mod platform;

/// In-order, case-insensitive character match (`gml` matches `gmail.com`),
/// like the original's `*g*m*l*` LIKE pattern.
pub fn fuzzy_matches(name: &str, query: &str) -> bool {
    let mut haystack = name.chars().flat_map(char::to_lowercase);
    query.chars().flat_map(char::to_lowercase).all(|q| haystack.any(|h| h == q))
}

/// The bundle identifier, also used as the defaults domain and keychain
/// service prefix.
pub const BUNDLE_ID: &str = "com.github.howler4695.masterpwd";
