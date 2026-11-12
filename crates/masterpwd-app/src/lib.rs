//! Master Password for macOS: a native AppKit menu-bar app.
//!
//! Layout:
//! - Safe, unit-tested logic with no AppKit types: [`data`] (the data-layer
//!   seam), [`view_model`] (the sites window state machine), [`core`] (lock
//!   policy, preferences, clipboard, menu), [`clipboard`], [`prefs`], [`menu`].
//! - [`platform`]: the thin AppKit/Carbon/Security layer.  All `unsafe` lives
//!   there; it renders state and forwards events, it decides nothing.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod clipboard;
pub mod core;
pub mod data;
pub mod menu;
pub mod prefs;
pub mod view_model;

#[cfg(target_os = "macos")]
pub mod platform;

/// The bundle identifier, also used as the defaults domain and keychain
/// service prefix.
pub const BUNDLE_ID: &str = "com.github.howler4695.masterpwd";
