//! The thin platform layer: AppKit, Carbon, Security and ServiceManagement.
//!
//! Every `unsafe` block of the crate lives below this module, each with a
//! comment saying why it is sound.  Nothing here makes decisions: events go to
//! [`crate::core::AppCore`], and its state is rendered back.

pub mod app;
pub mod avatars;
pub mod cgwindow;
pub mod dialogs;
pub mod defaults;
pub mod hotkey;
pub mod keychain;
pub mod local_auth;
pub mod login_item;
pub mod pasteboard;
pub mod runloop;
pub mod sites_window;
pub mod smoke;
pub mod status_item;
pub mod system_events;
pub mod welcome_window;

use objc2_foundation::{NSBundle, NSString};

/// Is this process running from a `.app` bundle (as opposed to `cargo run`)?
pub fn is_bundled() -> bool {
    let bundle = NSBundle::mainBundle();
    let has_id = bundle.bundleIdentifier().is_some();
    has_id && bundle.bundlePath().to_string().ends_with(".app")
}

/// Shorthand for a temporary `NSString`.
pub(crate) fn ns(s: &str) -> objc2::rc::Retained<NSString> {
    NSString::from_str(s)
}
