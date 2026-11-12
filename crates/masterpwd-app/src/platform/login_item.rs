//! "Open at Login" through `SMAppService.mainApp` (macOS 13+).
//!
//! Replaces the original's separate LoginHelper bundle and the deprecated
//! `SMLoginItemSetEnabled` / `SMCopyAllJobDictionaries` calls.  Only works for
//! a bundled, signed app; otherwise the menu item is disabled with a tooltip.

use objc2::runtime::AnyClass;
use objc2_service_management::{SMAppService, SMAppServiceStatus};

use crate::core::LoginItemState;

fn available() -> Result<(), String> {
    if !super::is_bundled() {
        return Err("Open at Login works only from the bundled Master Password.app.".into());
    }
    if AnyClass::get(c"SMAppService").is_none() {
        return Err("Open at Login requires macOS 13 or later.".into());
    }
    Ok(())
}

pub fn state() -> LoginItemState {
    if let Err(why) = available() {
        return LoginItemState::Unavailable(why);
    }
    // SAFETY: the class exists (checked above); `mainAppService` and `status`
    // take no arguments and are documented as safe to call from any thread.
    let status = unsafe { SMAppService::mainAppService().status() };
    match status {
        SMAppServiceStatus::Enabled => LoginItemState::Enabled,
        SMAppServiceStatus::RequiresApproval => LoginItemState::RequiresApproval,
        // NotRegistered, NotFound (e.g. app not in /Applications yet).
        _ => LoginItemState::Disabled,
    }
}

/// Register or unregister; returns the new state and an error message.
pub fn set_enabled(enabled: bool) -> (LoginItemState, Option<String>) {
    if let Err(why) = available() {
        return (LoginItemState::Unavailable(why.clone()), Some(why));
    }
    // SAFETY: as in `state`; the calls report failure through NSError.
    let result = unsafe {
        let service = SMAppService::mainAppService();
        if enabled {
            service.registerAndReturnError()
        } else {
            service.unregisterAndReturnError()
        }
    };
    let error = result.err().map(|e| e.localizedDescription().to_string());
    (state(), error)
}

/// Open System Settings ▸ Login Items (when approval is required).
pub fn open_settings() {
    if available().is_ok() {
        // SAFETY: class exists; no arguments.
        unsafe { SMAppService::openSystemSettingsLoginItems() };
    }
}
