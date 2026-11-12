//! Subscribes the app delegate to the system events that must lock the app:
//! sleep, display sleep, screen lock, screensaver and fast user switching.
//! The delegate's handler methods live in `platform::app`.

use objc2::runtime::AnyObject;
use objc2::sel;
use objc2_app_kit::{
    NSWorkspace, NSWorkspaceScreensDidSleepNotification, NSWorkspaceSessionDidResignActiveNotification,
    NSWorkspaceWillSleepNotification,
};
use objc2_foundation::NSDistributedNotificationCenter;

use super::ns;

/// Distributed notifications posted by loginwindow / screensaver.
pub const SCREEN_LOCKED: &str = "com.apple.screenIsLocked";
pub const SCREENSAVER_STARTED: &str = "com.apple.screensaver.didstart";

/// Register `observer` (which must implement the selectors named here and
/// outlive the registration — the app delegate lives for the whole process).
pub fn observe(observer: &AnyObject) {
    let workspace = NSWorkspace::sharedWorkspace().notificationCenter();
    // SAFETY: `observer` responds to each selector with the signature
    // `-(void)x:(NSNotification *)n` (see `AppDelegate`) and is never
    // deallocated; the notification names are framework constants.
    unsafe {
        workspace.addObserver_selector_name_object(
            observer,
            sel!(systemWillSleep:),
            Some(NSWorkspaceWillSleepNotification),
            None,
        );
        workspace.addObserver_selector_name_object(
            observer,
            sel!(screensDidSleep:),
            Some(NSWorkspaceScreensDidSleepNotification),
            None,
        );
        workspace.addObserver_selector_name_object(
            observer,
            sel!(sessionDidResignActive:),
            Some(NSWorkspaceSessionDidResignActiveNotification),
            None,
        );
        let distributed = NSDistributedNotificationCenter::defaultCenter();
        distributed.addObserver_selector_name_object(observer, sel!(screenLocked:), Some(&ns(SCREEN_LOCKED)), None);
        distributed.addObserver_selector_name_object(
            observer,
            sel!(screensaverStarted:),
            Some(&ns(SCREENSAVER_STARTED)),
            None,
        );
    }
}
