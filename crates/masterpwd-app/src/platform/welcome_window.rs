//! The first-launch welcome window (the original's `MPInitialWindow.xib`):
//! explains the hotkey and the menu-bar icon, offers "Open at Login".

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{sel, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSBackingStoreType, NSButton, NSControlStateValueOff, NSControlStateValueOn, NSFont,
    NSImage, NSImageView, NSTextField, NSWindow, NSWindowDelegate, NSWindowStyleMask,
};
use objc2_foundation::{NSPoint, NSRect, NSSize};

use super::ns;
use crate::core::LoginItemState;

pub const TAG_WELCOME_LOGIN: isize = 100;
pub const TAG_WELCOME_DONE: isize = 101;
pub const TAG_WELCOME_OPEN: isize = 102;

const TEXT: &str = "Master Password lives in your menu bar: look for the lock icon next to the clock.\n\n\
To begin, press ⌃⌘P (control, command and P) anywhere, or choose Open from that menu. \
Type your full name and your master password, then the name of a site: its password is \
computed on the spot.  Press ⏎ to copy it; the clipboard is cleared again after a minute.\n\n\
Your passwords are not stored anywhere, and this app never connects to the network.";

fn rect(x: f64, y: f64, w: f64, h: f64) -> NSRect {
    NSRect::new(NSPoint::new(x, y), NSSize::new(w, h))
}

pub struct WelcomeWindow {
    pub window: Retained<NSWindow>,
    open_at_login: Retained<NSButton>,
    mtm: MainThreadMarker,
}

impl WelcomeWindow {
    pub fn new(mtm: MainThreadMarker, target: &AnyObject, delegate: &ProtocolObject<dyn NSWindowDelegate>) -> Self {
        // SAFETY: designated initializer with valid arguments.
        let window = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                NSWindow::alloc(mtm),
                rect(0.0, 0.0, 500.0, 330.0),
                NSWindowStyleMask::Titled | NSWindowStyleMask::Closable,
                NSBackingStoreType::Buffered,
                false,
            )
        };
        // SAFETY: we hold our own strong reference.
        unsafe { window.setReleasedWhenClosed(false) };
        window.setTitle(&ns("Welcome to Master Password"));
        window.setDelegate(Some(delegate));
        window.center();
        let content = window.contentView().expect("a titled window has a content view");

        let icon = NSImageView::initWithFrame(NSImageView::alloc(mtm), rect(20.0, 222.0, 88.0, 88.0));
        if let Some(app_icon) = NSImage::imageNamed(&ns("NSApplicationIcon")) {
            icon.setImage(Some(&app_icon));
        }
        content.addSubview(&icon);
        let title = NSTextField::labelWithString(&ns("Welcome to Master Password"), mtm);
        title.setFont(Some(&NSFont::boldSystemFontOfSize(20.0)));
        title.setFrame(rect(124.0, 262.0, 360.0, 28.0));
        content.addSubview(&title);
        let body = NSTextField::wrappingLabelWithString(&ns(TEXT), mtm);
        body.setFont(Some(&NSFont::systemFontOfSize(13.0)));
        body.setFrame(rect(124.0, 70.0, 356.0, 186.0));
        content.addSubview(&body);

        // SAFETY: `target` (the app delegate) implements `uiAction:`.
        let (open_at_login, open, done) = unsafe {
            (
                NSButton::checkboxWithTitle_target_action(&ns("Open at Login"), Some(target), Some(sel!(uiAction:)), mtm),
                NSButton::buttonWithTitle_target_action(&ns("Open Now"), Some(target), Some(sel!(uiAction:)), mtm),
                NSButton::buttonWithTitle_target_action(&ns("Done"), Some(target), Some(sel!(uiAction:)), mtm),
            )
        };
        open_at_login.setTag(TAG_WELCOME_LOGIN);
        open_at_login.setFrame(rect(124.0, 24.0, 160.0, 24.0));
        content.addSubview(&open_at_login);
        open.setTag(TAG_WELCOME_OPEN);
        open.setFrame(rect(290.0, 18.0, 100.0, 32.0));
        content.addSubview(&open);
        done.setTag(TAG_WELCOME_DONE);
        done.setFrame(rect(390.0, 18.0, 96.0, 32.0));
        done.setKeyEquivalent(&ns("\r"));
        content.addSubview(&done);

        Self { window, open_at_login, mtm }
    }

    pub fn render(&self, login: &LoginItemState) {
        let (enabled, on, tip) = match login {
            LoginItemState::Unavailable(why) => (false, false, Some(why.as_str())),
            LoginItemState::Disabled => (true, false, None),
            LoginItemState::Enabled => (true, true, None),
            LoginItemState::RequiresApproval => (true, true, Some("Approve it in System Settings ▸ Login Items.")),
        };
        self.open_at_login.setEnabled(enabled);
        self.open_at_login.setState(if on { NSControlStateValueOn } else { NSControlStateValueOff });
        self.open_at_login.setToolTip(tip.map(ns).as_deref());
    }

    pub fn show(&self) {
        #[allow(deprecated)]
        NSApplication::sharedApplication(self.mtm).activateIgnoringOtherApps(true);
        self.window.makeKeyAndOrderFront(None);
    }

    pub fn close(&self) {
        if self.window.isVisible() {
            self.window.close();
        }
    }

    pub fn is_visible(&self) -> bool {
        self.window.isVisible()
    }
}
