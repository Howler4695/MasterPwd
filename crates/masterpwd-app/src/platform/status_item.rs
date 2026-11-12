//! The menu-bar status item and its menu, rendered from [`crate::menu`].

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{sel, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSControlStateValueOff, NSControlStateValueOn, NSEventModifierFlags, NSImage, NSMenu, NSMenuDelegate,
    NSAccessibility, NSMenuItem, NSScreen, NSStatusBar, NSStatusItem, NSVariableStatusItemLength,
};

use super::ns;
use crate::menu::{MenuEntry, MenuItem};

/// WindowServer's status-bar window level (`kCGStatusWindowLevel`).
const STATUS_LAYER: i64 = 25;

/// Where the status item is.  On macOS 26 status items are drawn by Control
/// Center: WindowServer lists a Control Center–owned window at the status
/// level with our item's frame (and reports *every* menu-bar item, the clock
/// included, as not "on screen"), so "visible" here means: AppKit says it is
/// visible, a status-level window with exactly our frame exists, the frame is
/// on a screen, and it is not hidden behind the camera notch.
#[derive(Debug, Clone, PartialEq)]
pub struct Placement {
    /// x, y, width, height in WindowServer coordinates.
    pub frame: (f64, f64, f64, f64),
    /// (owner pid, window number) of the status-level window at our frame.
    pub hosted_by: Option<(i64, i64)>,
    pub on_a_screen: bool,
    pub under_notch: bool,
    pub app_kit_visible: bool,
}

impl Placement {
    pub fn is_visible(&self) -> bool {
        self.app_kit_visible && self.hosted_by.is_some() && self.on_a_screen && !self.under_notch
    }
}

pub struct StatusItem {
    pub item: Retained<NSStatusItem>,
    pub menu: Retained<NSMenu>,
    mtm: MainThreadMarker,
}

fn symbol(name: &str) -> Option<Retained<NSImage>> {
    let image = NSImage::imageWithSystemSymbolName_accessibilityDescription(&ns(name), Some(&ns("Master Password")))?;
    image.setTemplate(true);
    Some(image)
}

impl StatusItem {
    /// `delegate` receives `menuNeedsUpdate:` (to rebuild) and is the target
    /// of every item's `menuAction:`.
    pub fn new(mtm: MainThreadMarker, delegate: &ProtocolObject<dyn NSMenuDelegate>) -> Self {
        let item = NSStatusBar::systemStatusBar().statusItemWithLength(NSVariableStatusItemLength);
        let menu = NSMenu::initWithTitle(NSMenu::alloc(mtm), &ns("Master Password"));
        menu.setAutoenablesItems(false);
        menu.setDelegate(Some(delegate));
        item.setMenu(Some(&menu));
        item.setAutosaveName(Some(&ns("MasterPassword")));
        item.setVisible(true);
        if let Some(button) = item.button(mtm) {
            button.setAccessibilityLabel(Some(&ns("Master Password")));
            button.setAccessibilityTitle(Some(&ns("Master Password")));
        }
        let this = Self { item, menu, mtm };
        this.set_locked(true);
        this
    }

    /// Lock icon reflects the state at a glance.
    pub fn set_locked(&self, locked: bool) {
        if let Some(button) = self.item.button(self.mtm) {
            let name = if locked { "lock.fill" } else { "lock.open.fill" };
            match symbol(name) {
                Some(image) => button.setImage(Some(&image)),
                None => button.setTitle(&ns("●●●|")),
            }
            button.setToolTip(Some(&ns(if locked {
                "Master Password (locked) — ⌃⌘P"
            } else {
                "Master Password (unlocked) — ⌃⌘P"
            })));
        }
    }

    /// Is the status item really in the menu bar?  See [`Placement`].
    pub fn placement(&self) -> Option<Placement> {
        let window = self.item.button(self.mtm)?.window()?;
        let frame = window.frame();
        let screens = NSScreen::screens(self.mtm);
        let main_height = screens.iter().next().map_or(0.0, |s| s.frame().size.height);
        // AppKit: bottom-left origin; WindowServer: top-left origin of the
        // primary screen.
        let cg = (frame.origin.x, main_height - frame.origin.y - frame.size.height, frame.size.width, frame.size.height);
        let close = |a: f64, b: f64| (a - b).abs() <= 1.0;
        let hosted = super::cgwindow::all_windows().into_iter().find(|w| {
            w.layer == STATUS_LAYER
                && close(w.bounds.0, cg.0)
                && close(w.bounds.1, cg.1)
                && close(w.bounds.2, cg.2)
                && close(w.bounds.3, cg.3)
        });
        let screen = screens.iter().find(|s| {
            let f = s.frame();
            let mid = frame.origin.x + frame.size.width / 2.0;
            mid >= f.origin.x && mid <= f.origin.x + f.size.width
        });
        let (on_a_screen, under_notch) = match &screen {
            Some(s) => {
                let (left, right) = (s.auxiliaryTopLeftArea(), s.auxiliaryTopRightArea());
                let has_notch = left.size.width > 0.0 && right.size.width > 0.0;
                let gap = (left.origin.x + left.size.width, right.origin.x);
                let (x0, x1) = (frame.origin.x, frame.origin.x + frame.size.width);
                (true, has_notch && x1 > gap.0 && x0 < gap.1)
            }
            None => (false, false),
        };
        Some(Placement {
            frame: cg,
            hosted_by: hosted.map(|w| (w.pid, w.number)),
            on_a_screen,
            under_notch,
            app_kit_visible: self.item.isVisible(),
        })
    }

    pub fn has_button(&self) -> bool {
        self.item.button(self.mtm).is_some()
    }

    /// Replace the menu's items with `entries`.
    pub fn rebuild(&self, entries: &[MenuEntry], target: &AnyObject) {
        fill(self.mtm, &self.menu, entries, target);
    }
}

fn fill(mtm: MainThreadMarker, menu: &NSMenu, entries: &[MenuEntry], target: &AnyObject) {
    menu.removeAllItems();
    for entry in entries {
        match entry {
            MenuEntry::Separator => menu.addItem(&NSMenuItem::separatorItem(mtm)),
            MenuEntry::Item(item) => menu.addItem(&make_item(mtm, item, target)),
        }
    }
}

fn make_item(mtm: MainThreadMarker, spec: &MenuItem, target: &AnyObject) -> Retained<NSMenuItem> {
    let action = spec.command.map(|_| sel!(menuAction:));
    // SAFETY: `menuAction:` is implemented by `target` (the app delegate,
    // alive for the whole process) with signature `-(void)x:(id)sender`.
    let item = unsafe {
        let item = NSMenuItem::initWithTitle_action_keyEquivalent(
            NSMenuItem::alloc(mtm),
            &ns(&spec.title),
            action,
            &ns(spec.key),
        );
        if spec.command.is_some() {
            item.setTarget(Some(target));
        }
        item
    };
    if let Some(command) = spec.command {
        item.setTag(command.tag());
    }
    let mut mask = NSEventModifierFlags::empty();
    if spec.modifiers.command {
        mask |= NSEventModifierFlags::Command;
    }
    if spec.modifiers.control {
        mask |= NSEventModifierFlags::Control;
    }
    if spec.modifiers.option {
        mask |= NSEventModifierFlags::Option;
    }
    item.setKeyEquivalentModifierMask(mask);
    item.setEnabled(spec.enabled);
    item.setState(if spec.checked { NSControlStateValueOn } else { NSControlStateValueOff });
    item.setToolTip(spec.tooltip.as_deref().map(ns).as_deref());
    if !spec.submenu.is_empty() || spec.command.is_none() {
        let submenu = NSMenu::initWithTitle(NSMenu::alloc(mtm), &ns(&spec.title));
        submenu.setAutoenablesItems(false);
        fill(mtm, &submenu, &spec.submenu, target);
        item.setSubmenu(Some(&submenu));
    }
    item
}
