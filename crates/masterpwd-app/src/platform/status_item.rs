//! The menu-bar status item and its menu, rendered from [`crate::menu`].

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{sel, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSControlStateValueOff, NSControlStateValueOn, NSEventModifierFlags, NSImage, NSMenu, NSMenuDelegate,
    NSMenuItem, NSStatusBar, NSStatusItem, NSVariableStatusItemLength,
};

use super::ns;
use crate::menu::{MenuEntry, MenuItem};

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
