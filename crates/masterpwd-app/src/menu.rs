//! The status-item menu as plain data.  `platform::status_item` renders it;
//! menu item tags carry a [`MenuCommand`] back.

/// Every action reachable from the status menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MenuCommand {
    Open,
    Lock,
    Quit,
    ToggleOpenAtLogin,
    ToggleHidePasswords,
    ToggleRememberPassword,
    ToggleSavePassword,
    ClipboardClear(u32),
    IdleLock(u32),
    /// Index into the user list.
    SelectUser(u32),
    NewUser,
    DeleteUser,
    ImportSites,
    ExportSecure,
    ExportReveal,
    ShowWelcome,
    ChangeMasterPassword,
    EnableSecondFactor,
    AddSmartCard,
    RotateRecoveryCode,
    DisableSecondFactor,
    ToggleLockOnCardRemoval,
    /// Index into the unlocked user's second-factor slots.
    RemoveSlot(u32),
}

const PARAM_CLIPBOARD: isize = 100_000;
const PARAM_IDLE: isize = 200_000;
const PARAM_USER: isize = 300_000;
const PARAM_SLOT: isize = 400_000;
const PARAM_SPAN: isize = 100_000;

impl MenuCommand {
    const SIMPLE: [(MenuCommand, isize); 19] = [
        (MenuCommand::Open, 1),
        (MenuCommand::Lock, 2),
        (MenuCommand::Quit, 3),
        (MenuCommand::ToggleOpenAtLogin, 10),
        (MenuCommand::ToggleHidePasswords, 11),
        (MenuCommand::ToggleRememberPassword, 12),
        (MenuCommand::ToggleSavePassword, 13),
        (MenuCommand::NewUser, 20),
        (MenuCommand::DeleteUser, 21),
        (MenuCommand::ImportSites, 22),
        (MenuCommand::ExportSecure, 23),
        (MenuCommand::ExportReveal, 24),
        (MenuCommand::ShowWelcome, 30),
        (MenuCommand::ChangeMasterPassword, 31),
        (MenuCommand::EnableSecondFactor, 40),
        (MenuCommand::AddSmartCard, 41),
        (MenuCommand::RotateRecoveryCode, 42),
        (MenuCommand::DisableSecondFactor, 43),
        (MenuCommand::ToggleLockOnCardRemoval, 44),
    ];

    /// Encode as an `NSMenuItem` tag (always > 0).
    pub fn tag(self) -> isize {
        match self {
            Self::ClipboardClear(s) => PARAM_CLIPBOARD + (s as isize).min(PARAM_SPAN - 1),
            Self::IdleLock(m) => PARAM_IDLE + (m as isize).min(PARAM_SPAN - 1),
            Self::SelectUser(i) => PARAM_USER + (i as isize).min(PARAM_SPAN - 1),
            Self::RemoveSlot(i) => PARAM_SLOT + (i as isize).min(PARAM_SPAN - 1),
            simple => Self::SIMPLE.iter().find(|(c, _)| *c == simple).map_or(0, |(_, t)| *t),
        }
    }

    /// Decode a tag; unknown tags yield `None` (ignored, never a panic).
    pub fn from_tag(tag: isize) -> Option<Self> {
        match tag {
            t if (PARAM_CLIPBOARD..PARAM_CLIPBOARD + PARAM_SPAN).contains(&t) => {
                Some(Self::ClipboardClear((t - PARAM_CLIPBOARD) as u32))
            }
            t if (PARAM_IDLE..PARAM_IDLE + PARAM_SPAN).contains(&t) => {
                Some(Self::IdleLock((t - PARAM_IDLE) as u32))
            }
            t if (PARAM_USER..PARAM_USER + PARAM_SPAN).contains(&t) => {
                Some(Self::SelectUser((t - PARAM_USER) as u32))
            }
            t if (PARAM_SLOT..PARAM_SLOT + PARAM_SPAN).contains(&t) => {
                Some(Self::RemoveSlot((t - PARAM_SLOT) as u32))
            }
            t => Self::SIMPLE.iter().find(|(_, x)| *x == t).map(|(c, _)| *c),
        }
    }
}

/// Modifier keys of a key equivalent (display only in a status menu).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Modifiers {
    pub command: bool,
    pub control: bool,
    pub option: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuItem {
    pub title: String,
    pub command: Option<MenuCommand>,
    pub key: &'static str,
    pub modifiers: Modifiers,
    pub enabled: bool,
    pub checked: bool,
    pub tooltip: Option<String>,
    pub submenu: Vec<MenuEntry>,
}

impl MenuItem {
    pub fn new(title: impl Into<String>, command: MenuCommand) -> Self {
        Self {
            title: title.into(),
            command: Some(command),
            key: "",
            modifiers: Modifiers::default(),
            enabled: true,
            checked: false,
            tooltip: None,
            submenu: Vec::new(),
        }
    }

    pub fn submenu(title: impl Into<String>, entries: Vec<MenuEntry>) -> Self {
        Self { command: None, submenu: entries, ..Self::new(title, MenuCommand::Open) }
    }

    pub fn key(mut self, key: &'static str, modifiers: Modifiers) -> Self {
        self.key = key;
        self.modifiers = modifiers;
        self
    }

    pub fn checked(mut self, checked: bool) -> Self {
        self.checked = checked;
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn tooltip(mut self, tooltip: impl Into<String>) -> Self {
        self.tooltip = Some(tooltip.into());
        self
    }

    /// Disabled, with an explanation.
    pub fn later(self) -> Self {
        self.enabled(false).tooltip("Coming in the next version.")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuEntry {
    Item(MenuItem),
    Separator,
}

impl From<MenuItem> for MenuEntry {
    fn from(item: MenuItem) -> Self {
        Self::Item(item)
    }
}

/// Find an item by command anywhere in a menu tree.
pub fn find(entries: &[MenuEntry], command: MenuCommand) -> Option<&MenuItem> {
    entries.iter().find_map(|e| match e {
        MenuEntry::Item(item) if item.command == Some(command) => Some(item),
        MenuEntry::Item(item) => find(&item.submenu, command),
        MenuEntry::Separator => None,
    })
}

/// Find a submenu by title.
pub fn find_title<'a>(entries: &'a [MenuEntry], title: &str) -> Option<&'a MenuItem> {
    entries.iter().find_map(|e| match e {
        MenuEntry::Item(item) if item.title == title => Some(item),
        MenuEntry::Item(item) => find_title(&item.submenu, title),
        MenuEntry::Separator => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_round_trip() {
        let all = MenuCommand::SIMPLE
            .iter()
            .map(|(c, _)| *c)
            .chain([
                MenuCommand::ClipboardClear(0),
                MenuCommand::ClipboardClear(60),
                MenuCommand::IdleLock(15),
                MenuCommand::SelectUser(0),
                MenuCommand::SelectUser(7),
                MenuCommand::RemoveSlot(3),
            ]);
        for c in all {
            assert!(c.tag() > 0);
            assert_eq!(MenuCommand::from_tag(c.tag()), Some(c), "{c:?}");
        }
        assert_eq!(MenuCommand::from_tag(0), None);
        assert_eq!(MenuCommand::from_tag(-7), None);
        assert_eq!(MenuCommand::from_tag(99), None);
    }
}
