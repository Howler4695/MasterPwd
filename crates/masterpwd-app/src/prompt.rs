//! Dialogs as data.  The core asks a question with a [`Prompt`]; the platform
//! shows it as an `NSAlert` (or the smoke test answers it) and hands back a
//! [`PromptAnswer`].  File panels work the same way ([`FileRequest`]).

use std::fmt;
use std::path::PathBuf;

use mpw_core::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Informational,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonRole {
    /// Triggered by ⏎.  At most one, always first.
    Default,
    Normal,
    /// Triggered by Esc.
    Cancel,
    /// Shown in red; never the default.
    Destructive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Button {
    pub title: String,
    pub role: ButtonRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub placeholder: String,
    pub secure: bool,
    pub initial: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub id: u64,
    pub style: Style,
    pub title: String,
    pub message: String,
    pub fields: Vec<Field>,
    pub buttons: Vec<Button>,
}

impl Prompt {
    pub fn new(style: Style, title: impl Into<String>, message: impl Into<String>) -> Self {
        Self { id: 0, style, title: title.into(), message: message.into(), fields: Vec::new(), buttons: Vec::new() }
    }

    pub fn button(mut self, title: impl Into<String>, role: ButtonRole) -> Self {
        self.buttons.push(Button { title: title.into(), role });
        self
    }

    pub fn field(mut self, placeholder: impl Into<String>, secure: bool) -> Self {
        self.fields.push(Field { placeholder: placeholder.into(), secure, initial: String::new() });
        self
    }

    /// A plain message with an OK button.
    pub fn info(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(Style::Informational, title, message).button("OK", ButtonRole::Default)
    }

    /// Index of the button with this title (tests, smoke test).
    pub fn button_index(&self, title: &str) -> Option<usize> {
        self.buttons.iter().position(|b| b.title == title)
    }

    /// Checked invariants: the destructive button is never the default, and
    /// the default (if any) comes first.
    pub fn is_well_formed(&self) -> bool {
        let defaults: Vec<usize> =
            self.buttons.iter().enumerate().filter(|(_, b)| b.role == ButtonRole::Default).map(|(i, _)| i).collect();
        !self.buttons.is_empty() && (defaults.is_empty() || defaults == [0])
    }
}

/// The user's response: the button index and the field values (wiped on drop).
pub struct PromptAnswer {
    pub button: usize,
    pub values: Vec<Zeroizing<String>>,
}

impl fmt::Debug for PromptAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PromptAnswer(button {}, {} values)", self.button, self.values.len())
    }
}

impl PromptAnswer {
    pub fn button(button: usize) -> Self {
        Self { button, values: Vec::new() }
    }

    pub fn with_values(button: usize, values: &[&str]) -> Self {
        Self { button, values: values.iter().map(|v| Zeroizing::new((*v).to_owned())).collect() }
    }

    pub fn value(&self, i: usize) -> &str {
        self.values.get(i).map_or("", |v| v.as_str())
    }
}

/// An open or save panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRequest {
    pub id: u64,
    pub save: bool,
    pub title: String,
    pub message: String,
    pub extensions: Vec<&'static str>,
    pub suggested_name: String,
}

/// `None`: cancelled.
pub type FileAnswer = Option<PathBuf>;
