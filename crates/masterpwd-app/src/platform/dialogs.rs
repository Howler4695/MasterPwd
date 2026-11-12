//! Shows [`Prompt`]s as `NSAlert`s and [`FileRequest`]s as open/save panels.
//! Both run app-modally; the core is not borrowed while they are up.

use std::path::PathBuf;
use std::time::Duration;

use mpw_core::Zeroizing;
use objc2::rc::Retained;
use objc2::{MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSAlert, NSAlertStyle, NSApplication, NSModalResponseOK, NSOpenPanel, NSSavePanel, NSSecureTextField,
    NSTextField, NSView,
};
use objc2_foundation::{NSArray, NSPoint, NSRect, NSSize, NSString};

use super::ns;
use crate::prompt::{ButtonRole, FileRequest, Prompt, PromptAnswer, Style};

const FIRST_BUTTON: isize = 1000;
const FIELD_W: f64 = 300.0;
const FIELD_H: f64 = 24.0;
const GAP: f64 = 8.0;

/// Review aid: show the alert for real, then answer `button` after `hold`.
pub struct AutoAnswer {
    pub hold: Duration,
    pub button: usize,
}

/// Run `prompt` modally.  The secure fields are cleared before returning.
pub fn run_prompt(mtm: MainThreadMarker, prompt: &Prompt, auto: Option<AutoAnswer>) -> PromptAnswer {
    let alert = NSAlert::new(mtm);
    alert.setAlertStyle(match prompt.style {
        Style::Informational => NSAlertStyle::Informational,
        Style::Warning => NSAlertStyle::Warning,
        Style::Critical => NSAlertStyle::Critical,
    });
    alert.setMessageText(&ns(&prompt.title));
    alert.setInformativeText(&ns(&prompt.message));

    let mut fields: Vec<Retained<NSTextField>> = Vec::new();
    if !prompt.fields.is_empty() {
        let n = prompt.fields.len() as f64;
        let height = n * FIELD_H + (n - 1.0) * GAP;
        let container = NSView::initWithFrame(NSView::alloc(mtm), NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(FIELD_W, height)));
        for (i, spec) in prompt.fields.iter().enumerate() {
            let y = height - (i as f64 + 1.0) * FIELD_H - i as f64 * GAP;
            let frame = NSRect::new(NSPoint::new(0.0, y), NSSize::new(FIELD_W, FIELD_H));
            let field: Retained<NSTextField> = if spec.secure {
                Retained::into_super(NSSecureTextField::initWithFrame(NSSecureTextField::alloc(mtm), frame))
            } else {
                NSTextField::initWithFrame(NSTextField::alloc(mtm), frame)
            };
            field.setPlaceholderString(Some(&ns(&spec.placeholder)));
            field.setStringValue(&ns(&spec.initial));
            container.addSubview(&field);
            fields.push(field);
        }
        alert.setAccessoryView(Some(&container));
    }

    for (i, b) in prompt.buttons.iter().enumerate() {
        let button = alert.addButtonWithTitle(&ns(&b.title));
        match b.role {
            ButtonRole::Destructive => {
                button.setHasDestructiveAction(true);
                if i == 0 {
                    // Never let ⏎ trigger a destructive action.
                    button.setKeyEquivalent(&ns(""));
                }
            }
            ButtonRole::Cancel if i != 0 => button.setKeyEquivalent(&ns("\u{1b}")),
            _ => {}
        }
    }
    alert.layout();
    if let Some(first) = fields.first() {
        alert.window().setInitialFirstResponder(Some(first));
    }

    if let Some(auto) = &auto {
        let code = FIRST_BUTTON + auto.button as isize;
        let window = alert.window();
        super::runloop::after(Duration::from_millis(300), move || {
            eprintln!("smoke-test: HOLD dialog window={}", window.windowNumber());
        });
        super::runloop::after(auto.hold, move || NSApplication::sharedApplication(mtm).stopModalWithCode(code));
    }

    let response = alert.runModal();
    let button = usize::try_from(response - FIRST_BUTTON).unwrap_or(usize::MAX);
    let values = fields
        .iter()
        .map(|f| {
            let v = Zeroizing::new(f.stringValue().to_string());
            f.setStringValue(&ns(""));
            v
        })
        .collect();
    PromptAnswer { button, values }
}

/// Run an open or save panel; `None` if cancelled.
pub fn run_file_panel(mtm: MainThreadMarker, request: &FileRequest) -> Option<PathBuf> {
    let types: Vec<Retained<NSString>> = request.extensions.iter().map(|e| ns(e)).collect();
    let types = NSArray::from_retained_slice(&types);
    #[allow(deprecated)] // setAllowedFileTypes: avoids pulling in UniformTypeIdentifiers
    let url = if request.save {
        let panel = NSSavePanel::savePanel(mtm);
        panel.setTitle(Some(&ns(&request.title)));
        panel.setMessage(Some(&ns(&request.message)));
        panel.setNameFieldStringValue(&ns(&request.suggested_name));
        panel.setAllowedFileTypes(Some(&types));
        panel.setCanCreateDirectories(true);
        (panel.runModal() == NSModalResponseOK).then(|| panel.URL()).flatten()
    } else {
        let panel = NSOpenPanel::openPanel(mtm);
        panel.setTitle(Some(&ns(&request.title)));
        panel.setMessage(Some(&ns(&request.message)));
        panel.setAllowedFileTypes(Some(&types));
        panel.setCanChooseDirectories(false);
        panel.setAllowsMultipleSelection(false);
        panel.setPrompt(Some(&ns("Import")));
        (panel.runModal() == NSModalResponseOK).then(|| panel.URL()).flatten()
    };
    url.and_then(|u| u.path()).map(|p| PathBuf::from(p.to_string()))
}
