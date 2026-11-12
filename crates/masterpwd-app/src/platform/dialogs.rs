//! Shows [`Prompt`]s as `NSAlert`s and [`FileRequest`]s as open/save panels.
//!
//! When the sites panel is up they run as *sheets* on it: the panel is a
//! non-activating key window, and a sheet inherits its keyboard focus even
//! though the app is not active.  Without a parent they run app-modally, with
//! the alert window made non-activating for the same reason.  Either way the
//! call blocks (pumping events) until answered; the core is not borrowed
//! meanwhile.

use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use block2::RcBlock;

use mpw_core::Zeroizing;
use objc2::rc::Retained;
use objc2::{MainThreadMarker, MainThreadOnly, Message};
use objc2_app_kit::{
    NSAlert, NSAlertStyle, NSApplication, NSEventMask, NSModalResponse, NSModalResponseOK, NSOpenPanel,
    NSSavePanel, NSSecureTextField, NSTextField, NSView, NSWindow, NSWindowStyleMask,
};
use objc2_foundation::{NSArray, NSDate, NSDefaultRunLoopMode, NSPoint, NSRect, NSSize, NSString};

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

/// Process events until `done` (a sheet's completion handler ran).
fn pump_until(mtm: MainThreadMarker, done: &Cell<bool>) {
    let app = NSApplication::sharedApplication(mtm);
    while !done.get() {
        let until = NSDate::dateWithTimeIntervalSinceNow(0.05);
        // SAFETY: the default run-loop mode is a framework constant; we
        // dispatch every event we dequeue, like -[NSApplication run].
        let event = unsafe {
            app.nextEventMatchingMask_untilDate_inMode_dequeue(NSEventMask::Any, Some(&until), NSDefaultRunLoopMode, true)
        };
        if let Some(event) = event {
            app.sendEvent(&event);
        }
    }
}

type Completion = (Rc<Cell<bool>>, Rc<Cell<NSModalResponse>>, RcBlock<dyn Fn(NSModalResponse)>);

/// A completion handler that records the response and flags `done`.
fn completion() -> Completion {
    let done = Rc::new(Cell::new(false));
    let response = Rc::new(Cell::new(0));
    let (d, r) = (done.clone(), response.clone());
    let block = RcBlock::new(move |code: NSModalResponse| {
        r.set(code);
        d.set(true);
    });
    (done, response, block)
}

/// Run `prompt` as a sheet on `parent`, or app-modally.  The secure fields
/// are cleared before returning.
pub fn run_prompt(
    mtm: MainThreadMarker,
    prompt: &Prompt,
    parent: Option<&NSWindow>,
    auto: Option<AutoAnswer>,
) -> PromptAnswer {
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

    let alert_window = alert.window();
    if let Some(auto) = &auto {
        let code = FIRST_BUTTON + auto.button as isize;
        let window = alert_window.clone();
        super::runloop::after(Duration::from_millis(300), move || {
            eprintln!("smoke-test: HOLD dialog window={}", window.windowNumber());
        });
        let (window, parent) = (alert_window.clone(), parent.map(|p| p.retain()));
        super::runloop::after(auto.hold, move || match parent {
            Some(parent) => parent.endSheet_returnCode(&window, code),
            None => NSApplication::sharedApplication(mtm).stopModalWithCode(code),
        });
    }

    let response = match parent {
        Some(parent) => {
            let (done, response, block) = completion();
            alert.beginSheetModalForWindow_completionHandler(parent, Some(&block));
            pump_until(mtm, &done);
            response.get()
        }
        None => {
            alert_window.setStyleMask(alert_window.styleMask() | NSWindowStyleMask::NonactivatingPanel);
            alert.runModal()
        }
    };
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

/// Run an open or save panel (as a sheet on `parent` if given); `None` if
/// cancelled.
pub fn run_file_panel(mtm: MainThreadMarker, request: &FileRequest, parent: Option<&NSWindow>) -> Option<PathBuf> {
    let types: Vec<Retained<NSString>> = request.extensions.iter().map(|e| ns(e)).collect();
    let types = NSArray::from_retained_slice(&types);
    let panel: Retained<NSSavePanel> = if request.save {
        let panel = NSSavePanel::savePanel(mtm);
        panel.setNameFieldStringValue(&ns(&request.suggested_name));
        panel.setCanCreateDirectories(true);
        panel
    } else {
        let panel = NSOpenPanel::openPanel(mtm);
        panel.setCanChooseDirectories(false);
        panel.setAllowsMultipleSelection(false);
        panel.setPrompt(Some(&ns("Import")));
        Retained::into_super(panel)
    };
    panel.setTitle(Some(&ns(&request.title)));
    panel.setMessage(Some(&ns(&request.message)));
    #[allow(deprecated)] // setAllowedFileTypes: avoids pulling in UniformTypeIdentifiers
    panel.setAllowedFileTypes(Some(&types));
    let response = match parent {
        Some(parent) => {
            let (done, response, block) = completion();
            panel.beginSheetModalForWindow_completionHandler(parent, &block);
            pump_until(mtm, &done);
            response.get()
        }
        None => panel.runModal(),
    };
    if response != NSModalResponseOK {
        return None;
    }
    panel.URL().and_then(|u| u.path()).map(|p| PathBuf::from(p.to_string()))
}
