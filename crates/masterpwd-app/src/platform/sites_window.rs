//! The sites window, built programmatically.  It renders a
//! [`SitesView`](crate::view_model::SitesView) and reports input to the app
//! delegate (text changes via `controlTextDidChange:`, keys via
//! `control:textView:doCommandBySelector:`, buttons via `uiAction:`).

use std::cell::Cell;

use mpw_core::{IdenticonColor, KeyPurpose, ResultType};
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{define_class, msg_send, sel, DefinedClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSBackingStoreType, NSButton, NSColor, NSControl, NSEvent, NSEventModifierFlags, NSFont,
    NSPopUpButton, NSProgressIndicator, NSProgressIndicatorStyle, NSResponder, NSSecureTextField,
    NSSegmentSwitchTracking, NSSegmentedControl, NSStepper, NSTextAlignment, NSTextField, NSTextFieldDelegate,
    NSView, NSWindow, NSWindowCollectionBehavior, NSWindowDelegate, NSWindowSharingType, NSWindowStyleMask,
};
use objc2_foundation::{NSArray, NSPoint, NSRect, NSSize, NSString};

use super::ns;
use crate::view_model::{Mode, SitesView};

// Control tags, reported back to the delegate.
pub const TAG_FULL_NAME: isize = 1;
pub const TAG_MASTER_PASSWORD: isize = 2;
pub const TAG_SITE: isize = 3;
pub const TAG_QUESTION: isize = 4;
pub const TAG_UNLOCK: isize = 10;
pub const TAG_PURPOSE: isize = 11;
pub const TAG_TYPE: isize = 12;
pub const TAG_COUNTER: isize = 13;
pub const TAG_LOCK: isize = 14;
pub const TAG_COPY: isize = 15;

/// Set to override `NSWindowSharingNone` (e.g. to screenshot during review).
pub const ALLOW_CAPTURE_ENV: &str = "MASTERPWD_ALLOW_SCREEN_CAPTURE";

pub const PURPOSES: [KeyPurpose; 3] =
    [KeyPurpose::Authentication, KeyPurpose::Identification, KeyPurpose::Recovery];

const W: f64 = 520.0;
const H: f64 = 420.0;

fn rect(x: f64, y: f64, w: f64, h: f64) -> NSRect {
    NSRect::new(NSPoint::new(x, y), NSSize::new(w, h))
}

/// Delivers ⌥ (reveal) and Esc to the app delegate.
pub type FlagsCallback = fn(option_down: bool);
pub type CancelCallback = fn();

pub struct SitesWindowIvars {
    on_flags: FlagsCallback,
    on_cancel: CancelCallback,
}

define_class!(
    // SAFETY: NSWindow may be subclassed; we only override responder methods
    // and call super; no Drop impl.
    #[unsafe(super(NSWindow, NSResponder, objc2_foundation::NSObject))]
    #[thread_kind = MainThreadOnly]
    #[ivars = SitesWindowIvars]
    #[name = "MPWSitesWindow"]
    pub struct SitesWindowView;

    impl SitesWindowView {
        // SAFETY: signature matches -[NSResponder flagsChanged:].
        #[unsafe(method(flagsChanged:))]
        fn flags_changed(&self, event: &NSEvent) {
            (self.ivars().on_flags)(event.modifierFlags().contains(NSEventModifierFlags::Option));
            // SAFETY: forwarding the same event to the superclass.
            let _: () = unsafe { msg_send![super(self), flagsChanged: event] };
        }

        // SAFETY: signature matches -[NSResponder cancelOperation:].
        #[unsafe(method(cancelOperation:))]
        fn cancel_operation(&self, _sender: Option<&AnyObject>) {
            (self.ivars().on_cancel)();
        }
    }
);

pub struct SitesWindow {
    pub window: Retained<SitesWindowView>,
    prompt: Retained<NSTextField>,
    // Locked.
    full_name: Retained<NSTextField>,
    master_password: Retained<NSSecureTextField>,
    identicon: Retained<NSTextField>,
    unlock: Retained<NSButton>,
    spinner: Retained<NSProgressIndicator>,
    // Unlocked.
    site: Retained<NSTextField>,
    candidates: Retained<NSTextField>,
    result_label: Retained<NSTextField>,
    result: Retained<NSTextField>,
    purpose: Retained<NSSegmentedControl>,
    result_type: Retained<NSPopUpButton>,
    counter_label: Retained<NSTextField>,
    counter: Retained<NSStepper>,
    question: Retained<NSTextField>,
    copy: Retained<NSButton>,
    lock: Retained<NSButton>,
    // Both.
    error: Retained<NSTextField>,
    hint: Retained<NSTextField>,
    last_mode: Cell<Option<Mode>>,
    type_choices: std::cell::RefCell<Vec<ResultType>>,
    mtm: MainThreadMarker,
}

fn label(mtm: MainThreadMarker, text: &str, frame: NSRect, size: f64) -> Retained<NSTextField> {
    let l = NSTextField::labelWithString(&ns(text), mtm);
    l.setFrame(frame);
    l.setFont(Some(&NSFont::systemFontOfSize(size)));
    l
}

fn field(
    mtm: MainThreadMarker,
    placeholder: &str,
    frame: NSRect,
    tag: isize,
    delegate: &ProtocolObject<dyn NSTextFieldDelegate>,
) -> Retained<NSTextField> {
    let f = NSTextField::initWithFrame(NSTextField::alloc(mtm), frame);
    f.setPlaceholderString(Some(&ns(placeholder)));
    f.setTag(tag);
    // SAFETY: the delegate (app delegate) outlives the field; the field
    // holds it weakly as AppKit expects.
    unsafe { f.setDelegate(Some(delegate)) };
    f.setFont(Some(&NSFont::systemFontOfSize(15.0)));
    // No autocorrection/completion popups on names and site names.
    f.setAutomaticTextCompletionEnabled(false);
    f
}

fn set_target(control: &NSControl, target: &AnyObject, tag: isize) {
    control.setTag(tag);
    // SAFETY: `target` (the app delegate, alive for the whole process)
    // implements `uiAction:` as `-(void)x:(id)sender`.
    unsafe {
        control.setTarget(Some(target));
        control.setAction(Some(sel!(uiAction:)));
    }
}

/// Only touch a field when the text differs, so the caret doesn't jump.
fn set_text(f: &NSTextField, text: &str) {
    if f.stringValue().to_string() != text {
        f.setStringValue(&ns(text));
    }
}

fn identicon_color(c: IdenticonColor) -> Retained<NSColor> {
    match c {
        IdenticonColor::Red => NSColor::systemRedColor(),
        IdenticonColor::Green => NSColor::systemGreenColor(),
        IdenticonColor::Yellow => NSColor::systemYellowColor(),
        IdenticonColor::Blue => NSColor::systemBlueColor(),
        IdenticonColor::Magenta => NSColor::systemPinkColor(),
        IdenticonColor::Cyan => NSColor::systemTealColor(),
        IdenticonColor::Mono => NSColor::labelColor(),
    }
}

impl SitesWindow {
    pub fn new(
        mtm: MainThreadMarker,
        target: &AnyObject,
        text_delegate: &ProtocolObject<dyn NSTextFieldDelegate>,
        window_delegate: &ProtocolObject<dyn NSWindowDelegate>,
        on_flags: FlagsCallback,
        on_cancel: CancelCallback,
    ) -> Self {
        let this = SitesWindowView::alloc(mtm).set_ivars(SitesWindowIvars { on_flags, on_cancel });
        // SAFETY: designated initializer of NSWindow with valid arguments.
        let window: Retained<SitesWindowView> = unsafe {
            msg_send![super(this),
                initWithContentRect: rect(0.0, 0.0, W, H),
                styleMask: NSWindowStyleMask::Titled | NSWindowStyleMask::Closable,
                backing: NSBackingStoreType::Buffered,
                defer: false]
        };
        // SAFETY: we keep our own strong reference; AppKit must not release
        // the window on close as well.
        unsafe { window.setReleasedWhenClosed(false) };
        window.setTitle(&ns("Master Password"));
        window.setDelegate(Some(window_delegate));
        window.setCollectionBehavior(
            NSWindowCollectionBehavior::MoveToActiveSpace | NSWindowCollectionBehavior::FullScreenAuxiliary,
        );
        // Keep the window out of screenshots, recordings and screen sharing.
        let allow_capture = std::env::var(ALLOW_CAPTURE_ENV).is_ok_and(|v| v == "1");
        window.setSharingType(if allow_capture { NSWindowSharingType::ReadOnly } else { NSWindowSharingType::None });
        window.center();

        let content = window.contentView().expect("a titled window has a content view");
        let add = |v: &NSView| content.addSubview(v);

        let prompt = label(mtm, "", rect(20.0, 372.0, 480.0, 24.0), 15.0);
        prompt.setFont(Some(&NSFont::boldSystemFontOfSize(15.0)));
        add(&prompt);

        // ----- locked
        let full_name = field(mtm, "Your full name", rect(20.0, 330.0, 480.0, 26.0), TAG_FULL_NAME, text_delegate);
        add(&full_name);
        let master_password = NSSecureTextField::initWithFrame(NSSecureTextField::alloc(mtm), rect(20.0, 292.0, 480.0, 26.0));
        master_password.setPlaceholderString(Some(&ns("Your master password")));
        master_password.setTag(TAG_MASTER_PASSWORD);
        // SAFETY: as in `field`.
        unsafe { master_password.setDelegate(Some(text_delegate)) };
        master_password.setFont(Some(&NSFont::systemFontOfSize(15.0)));
        add(&master_password);
        let identicon = label(mtm, "", rect(20.0, 250.0, 480.0, 32.0), 24.0);
        identicon.setAlignment(NSTextAlignment::Center);
        identicon.setToolTip(Some(&ns(
            "Your identicon: it looks the same every time you type the same name and master password.",
        )));
        add(&identicon);
        // SAFETY: `target` implements `uiAction:`.
        let unlock = unsafe {
            NSButton::buttonWithTitle_target_action(&ns("Unlock"), Some(target), Some(sel!(uiAction:)), mtm)
        };
        unlock.setTag(TAG_UNLOCK);
        unlock.setFrame(rect(400.0, 205.0, 100.0, 32.0));
        add(&unlock);
        let spinner = NSProgressIndicator::initWithFrame(NSProgressIndicator::alloc(mtm), rect(370.0, 212.0, 18.0, 18.0));
        spinner.setStyle(NSProgressIndicatorStyle::Spinning);
        spinner.setIndeterminate(true);
        spinner.setDisplayedWhenStopped(false);
        add(&spinner);

        // ----- unlocked
        let site = field(mtm, "Site name, e.g. apple.com", rect(20.0, 328.0, 480.0, 30.0), TAG_SITE, text_delegate);
        site.setFont(Some(&NSFont::systemFontOfSize(18.0)));
        add(&site);
        let candidates = NSTextField::wrappingLabelWithString(&ns(""), mtm);
        candidates.setFrame(rect(20.0, 228.0, 480.0, 94.0));
        candidates.setFont(Some(&NSFont::systemFontOfSize(13.0)));
        candidates.setTextColor(Some(&NSColor::secondaryLabelColor()));
        add(&candidates);
        let result_label = label(mtm, "", rect(20.0, 200.0, 480.0, 20.0), 13.0);
        add(&result_label);
        let result = label(mtm, "", rect(20.0, 156.0, 480.0, 40.0), 26.0);
        result.setFont(Some(&NSFont::monospacedSystemFontOfSize_weight(26.0, 0.0)));
        result.setAlignment(NSTextAlignment::Center);
        result.setSelectable(false);
        add(&result);

        let labels = ["Password", "Login Name", "Security Answer"].map(ns);
        let labels = NSArray::from_retained_slice(&labels);
        // SAFETY: `target` implements `uiAction:`.
        let purpose = unsafe {
            NSSegmentedControl::segmentedControlWithLabels_trackingMode_target_action(
                &labels,
                NSSegmentSwitchTracking::SelectOne,
                Some(target),
                Some(sel!(uiAction:)),
                mtm,
            )
        };
        purpose.setTag(TAG_PURPOSE);
        purpose.setFrame(rect(20.0, 116.0, 320.0, 28.0));
        add(&purpose);
        let result_type = NSPopUpButton::initWithFrame_pullsDown(NSPopUpButton::alloc(mtm), rect(350.0, 114.0, 152.0, 30.0), false);
        set_target(&result_type, target, TAG_TYPE);
        add(&result_type);

        let counter_label = label(mtm, "Counter: 1", rect(20.0, 80.0, 100.0, 22.0), 13.0);
        add(&counter_label);
        let counter = NSStepper::initWithFrame(NSStepper::alloc(mtm), rect(120.0, 78.0, 20.0, 26.0));
        counter.setMinValue(1.0);
        counter.setMaxValue(crate::view_model::COUNTER_MAX as f64);
        counter.setIncrement(1.0);
        counter.setValueWraps(false);
        set_target(&counter, target, TAG_COUNTER);
        counter.setToolTip(Some(&ns("Increase the counter to get a new password for this site.")));
        add(&counter);
        let question = field(
            mtm,
            "Question keyword (optional), e.g. mother",
            rect(20.0, 78.0, 480.0, 26.0),
            TAG_QUESTION,
            text_delegate,
        );
        add(&question);

        // SAFETY: `target` implements `uiAction:`.
        let (copy, lock) = unsafe {
            (
                NSButton::buttonWithTitle_target_action(&ns("Copy"), Some(target), Some(sel!(uiAction:)), mtm),
                NSButton::buttonWithTitle_target_action(&ns("Lock"), Some(target), Some(sel!(uiAction:)), mtm),
            )
        };
        copy.setTag(TAG_COPY);
        copy.setFrame(rect(400.0, 40.0, 100.0, 32.0));
        add(&copy);
        lock.setTag(TAG_LOCK);
        lock.setFrame(rect(300.0, 40.0, 100.0, 32.0));
        add(&lock);

        // ----- both
        let error = NSTextField::wrappingLabelWithString(&ns(""), mtm);
        error.setFrame(rect(20.0, 40.0, 270.0, 34.0));
        error.setTextColor(Some(&NSColor::systemRedColor()));
        error.setFont(Some(&NSFont::systemFontOfSize(12.0)));
        add(&error);
        let hint = label(mtm, "", rect(20.0, 12.0, 480.0, 18.0), 11.0);
        hint.setTextColor(Some(&NSColor::tertiaryLabelColor()));
        add(&hint);

        window.setInitialFirstResponder(Some(&master_password));

        Self {
            window,
            prompt,
            full_name,
            master_password,
            identicon,
            unlock,
            spinner,
            site,
            candidates,
            result_label,
            result,
            purpose,
            result_type,
            counter_label,
            counter,
            question,
            copy,
            lock,
            error,
            hint,
            last_mode: Cell::new(None),
            type_choices: std::cell::RefCell::new(Vec::new()),
            mtm,
        }
    }

    pub fn is_visible(&self) -> bool {
        self.window.isVisible()
    }

    pub fn show(&self) {
        let app = NSApplication::sharedApplication(self.mtm);
        #[allow(deprecated)]
        app.activateIgnoringOtherApps(true);
        self.window.makeKeyAndOrderFront(None);
        self.focus();
    }

    pub fn close(&self) {
        if self.window.isVisible() {
            self.window.close();
        }
    }

    pub fn excluded_from_capture(&self) -> bool {
        self.window.sharingType() == NSWindowSharingType::None
    }

    /// Text of the editable fields, for event handling.
    pub fn text_of(&self, tag: isize) -> Option<Retained<NSString>> {
        Some(match tag {
            TAG_FULL_NAME => self.full_name.stringValue(),
            TAG_MASTER_PASSWORD => self.master_password.stringValue(),
            TAG_SITE => self.site.stringValue(),
            TAG_QUESTION => self.question.stringValue(),
            _ => return None,
        })
    }

    /// Programmatic input (smoke test): set a field as if typed.
    pub fn set_field(&self, tag: isize, text: &str) {
        let f: &NSTextField = match tag {
            TAG_FULL_NAME => &self.full_name,
            TAG_MASTER_PASSWORD => &self.master_password,
            TAG_SITE => &self.site,
            TAG_QUESTION => &self.question,
            _ => return,
        };
        f.setStringValue(&ns(text));
    }

    /// The displayed result (smoke test).
    pub fn displayed_result(&self) -> String {
        self.result.stringValue().to_string()
    }

    pub fn selected_purpose(&self) -> Option<KeyPurpose> {
        PURPOSES.get(usize::try_from(self.purpose.selectedSegment()).ok()?).copied()
    }

    pub fn selected_type(&self) -> Option<ResultType> {
        let index = usize::try_from(self.result_type.indexOfSelectedItem()).ok()?;
        self.type_choices.borrow().get(index).copied()
    }

    pub fn counter_value(&self) -> u32 {
        self.counter.integerValue().clamp(1, i64::from(u32::MAX) as isize) as u32
    }

    pub fn focus_password(&self) {
        self.window.makeFirstResponder(Some(&self.master_password));
    }

    fn focus(&self) {
        let target: &NSView = match self.last_mode.get() {
            Some(Mode::Unlocked) => &self.site,
            _ if self.full_name.stringValue().length() == 0 => &self.full_name,
            _ => &self.master_password,
        };
        self.window.makeFirstResponder(Some(target));
    }

    pub fn render(&self, view: &SitesView) {
        let mode_changed = self.last_mode.get() != Some(view.mode);
        self.last_mode.set(Some(view.mode));
        let locked = view.mode != Mode::Unlocked;

        set_text(&self.prompt, &view.prompt);

        for v in [&*self.full_name as &NSView, &self.master_password, &self.identicon, &self.unlock] {
            v.setHidden(!locked);
        }
        set_text(&self.full_name, &view.full_name);
        self.full_name.setEditable(view.mode == Mode::Locked);
        self.master_password.setEditable(view.mode == Mode::Locked);
        if mode_changed {
            // Never leave the master password sitting in a field.
            self.master_password.setStringValue(&ns(""));
        }
        match &view.identicon {
            Some(i) => {
                set_text(&self.identicon, &i.text());
                self.identicon.setTextColor(Some(&identicon_color(i.color)));
            }
            None => set_text(&self.identicon, ""),
        }
        self.unlock.setEnabled(view.can_unlock);
        if view.mode == Mode::Unlocking {
            // SAFETY: plain AppKit call on the main thread.
            unsafe { self.spinner.startAnimation(None) };
        } else {
            // SAFETY: as above.
            unsafe { self.spinner.stopAnimation(None) };
        }

        for v in [
            &*self.site as &NSView,
            &self.candidates,
            &self.result_label,
            &self.result,
            &self.purpose,
            &self.result_type,
            &self.copy,
            &self.lock,
        ] {
            v.setHidden(locked);
        }
        set_text(&self.site, &view.site_query);
        let list: Vec<String> = view
            .candidates
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let marker = if Some(i) == view.selection { "▸ " } else { "    " };
                let new = if c.known { "" } else { "  (new site)" };
                format!("{marker}{}{new}", c.name)
            })
            .collect();
        set_text(&self.candidates, &list.join("\n"));
        set_text(&self.result_label, &view.result_label);
        set_text(&self.result, &view.result_display);
        self.result.setTextColor(Some(&*if view.result_masked {
            NSColor::secondaryLabelColor()
        } else {
            NSColor::labelColor()
        }));

        if let Some(i) = PURPOSES.iter().position(|p| *p == view.purpose) {
            self.purpose.setSelectedSegment(i as isize);
        }
        {
            let mut choices = self.type_choices.borrow_mut();
            if *choices != view.type_choices {
                self.result_type.removeAllItems();
                for t in &view.type_choices {
                    self.result_type.addItemWithTitle(&ns(t.long_name()));
                }
                *choices = view.type_choices.clone();
            }
            match view.selected_type.and_then(|t| choices.iter().position(|c| *c == t)) {
                Some(i) => self.result_type.selectItemAtIndex(i as isize),
                None => self.result_type.selectItemAtIndex(-1),
            }
        }
        self.result_type.setEnabled(view.selected_type.is_some());

        let show_counter = !locked && view.question.is_none();
        self.counter_label.setHidden(!show_counter);
        self.counter.setHidden(!show_counter);
        self.counter_label.setTextColor(Some(&*if view.counter.is_some() {
            NSColor::labelColor()
        } else {
            NSColor::disabledControlTextColor()
        }));
        self.counter.setEnabled(view.counter.is_some());
        if let Some(c) = view.counter {
            set_text(&self.counter_label, &format!("Counter: {c}"));
            self.counter.setIntegerValue(c as isize);
        }
        self.question.setHidden(locked || view.question.is_none());
        if let Some(q) = &view.question {
            set_text(&self.question, q);
        }
        self.copy.setEnabled(view.can_copy);

        set_text(&self.error, view.error.as_deref().unwrap_or(""));
        set_text(&self.hint, view.hint);

        if mode_changed && self.window.isVisible() {
            self.focus();
        }
    }
}
