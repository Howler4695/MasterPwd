//! The sites window, built programmatically.  It renders a
//! [`SitesView`](crate::view_model::SitesView) and reports input to the app
//! delegate: text changes via `controlTextDidChange:`, keys via
//! `control:textView:doCommandBySelector:`, buttons via `uiAction:`, the two
//! tables via the table data-source/delegate methods.

use std::cell::{Cell, RefCell};

use mpw_core::{IdenticonColor, KeyPurpose};
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{define_class, msg_send, sel, DefinedClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSBackingStoreType, NSBorderType, NSButton, NSColor, NSControl, NSEvent, NSEventModifierFlags,
    NSFont, NSImageScaling, NSImageView, NSPopUpButton, NSProgressIndicator, NSProgressIndicatorStyle, NSResponder,
    NSScrollView, NSSecureTextField, NSSegmentSwitchTracking, NSSegmentedControl, NSStepper, NSTableColumn,
    NSTableView, NSTableViewDataSource, NSTableViewDelegate, NSTableViewStyle, NSTextAlignment, NSTextField,
    NSTextFieldDelegate, NSView, NSWindow, NSWindowCollectionBehavior, NSWindowDelegate, NSWindowSharingType,
    NSWindowStyleMask,
};
use objc2_foundation::{NSArray, NSIndexSet, NSPoint, NSRect, NSSize, NSString};

use super::{avatars, ns};
use crate::view_model::{Candidate, Screen, SitesView, TypeChoice, UserRow};

// Control tags, reported back to the delegate.
pub const TAG_MASTER_PASSWORD: isize = 2;
pub const TAG_SITE: isize = 3;
pub const TAG_NEW_NAME: isize = 5;
pub const TAG_NEW_PASSWORD: isize = 6;
pub const TAG_NEW_CONFIRM: isize = 7;
pub const TAG_UNLOCK: isize = 10;
pub const TAG_PURPOSE: isize = 11;
pub const TAG_TYPE: isize = 12;
pub const TAG_COUNTER: isize = 13;
pub const TAG_LOCK: isize = 14;
pub const TAG_COPY: isize = 15;
pub const TAG_QUICK_UNLOCK: isize = 16;
pub const TAG_CREATE: isize = 17;
pub const TAG_CANCEL_NEW: isize = 18;
pub const TAG_AVATAR_PREV: isize = 19;
pub const TAG_AVATAR_NEXT: isize = 20;
pub const TAG_QUESTION: isize = 21;
pub const TAG_ADD_QUESTION: isize = 22;
pub const TAG_REMOVE_QUESTION: isize = 23;
pub const TAG_UPGRADE: isize = 24;
pub const TAG_DELETE_SITE: isize = 25;
pub const TAG_USERS_TABLE: isize = 30;
pub const TAG_SITES_TABLE: isize = 31;

/// Set to override `NSWindowSharingNone` (e.g. to screenshot during review).
pub const ALLOW_CAPTURE_ENV: &str = "MASTERPWD_ALLOW_SCREEN_CAPTURE";

pub const PURPOSES: [KeyPurpose; 3] = [KeyPurpose::Authentication, KeyPurpose::Identification, KeyPurpose::Recovery];

const W: f64 = 640.0;
const H: f64 = 500.0;
const RIGHT: f64 = 260.0;
const RIGHT_W: f64 = 360.0;

fn rect(x: f64, y: f64, w: f64, h: f64) -> NSRect {
    NSRect::new(NSPoint::new(x, y), NSSize::new(w, h))
}

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

/// Is ⇧ held right now?
pub fn shift_down() -> bool {
    NSEvent::modifierFlags_class().contains(NSEventModifierFlags::Shift)
}

pub struct SitesWindow {
    pub window: Retained<SitesWindowView>,
    prompt: Retained<NSTextField>,
    // users (pick + new user)
    users_scroll: Retained<NSScrollView>,
    users_table: Retained<NSTableView>,
    pick_avatar: Retained<NSImageView>,
    pick_name: Retained<NSTextField>,
    master_password: Retained<NSSecureTextField>,
    identicon: Retained<NSTextField>,
    unlock: Retained<NSButton>,
    quick_unlock: Retained<NSButton>,
    spinner: Retained<NSProgressIndicator>,
    new_name: Retained<NSTextField>,
    new_password: Retained<NSSecureTextField>,
    new_confirm: Retained<NSSecureTextField>,
    new_avatar: Retained<NSImageView>,
    avatar_prev: Retained<NSButton>,
    avatar_next: Retained<NSButton>,
    create: Retained<NSButton>,
    cancel_new: Retained<NSButton>,
    // sites
    site: Retained<NSTextField>,
    sites_scroll: Retained<NSScrollView>,
    sites_table: Retained<NSTableView>,
    result_label: Retained<NSTextField>,
    result: Retained<NSTextField>,
    purpose: Retained<NSSegmentedControl>,
    result_type: Retained<NSPopUpButton>,
    counter_label: Retained<NSTextField>,
    counter: Retained<NSStepper>,
    question: Retained<NSPopUpButton>,
    add_question: Retained<NSButton>,
    remove_question: Retained<NSButton>,
    algorithm: Retained<NSTextField>,
    upgrade: Retained<NSButton>,
    delete_site: Retained<NSButton>,
    copy: Retained<NSButton>,
    lock: Retained<NSButton>,
    // both
    error: Retained<NSTextField>,
    hint: Retained<NSTextField>,
    last_screen: Cell<Option<Screen>>,
    /// True while render() updates controls: ignore the resulting callbacks.
    rendering: Cell<bool>,
    user_rows: RefCell<Vec<UserRow>>,
    site_rows: RefCell<Vec<Candidate>>,
    type_choices: RefCell<Vec<TypeChoice>>,
    questions: RefCell<Vec<String>>,
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
    // SAFETY: the delegate (app delegate) outlives the field.
    unsafe { f.setDelegate(Some(delegate)) };
    f.setFont(Some(&NSFont::systemFontOfSize(15.0)));
    f.setAutomaticTextCompletionEnabled(false);
    f
}

fn secure_field(
    mtm: MainThreadMarker,
    placeholder: &str,
    frame: NSRect,
    tag: isize,
    delegate: &ProtocolObject<dyn NSTextFieldDelegate>,
) -> Retained<NSSecureTextField> {
    let f = NSSecureTextField::initWithFrame(NSSecureTextField::alloc(mtm), frame);
    f.setPlaceholderString(Some(&ns(placeholder)));
    f.setTag(tag);
    // SAFETY: as in `field`.
    unsafe { f.setDelegate(Some(delegate)) };
    f.setFont(Some(&NSFont::systemFontOfSize(15.0)));
    f
}

fn button(mtm: MainThreadMarker, title: &str, target: &AnyObject, tag: isize, frame: NSRect) -> Retained<NSButton> {
    // SAFETY: `target` (the app delegate, alive for the whole process)
    // implements `uiAction:` as `-(void)x:(id)sender`.
    let b = unsafe { NSButton::buttonWithTitle_target_action(&ns(title), Some(target), Some(sel!(uiAction:)), mtm) };
    b.setTag(tag);
    b.setFrame(frame);
    b
}

fn set_target(control: &NSControl, target: &AnyObject, tag: isize) {
    control.setTag(tag);
    // SAFETY: as in `button`.
    unsafe {
        control.setTarget(Some(target));
        control.setAction(Some(sel!(uiAction:)));
    }
}

fn set_text(f: &NSTextField, text: &str) {
    if f.stringValue().to_string() != text {
        f.setStringValue(&ns(text));
    }
}

fn image_view(mtm: MainThreadMarker, frame: NSRect) -> Retained<NSImageView> {
    let v = NSImageView::initWithFrame(NSImageView::alloc(mtm), frame);
    v.setImageScaling(NSImageScaling::ScaleProportionallyUpOrDown);
    v
}

fn table(
    mtm: MainThreadMarker,
    frame: NSRect,
    tag: isize,
    row_height: f64,
    target: &AnyObject,
    source: &ProtocolObject<dyn NSTableViewDataSource>,
    delegate: &ProtocolObject<dyn NSTableViewDelegate>,
) -> (Retained<NSScrollView>, Retained<NSTableView>) {
    let scroll = NSScrollView::initWithFrame(NSScrollView::alloc(mtm), frame);
    scroll.setHasVerticalScroller(true);
    scroll.setBorderType(NSBorderType::BezelBorder);
    let t = NSTableView::initWithFrame(NSTableView::alloc(mtm), rect(0.0, 0.0, frame.size.width, frame.size.height));
    let column = NSTableColumn::initWithIdentifier(NSTableColumn::alloc(mtm), &ns("main"));
    column.setWidth(frame.size.width - 20.0);
    t.addTableColumn(&column);
    t.setHeaderView(None);
    t.setRowHeight(row_height);
    t.setStyle(NSTableViewStyle::FullWidth);
    t.setAllowsEmptySelection(true);
    t.setTag(tag);
    // SAFETY: data source and delegate are the app delegate, which outlives
    // the table; `tableDoubleClick:` is implemented by `target`.
    unsafe {
        t.setDataSource(Some(source));
        t.setDelegate(Some(delegate));
        t.setTarget(Some(target));
        t.setDoubleAction(Some(sel!(tableDoubleClick:)));
    }
    scroll.setDocumentView(Some(&t));
    (scroll, t)
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

pub struct Delegates<'a> {
    pub target: &'a AnyObject,
    pub text: &'a ProtocolObject<dyn NSTextFieldDelegate>,
    pub window: &'a ProtocolObject<dyn NSWindowDelegate>,
    pub source: &'a ProtocolObject<dyn NSTableViewDataSource>,
    pub table: &'a ProtocolObject<dyn NSTableViewDelegate>,
}

impl SitesWindow {
    pub fn new(mtm: MainThreadMarker, d: Delegates<'_>, on_flags: FlagsCallback, on_cancel: CancelCallback) -> Self {
        let this = SitesWindowView::alloc(mtm).set_ivars(SitesWindowIvars { on_flags, on_cancel });
        // SAFETY: designated initializer of NSWindow with valid arguments.
        let window: Retained<SitesWindowView> = unsafe {
            msg_send![super(this),
                initWithContentRect: rect(0.0, 0.0, W, H),
                styleMask: NSWindowStyleMask::Titled | NSWindowStyleMask::Closable,
                backing: NSBackingStoreType::Buffered,
                defer: false]
        };
        // SAFETY: we keep our own strong reference.
        unsafe { window.setReleasedWhenClosed(false) };
        window.setTitle(&ns("Master Password"));
        window.setDelegate(Some(d.window));
        window.setCollectionBehavior(
            NSWindowCollectionBehavior::MoveToActiveSpace | NSWindowCollectionBehavior::FullScreenAuxiliary,
        );
        let allow_capture = std::env::var(ALLOW_CAPTURE_ENV).is_ok_and(|v| v == "1");
        window.setSharingType(if allow_capture { NSWindowSharingType::ReadOnly } else { NSWindowSharingType::None });
        window.center();
        let content = window.contentView().expect("a titled window has a content view");
        let add = |v: &NSView| content.addSubview(v);
        let t = d.target;

        let prompt = label(mtm, "", rect(20.0, 466.0, 600.0, 22.0), 15.0);
        prompt.setFont(Some(&NSFont::boldSystemFontOfSize(15.0)));
        add(&prompt);

        // ----- users
        let (users_scroll, users_table) = table(mtm, rect(20.0, 90.0, 220.0, 362.0), TAG_USERS_TABLE, 40.0, t, d.source, d.table);
        add(&users_scroll);
        let pick_avatar = image_view(mtm, rect(RIGHT + 132.0, 346.0, 96.0, 96.0));
        add(&pick_avatar);
        let pick_name = label(mtm, "", rect(RIGHT, 316.0, RIGHT_W, 22.0), 16.0);
        pick_name.setFont(Some(&NSFont::boldSystemFontOfSize(16.0)));
        pick_name.setAlignment(NSTextAlignment::Center);
        add(&pick_name);
        let master_password = secure_field(mtm, "Master password", rect(RIGHT, 278.0, RIGHT_W, 26.0), TAG_MASTER_PASSWORD, d.text);
        add(&master_password);
        let identicon = label(mtm, "", rect(RIGHT, 240.0, RIGHT_W, 30.0), 22.0);
        identicon.setAlignment(NSTextAlignment::Center);
        identicon.setToolTip(Some(&ns(
            "Your identicon: it looks the same every time you type the same name and master password.",
        )));
        add(&identicon);
        let unlock = button(mtm, "Unlock", t, TAG_UNLOCK, rect(520.0, 196.0, 100.0, 32.0));
        add(&unlock);
        let quick_unlock = button(mtm, "Unlock with Touch ID", t, TAG_QUICK_UNLOCK, rect(RIGHT, 196.0, 200.0, 32.0));
        quick_unlock.setToolTip(Some(&ns(
            "Uses this user's derived keys saved in your login Keychain, after Touch ID or your Mac password.",
        )));
        add(&quick_unlock);
        let spinner = NSProgressIndicator::initWithFrame(NSProgressIndicator::alloc(mtm), rect(494.0, 203.0, 18.0, 18.0));
        spinner.setStyle(NSProgressIndicatorStyle::Spinning);
        spinner.setIndeterminate(true);
        spinner.setDisplayedWhenStopped(false);
        add(&spinner);

        let new_name = field(mtm, "Your full name, as on official documents", rect(RIGHT, 418.0, RIGHT_W, 26.0), TAG_NEW_NAME, d.text);
        add(&new_name);
        let new_password = secure_field(mtm, "Choose a master password", rect(RIGHT, 382.0, RIGHT_W, 26.0), TAG_NEW_PASSWORD, d.text);
        add(&new_password);
        let new_confirm = secure_field(mtm, "Type the master password again", rect(RIGHT, 346.0, RIGHT_W, 26.0), TAG_NEW_CONFIRM, d.text);
        add(&new_confirm);
        let new_avatar = image_view(mtm, rect(RIGHT, 226.0, 72.0, 72.0));
        add(&new_avatar);
        let avatar_prev = button(mtm, "◀", t, TAG_AVATAR_PREV, rect(RIGHT + 80.0, 246.0, 44.0, 32.0));
        avatar_prev.setToolTip(Some(&ns("Previous avatar")));
        add(&avatar_prev);
        let avatar_next = button(mtm, "▶", t, TAG_AVATAR_NEXT, rect(RIGHT + 126.0, 246.0, 44.0, 32.0));
        avatar_next.setToolTip(Some(&ns("Next avatar")));
        add(&avatar_next);
        let create = button(mtm, "Create User", t, TAG_CREATE, rect(500.0, 160.0, 120.0, 32.0));
        add(&create);
        let cancel_new = button(mtm, "Cancel", t, TAG_CANCEL_NEW, rect(400.0, 160.0, 100.0, 32.0));
        add(&cancel_new);

        // ----- sites
        let site = field(mtm, "Site name, e.g. apple.com", rect(20.0, 430.0, 600.0, 28.0), TAG_SITE, d.text);
        site.setFont(Some(&NSFont::systemFontOfSize(17.0)));
        add(&site);
        let (sites_scroll, sites_table) = table(mtm, rect(20.0, 90.0, 220.0, 330.0), TAG_SITES_TABLE, 24.0, t, d.source, d.table);
        add(&sites_scroll);
        let result_label = label(mtm, "", rect(RIGHT, 398.0, RIGHT_W, 18.0), 13.0);
        add(&result_label);
        let result = label(mtm, "", rect(RIGHT, 356.0, RIGHT_W, 38.0), 24.0);
        result.setFont(Some(&NSFont::monospacedSystemFontOfSize_weight(24.0, 0.0)));
        result.setAlignment(NSTextAlignment::Center);
        result.setSelectable(false);
        add(&result);
        let labels = ["Password", "Login Name", "Answer"].map(ns);
        let labels = NSArray::from_retained_slice(&labels);
        // SAFETY: `t` implements `uiAction:`.
        let purpose = unsafe {
            NSSegmentedControl::segmentedControlWithLabels_trackingMode_target_action(
                &labels,
                NSSegmentSwitchTracking::SelectOne,
                Some(t),
                Some(sel!(uiAction:)),
                mtm,
            )
        };
        purpose.setTag(TAG_PURPOSE);
        purpose.setFrame(rect(RIGHT, 318.0, RIGHT_W, 28.0));
        add(&purpose);
        let result_type = NSPopUpButton::initWithFrame_pullsDown(NSPopUpButton::alloc(mtm), rect(RIGHT, 280.0, 236.0, 30.0), false);
        set_target(&result_type, t, TAG_TYPE);
        result_type.setToolTip(Some(&ns("How this site's result is produced.")));
        add(&result_type);
        let counter_label = label(mtm, "Counter: 1", rect(504.0, 286.0, 90.0, 18.0), 13.0);
        add(&counter_label);
        let counter = NSStepper::initWithFrame(NSStepper::alloc(mtm), rect(598.0, 282.0, 20.0, 26.0));
        counter.setMinValue(1.0);
        counter.setMaxValue(crate::view_model::COUNTER_MAX as f64);
        counter.setIncrement(1.0);
        counter.setValueWraps(false);
        set_target(&counter, t, TAG_COUNTER);
        counter.setToolTip(Some(&ns("Increase the counter to get a new password for this site.")));
        add(&counter);
        let question = NSPopUpButton::initWithFrame_pullsDown(NSPopUpButton::alloc(mtm), rect(RIGHT, 244.0, 196.0, 30.0), false);
        set_target(&question, t, TAG_QUESTION);
        add(&question);
        let add_question = button(mtm, "Add…", t, TAG_ADD_QUESTION, rect(460.0, 242.0, 78.0, 32.0));
        add_question.setToolTip(Some(&ns("Add a security question keyword.")));
        add(&add_question);
        let remove_question = button(mtm, "Remove", t, TAG_REMOVE_QUESTION, rect(540.0, 242.0, 80.0, 32.0));
        add(&remove_question);
        let algorithm = label(mtm, "", rect(RIGHT, 214.0, 200.0, 18.0), 12.0);
        algorithm.setTextColor(Some(&NSColor::secondaryLabelColor()));
        add(&algorithm);
        let upgrade = button(mtm, "Upgrade to v3…", t, TAG_UPGRADE, rect(470.0, 206.0, 150.0, 32.0));
        upgrade.setToolTip(Some(&ns("Move this site to the current algorithm.  Its generated password changes.")));
        add(&upgrade);
        let delete_site = button(mtm, "Delete Site…", t, TAG_DELETE_SITE, rect(RIGHT, 168.0, 130.0, 32.0));
        add(&delete_site);
        let lock = button(mtm, "Lock", t, TAG_LOCK, rect(420.0, 90.0, 100.0, 32.0));
        add(&lock);
        let copy = button(mtm, "Copy", t, TAG_COPY, rect(520.0, 90.0, 100.0, 32.0));
        add(&copy);

        // ----- both
        let error = NSTextField::wrappingLabelWithString(&ns(""), mtm);
        error.setFrame(rect(20.0, 34.0, 600.0, 48.0));
        error.setFont(Some(&NSFont::systemFontOfSize(12.0)));
        add(&error);
        let hint = label(mtm, "", rect(20.0, 10.0, 600.0, 18.0), 11.0);
        hint.setTextColor(Some(&NSColor::tertiaryLabelColor()));
        add(&hint);

        Self {
            window,
            prompt,
            users_scroll,
            users_table,
            pick_avatar,
            pick_name,
            master_password,
            identicon,
            unlock,
            quick_unlock,
            spinner,
            new_name,
            new_password,
            new_confirm,
            new_avatar,
            avatar_prev,
            avatar_next,
            create,
            cancel_new,
            site,
            sites_scroll,
            sites_table,
            result_label,
            result,
            purpose,
            result_type,
            counter_label,
            counter,
            question,
            add_question,
            remove_question,
            algorithm,
            upgrade,
            delete_site,
            copy,
            lock,
            error,
            hint,
            last_screen: Cell::new(None),
            rendering: Cell::new(false),
            user_rows: RefCell::new(Vec::new()),
            site_rows: RefCell::new(Vec::new()),
            type_choices: RefCell::new(Vec::new()),
            questions: RefCell::new(Vec::new()),
            mtm,
        }
    }

    pub fn is_visible(&self) -> bool {
        self.window.isVisible()
    }

    pub fn is_rendering(&self) -> bool {
        self.rendering.get()
    }

    pub fn show(&self) {
        #[allow(deprecated)]
        NSApplication::sharedApplication(self.mtm).activateIgnoringOtherApps(true);
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

    fn text_field(&self, tag: isize) -> Option<&NSTextField> {
        Some(match tag {
            TAG_MASTER_PASSWORD => &self.master_password,
            TAG_SITE => &self.site,
            TAG_NEW_NAME => &self.new_name,
            TAG_NEW_PASSWORD => &self.new_password,
            TAG_NEW_CONFIRM => &self.new_confirm,
            _ => return None,
        })
    }

    pub fn text_of(&self, tag: isize) -> Option<Retained<NSString>> {
        self.text_field(tag).map(|f| f.stringValue())
    }

    /// Programmatic input (smoke test).
    pub fn set_field(&self, tag: isize, text: &str) {
        if let Some(f) = self.text_field(tag) {
            f.setStringValue(&ns(text));
        }
    }

    pub fn focus_field(&self, tag: isize) {
        if let Some(f) = self.text_field(tag) {
            self.window.makeFirstResponder(Some(f));
        }
    }

    pub fn displayed_result(&self) -> String {
        self.result.stringValue().to_string()
    }

    pub fn selected_purpose(&self) -> Option<KeyPurpose> {
        PURPOSES.get(usize::try_from(self.purpose.selectedSegment()).ok()?).copied()
    }

    pub fn selected_type(&self) -> Option<TypeChoice> {
        let index = usize::try_from(self.result_type.indexOfSelectedItem()).ok()?;
        self.type_choices.borrow().get(index).copied()
    }

    pub fn selected_question(&self) -> Option<String> {
        let index = usize::try_from(self.question.indexOfSelectedItem()).ok()?;
        self.questions.borrow().get(index).cloned()
    }

    pub fn counter_value(&self) -> u32 {
        self.counter.integerValue().clamp(1, i64::from(u32::MAX) as isize) as u32
    }

    pub fn selected_row(&self, tag: isize) -> Option<usize> {
        let t = if tag == TAG_USERS_TABLE { &self.users_table } else { &self.sites_table };
        usize::try_from(t.selectedRow()).ok()
    }

    pub fn clicked_row(&self, tag: isize) -> Option<usize> {
        let t = if tag == TAG_USERS_TABLE { &self.users_table } else { &self.sites_table };
        usize::try_from(t.clickedRow()).ok()
    }

    /// The number of rows of a table (data source).
    pub fn row_count(&self, tag: isize) -> usize {
        match tag {
            TAG_USERS_TABLE => self.user_rows.borrow().len() + 1,
            TAG_SITES_TABLE => self.site_rows.borrow().len(),
            _ => 0,
        }
    }

    /// The view of a table row (delegate).
    pub fn row_view(&self, tag: isize, row: usize) -> Option<Retained<NSView>> {
        let mtm = self.mtm;
        match tag {
            TAG_USERS_TABLE => {
                let users = self.user_rows.borrow();
                let (title, image, detail) = match users.get(row) {
                    Some(u) => (
                        u.full_name.clone(),
                        avatars::avatar(u.avatar),
                        u.saved_keys.then_some("Touch ID"),
                    ),
                    None if row == users.len() => ("New User…".to_owned(), avatars::add_user(), None),
                    None => return None,
                };
                let cell = NSView::initWithFrame(NSView::alloc(mtm), rect(0.0, 0.0, 200.0, 40.0));
                let icon = image_view(mtm, rect(4.0, 4.0, 32.0, 32.0));
                if let Some(image) = image {
                    icon.setImage(Some(&image));
                }
                cell.addSubview(&icon);
                let name = label(mtm, &title, rect(44.0, detail.map_or(11.0, |_| 18.0), 150.0, 18.0), 13.0);
                name.setLineBreakMode(objc2_app_kit::NSLineBreakMode::ByTruncatingTail);
                cell.addSubview(&name);
                if let Some(detail) = detail {
                    let d = label(mtm, detail, rect(44.0, 3.0, 150.0, 14.0), 10.0);
                    d.setTextColor(Some(&NSColor::secondaryLabelColor()));
                    cell.addSubview(&d);
                }
                Some(cell)
            }
            TAG_SITES_TABLE => {
                let sites = self.site_rows.borrow();
                let c = sites.get(row)?;
                let text = if c.known { c.name.clone() } else { format!("{}  (new site)", c.name) };
                let l = label(mtm, &text, rect(0.0, 3.0, 200.0, 18.0), 13.0);
                l.setLineBreakMode(objc2_app_kit::NSLineBreakMode::ByTruncatingTail);
                if !c.known {
                    l.setTextColor(Some(&NSColor::secondaryLabelColor()));
                }
                if c.uses > 0 {
                    l.setToolTip(Some(&ns(&format!("Used {} time{}", c.uses, if c.uses == 1 { "" } else { "s" }))));
                }
                Some(Retained::into_super(Retained::into_super(l)))
            }
            _ => None,
        }
    }

    fn focus(&self) {
        let target: &NSView = match self.last_screen.get() {
            Some(Screen::Unlocked) => &self.site,
            Some(Screen::NewUser) if self.new_name.stringValue().length() == 0 => &self.new_name,
            Some(Screen::NewUser) => &self.new_password,
            _ => &self.master_password,
        };
        self.window.makeFirstResponder(Some(target));
    }

    pub fn render(&self, view: &SitesView) {
        self.rendering.set(true);
        self.render_inner(view);
        self.rendering.set(false);
    }

    fn render_inner(&self, view: &SitesView) {
        let changed = self.last_screen.get() != Some(view.screen);
        self.last_screen.set(Some(view.screen));
        let pick = matches!(view.screen, Screen::Pick | Screen::Unlocking);
        let new = view.screen == Screen::NewUser;
        let unlocked = view.screen == Screen::Unlocked;

        set_text(&self.prompt, &view.prompt);

        // ----- user list
        self.users_scroll.setHidden(unlocked);
        if *self.user_rows.borrow() != view.users {
            *self.user_rows.borrow_mut() = view.users.clone();
            self.users_table.reloadData();
        }
        match view.picked {
            Some(i) if self.selected_row(TAG_USERS_TABLE) != Some(i) => {
                self.users_table.selectRowIndexes_byExtendingSelection(&NSIndexSet::indexSetWithIndex(i), false);
                self.users_table.scrollRowToVisible(i as isize);
            }
            None => {
                // SAFETY: plain AppKit call on the main thread.
                unsafe { self.users_table.deselectAll(None) };
            }
            _ => {}
        }
        self.users_table.setEnabled(view.screen != Screen::Unlocking);

        for v in [&*self.pick_avatar as &NSView, &self.pick_name, &self.master_password, &self.unlock] {
            v.setHidden(!pick);
        }
        self.quick_unlock.setHidden(!pick || !view.can_quick_unlock);
        self.quick_unlock.setEnabled(view.screen == Screen::Pick);
        self.pick_avatar.setImage(avatars::avatar(view.picked_avatar).as_deref());
        set_text(&self.pick_name, &view.picked_name);
        self.master_password.setEditable(view.screen == Screen::Pick);
        self.unlock.setEnabled(view.can_unlock);
        if changed {
            // Never leave a master password sitting in a field.
            for f in [&self.master_password, &self.new_password, &self.new_confirm] {
                f.setStringValue(&ns(""));
            }
            if view.screen == Screen::NewUser {
                self.new_name.setStringValue(&ns(""));
            }
        }
        if view.screen == Screen::Unlocking {
            // SAFETY: plain AppKit call on the main thread.
            unsafe { self.spinner.startAnimation(None) };
        } else {
            // SAFETY: as above.
            unsafe { self.spinner.stopAnimation(None) };
        }

        for v in [
            &*self.new_name as &NSView,
            &self.new_password,
            &self.new_confirm,
            &self.new_avatar,
            &self.avatar_prev,
            &self.avatar_next,
            &self.create,
            &self.cancel_new,
        ] {
            v.setHidden(!new);
        }
        self.cancel_new.setEnabled(!view.users.is_empty());
        self.create.setEnabled(view.can_create);
        self.new_avatar.setImage(avatars::avatar(view.new_avatar).as_deref());
        self.new_confirm.setTextColor(Some(&*match view.passwords_match {
            Some(false) => NSColor::systemRedColor(),
            _ => NSColor::labelColor(),
        }));

        self.identicon.setHidden(unlocked);
        self.identicon.setFrame(if new { rect(RIGHT + 180.0, 246.0, 180.0, 32.0) } else { rect(RIGHT, 240.0, RIGHT_W, 30.0) });
        match &view.identicon {
            Some(i) => {
                set_text(&self.identicon, &i.text());
                self.identicon.setTextColor(Some(&identicon_color(i.color)));
            }
            None => set_text(&self.identicon, ""),
        }

        // ----- sites
        for v in [
            &*self.site as &NSView,
            &self.sites_scroll,
            &self.result_label,
            &self.result,
            &self.purpose,
            &self.result_type,
            &self.copy,
            &self.lock,
        ] {
            v.setHidden(!unlocked);
        }
        set_text(&self.site, &view.site_query);
        if *self.site_rows.borrow() != view.candidates {
            *self.site_rows.borrow_mut() = view.candidates.clone();
            self.sites_table.reloadData();
        }
        match view.selection {
            Some(i) => {
                if self.selected_row(TAG_SITES_TABLE) != Some(i) {
                    self.sites_table.selectRowIndexes_byExtendingSelection(&NSIndexSet::indexSetWithIndex(i), false);
                }
                self.sites_table.scrollRowToVisible(i as isize);
            }
            // SAFETY: plain AppKit call on the main thread.
            None => unsafe { self.sites_table.deselectAll(None) },
        }
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
        self.purpose.setEnabled(view.selection.is_some());
        {
            let mut choices = self.type_choices.borrow_mut();
            if *choices != view.type_choices {
                self.result_type.removeAllItems();
                for c in &view.type_choices {
                    self.result_type.addItemWithTitle(&ns(&c.label()));
                }
                *choices = view.type_choices.clone();
            }
            self.result_type.selectItemAtIndex(view.selected_type.map_or(-1, |i| i as isize));
        }
        self.result_type.setEnabled(view.type_choices.len() > 1);

        let show_counter = unlocked && view.counter.is_some();
        self.counter_label.setHidden(!show_counter);
        self.counter.setHidden(!show_counter);
        if let Some(c) = view.counter {
            set_text(&self.counter_label, &format!("Counter: {c}"));
            self.counter.setIntegerValue(c as isize);
        }

        let show_questions = unlocked && view.questions.is_some();
        for v in [&*self.question as &NSView, &self.add_question, &self.remove_question] {
            v.setHidden(!show_questions);
        }
        if let Some((keywords, selected)) = &view.questions {
            let mut current = self.questions.borrow_mut();
            if *current != *keywords {
                self.question.removeAllItems();
                for k in keywords {
                    let title = if k.is_empty() { "Any question (site-wide)".to_owned() } else { format!("“{k}”") };
                    self.question.addItemWithTitle(&ns(&title));
                }
                *current = keywords.clone();
            }
            self.question.selectItemAtIndex(*selected as isize);
            self.remove_question.setEnabled(view.can_remove_question);
        }

        match view.algorithm.filter(|_| unlocked) {
            Some((v, outdated)) => {
                self.algorithm.setHidden(false);
                set_text(&self.algorithm, &format!("Algorithm {v}{}", if outdated { " (outdated)" } else { "" }));
                self.upgrade.setHidden(!outdated);
            }
            None => {
                self.algorithm.setHidden(true);
                self.upgrade.setHidden(true);
            }
        }
        self.delete_site.setHidden(!unlocked || !view.can_delete_site);
        self.copy.setEnabled(view.can_copy);

        match (&view.error, &view.notice) {
            (Some(e), _) => {
                set_text(&self.error, e);
                self.error.setTextColor(Some(&NSColor::systemRedColor()));
            }
            (None, Some(n)) => {
                set_text(&self.error, n);
                self.error.setTextColor(Some(&NSColor::secondaryLabelColor()));
            }
            (None, None) => set_text(&self.error, ""),
        }
        set_text(&self.hint, view.hint);

        if changed && self.window.isVisible() {
            self.focus();
        }
    }
}
