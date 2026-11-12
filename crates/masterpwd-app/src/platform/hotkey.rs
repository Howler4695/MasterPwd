//! Global hotkeys through Carbon's `RegisterEventHotKey`, like the original.
//!
//! Unlike an event tap this needs no Accessibility permission and never sees
//! any other keystroke: the system only tells us when our combination is
//! pressed.  Carbon's event API is old but still supported on Apple Silicon
//! and is what every hotkey library uses under the hood.

use std::ffi::c_void;
use std::ptr;

type OSStatus = i32;
type EventTargetRef = *mut c_void;
type EventHandlerRef = *mut c_void;
type EventHandlerCallRef = *mut c_void;
type EventRef = *mut c_void;
type EventHotKeyRef = *mut c_void;
type EventHandlerProc = extern "C" fn(EventHandlerCallRef, EventRef, *mut c_void) -> OSStatus;

#[repr(C)]
struct EventTypeSpec {
    event_class: u32,
    event_kind: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EventHotKeyID {
    signature: u32,
    id: u32,
}

#[link(name = "Carbon", kind = "framework")]
extern "C" {
    fn GetApplicationEventTarget() -> EventTargetRef;
    fn InstallEventHandler(
        target: EventTargetRef,
        handler: EventHandlerProc,
        num_types: usize,
        list: *const EventTypeSpec,
        user_data: *mut c_void,
        out_ref: *mut EventHandlerRef,
    ) -> OSStatus;
    fn RemoveEventHandler(handler: EventHandlerRef) -> OSStatus;
    fn RegisterEventHotKey(
        key_code: u32,
        modifiers: u32,
        id: EventHotKeyID,
        target: EventTargetRef,
        options: u32,
        out_ref: *mut EventHotKeyRef,
    ) -> OSStatus;
    fn UnregisterEventHotKey(hot_key: EventHotKeyRef) -> OSStatus;
    fn GetEventParameter(
        event: EventRef,
        name: u32,
        desired_type: u32,
        actual_type: *mut u32,
        buffer_size: usize,
        actual_size: *mut usize,
        data: *mut c_void,
    ) -> OSStatus;
}

const fn four_cc(s: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*s)
}

const NO_ERR: OSStatus = 0;
const EVENT_NOT_HANDLED_ERR: OSStatus = -9874;
const K_EVENT_CLASS_KEYBOARD: u32 = four_cc(b"keyb");
const K_EVENT_HOT_KEY_PRESSED: u32 = 5;
const K_EVENT_PARAM_DIRECT_OBJECT: u32 = four_cc(b"----");
const TYPE_EVENT_HOT_KEY_ID: u32 = four_cc(b"hkid");
const CMD_KEY: u32 = 1 << 8;
const OPTION_KEY: u32 = 1 << 11;
const CONTROL_KEY: u32 = 1 << 12;
/// `kVK_ANSI_P`.
const KEY_P: u32 = 35;
const SIGNATURE: u32 = four_cc(b"MPwd");

/// The hotkeys we register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotKey {
    /// ⌃⌘P: show the sites window.
    Show = 1,
    /// ⌃⌥⌘P: lock.
    Lock = 2,
}

/// Registered hotkeys; unregistered on drop.
pub struct HotKeys {
    handler: EventHandlerRef,
    keys: Vec<EventHotKeyRef>,
}

/// What a hotkey press calls.  Runs on the main thread.
pub type Callback = fn(HotKey);

extern "C" fn handle_event(_next: EventHandlerCallRef, event: EventRef, user_data: *mut c_void) -> OSStatus {
    let mut id = EventHotKeyID { signature: 0, id: 0 };
    // SAFETY: `event` is the live event Carbon passes us; we ask for the
    // direct-object parameter typed as an EventHotKeyID into a buffer of
    // exactly that size.
    let status = unsafe {
        GetEventParameter(
            event,
            K_EVENT_PARAM_DIRECT_OBJECT,
            TYPE_EVENT_HOT_KEY_ID,
            ptr::null_mut(),
            std::mem::size_of::<EventHotKeyID>(),
            ptr::null_mut(),
            (&mut id as *mut EventHotKeyID).cast(),
        )
    };
    if status != NO_ERR || id.signature != SIGNATURE {
        return EVENT_NOT_HANDLED_ERR;
    }
    let key = match id.id {
        1 => HotKey::Show,
        2 => HotKey::Lock,
        _ => return EVENT_NOT_HANDLED_ERR,
    };
    // SAFETY: `user_data` is the `Callback` fn pointer we registered in
    // `register`; fn pointers round-trip through `*mut c_void` on Apple
    // platforms.
    let callback: Callback = unsafe { std::mem::transmute::<*mut c_void, Callback>(user_data) };
    // Never unwind into Carbon.
    if std::panic::catch_unwind(|| callback(key)).is_err() {
        eprintln!("MasterPwd: hotkey handler panicked");
    }
    NO_ERR
}

/// Register ⌃⌘P (show) and ⌃⌥⌘P (lock).  Must be called on the main thread.
/// Returns the registered keys and a message for each one that failed (e.g.
/// already taken by another app).
pub fn register(callback: Callback) -> (HotKeys, Vec<String>) {
    let mut errors = Vec::new();
    let spec = EventTypeSpec { event_class: K_EVENT_CLASS_KEYBOARD, event_kind: K_EVENT_HOT_KEY_PRESSED };
    let mut handler: EventHandlerRef = ptr::null_mut();
    // SAFETY: we pass a valid handler with the C ABI Carbon expects, one
    // event spec, and a fn pointer as user data that lives forever.
    let status = unsafe {
        InstallEventHandler(
            GetApplicationEventTarget(),
            handle_event,
            1,
            &spec,
            callback as *mut c_void,
            &mut handler,
        )
    };
    if status != NO_ERR {
        errors.push(format!("could not install the hotkey handler (OSStatus {status})"));
        return (HotKeys { handler: ptr::null_mut(), keys: Vec::new() }, errors);
    }
    let mut keys = Vec::new();
    for (key, modifiers, label) in [
        (HotKey::Show, CONTROL_KEY | CMD_KEY, "⌃⌘P"),
        (HotKey::Lock, CONTROL_KEY | OPTION_KEY | CMD_KEY, "⌃⌥⌘P"),
    ] {
        let mut hot_key: EventHotKeyRef = ptr::null_mut();
        let id = EventHotKeyID { signature: SIGNATURE, id: key as u32 };
        // SAFETY: plain value arguments and a valid out-pointer.
        let status =
            unsafe { RegisterEventHotKey(KEY_P, modifiers, id, GetApplicationEventTarget(), 0, &mut hot_key) };
        if status == NO_ERR && !hot_key.is_null() {
            keys.push(hot_key);
        } else {
            errors.push(format!("could not register {label} (OSStatus {status}; is another app using it?)"));
        }
    }
    (HotKeys { handler, keys }, errors)
}

impl HotKeys {
    pub fn count(&self) -> usize {
        self.keys.len()
    }
}

impl Drop for HotKeys {
    fn drop(&mut self) {
        for key in self.keys.drain(..) {
            // SAFETY: each ref came from a successful RegisterEventHotKey and
            // is unregistered exactly once.
            unsafe { UnregisterEventHotKey(key) };
        }
        if !self.handler.is_null() {
            // SAFETY: the ref came from a successful InstallEventHandler.
            unsafe { RemoveEventHandler(self.handler) };
        }
    }
}
