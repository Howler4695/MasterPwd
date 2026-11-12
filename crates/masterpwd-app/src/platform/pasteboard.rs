//! `NSPasteboard` behind [`crate::clipboard::Pasteboard`].
//!
//! Secrets are written together with the `org.nspasteboard.ConcealedType` and
//! `org.nspasteboard.TransientType` marker types (<http://nspasteboard.org>),
//! which clipboard managers and Universal Clipboard-aware tools honour by not
//! recording or syncing the item.

use objc2::rc::Retained;
use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};
use objc2_foundation::{NSArray, NSData, NSString};

use super::ns;
use crate::clipboard::Pasteboard;

pub const CONCEALED_TYPE: &str = "org.nspasteboard.ConcealedType";
pub const TRANSIENT_TYPE: &str = "org.nspasteboard.TransientType";

pub struct SystemPasteboard {
    pb: Retained<NSPasteboard>,
    /// Private pasteboards (smoke test) are released when dropped.
    private: bool,
}

impl SystemPasteboard {
    /// The general (system-wide) pasteboard.
    pub fn general() -> Self {
        Self { pb: NSPasteboard::generalPasteboard(), private: false }
    }

    /// A uniquely named pasteboard nobody else sees (for the smoke test, so it
    /// doesn't clobber the user's clipboard).
    pub fn private() -> Self {
        Self { pb: NSPasteboard::pasteboardWithUniqueName(), private: true }
    }

    /// Another handle on the same pasteboard (does not release it on drop).
    pub fn shared(&self) -> Self {
        Self { pb: self.pb.clone(), private: false }
    }

    /// The plain-text contents (smoke test only).
    pub fn string(&self) -> Option<String> {
        // SAFETY: NSPasteboardTypeString is an immutable framework constant.
        let t = unsafe { NSPasteboardTypeString };
        self.pb.stringForType(t).map(|s| s.to_string())
    }

    /// The declared types (smoke test only).
    pub fn type_names(&self) -> Vec<String> {
        self.pb.types().map(|a| a.iter().map(|t| t.to_string()).collect()).unwrap_or_default()
    }
}

impl Pasteboard for SystemPasteboard {
    fn write_secret(&mut self, text: &str) -> Result<i64, String> {
        let concealed = ns(CONCEALED_TYPE);
        let transient = ns(TRANSIENT_TYPE);
        // SAFETY: NSPasteboardTypeString is an immutable framework constant.
        let string_type: &NSString = unsafe { NSPasteboardTypeString };
        let types = NSArray::from_slice(&[string_type, &*concealed, &*transient]);
        // SAFETY: `types` is an NSArray of NSString pasteboard types, as
        // required; a nil owner means we provide all data up front.
        unsafe { self.pb.declareTypes_owner(&types, None) };
        let empty = NSData::new();
        let ok = self.pb.setString_forType(&ns(text), string_type)
            && self.pb.setData_forType(Some(&empty), &concealed)
            && self.pb.setData_forType(Some(&empty), &transient);
        if ok {
            Ok(self.pb.changeCount() as i64)
        } else {
            self.pb.clearContents();
            Err("the pasteboard refused the password".into())
        }
    }

    fn change_count(&self) -> i64 {
        self.pb.changeCount() as i64
    }

    fn clear(&mut self) {
        self.pb.clearContents();
    }
}

impl Drop for SystemPasteboard {
    fn drop(&mut self) {
        if self.private {
            // SAFETY: `-releaseGlobally` takes no arguments and returns void;
            // we only call it on our own uniquely named pasteboard.
            let _: () = unsafe { objc2::msg_send![&*self.pb, releaseGlobally] };
        }
    }
}
