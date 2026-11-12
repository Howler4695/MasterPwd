//! WindowServer's view of our windows (`CGWindowListCopyWindowInfo`), used to
//! prove that the status item and the windows are really on screen.

use std::ffi::c_void;

use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2_foundation::{NSArray, NSDictionary, NSNumber, NSString};

use super::ns;

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGWindowListCopyWindowInfo(option: u32, relative_to_window: u32) -> *mut c_void;
}

const OPTION_ALL: u32 = 0;
const OPTION_ON_SCREEN_ONLY: u32 = 1 << 0;
const OPTION_INCLUDING_WINDOW: u32 = 1 << 3;

/// A window as WindowServer reports it.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowInfo {
    pub number: i64,
    pub pid: i64,
    pub layer: i64,
    pub on_screen: bool,
    /// 0 = none (excluded from capture), 1 = read-only.
    pub sharing: i64,
    pub name: String,
    /// x, y, width, height (top-left origin, points).
    pub bounds: (f64, f64, f64, f64),
}

fn list(option: u32, window: u32) -> Vec<WindowInfo> {
    // SAFETY: plain C call; returns a +1 CFArrayRef of CFDictionaryRef (or
    // NULL), toll-free bridged to NSArray<NSDictionary>, which we take over.
    let array: Option<Retained<NSArray<NSDictionary<NSString, AnyObject>>>> = unsafe {
        let raw = CGWindowListCopyWindowInfo(option, window);
        Retained::from_raw(raw.cast())
    };
    let Some(array) = array else { return Vec::new() };
    let num = |d: &NSDictionary<NSString, AnyObject>, key: &str| -> Option<Retained<NSNumber>> {
        d.objectForKey(&ns(key)).and_then(|o| o.downcast::<NSNumber>().ok())
    };
    array
        .iter()
        .map(|d| {
            let bounds = d
                .objectForKey(&ns("kCGWindowBounds"))
                .and_then(|o| o.downcast::<NSDictionary>().ok())
                .map(|b| {
                    // SAFETY: kCGWindowBounds is a dictionary of NSString -> NSNumber.
                    let b: Retained<NSDictionary<NSString, AnyObject>> = unsafe { Retained::cast_unchecked(b) };
                    let f = |k: &str| num(&b, k).map_or(0.0, |n| n.doubleValue());
                    (f("X"), f("Y"), f("Width"), f("Height"))
                })
                .unwrap_or_default();
            WindowInfo {
                number: num(&d, "kCGWindowNumber").map_or(0, |n| n.longLongValue()),
                pid: num(&d, "kCGWindowOwnerPID").map_or(0, |n| n.longLongValue()),
                layer: num(&d, "kCGWindowLayer").map_or(0, |n| n.longLongValue()),
                on_screen: num(&d, "kCGWindowIsOnscreen").is_some_and(|n| n.boolValue()),
                sharing: num(&d, "kCGWindowSharingState").map_or(-1, |n| n.longLongValue()),
                name: d
                    .objectForKey(&ns("kCGWindowName"))
                    .and_then(|o| o.downcast::<NSString>().ok())
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                bounds,
            }
        })
        .collect()
}

/// One window by number (on screen or not).
pub fn window(number: i64) -> Option<WindowInfo> {
    let n = u32::try_from(number).ok()?;
    list(OPTION_INCLUDING_WINDOW, n).into_iter().find(|w| w.number == number)
}

/// Every window WindowServer knows about (any owner).
pub fn all_windows() -> Vec<WindowInfo> {
    list(OPTION_ALL, 0)
}

/// All windows of this process (on screen or not).
pub fn own_windows() -> Vec<WindowInfo> {
    let pid = i64::from(std::process::id());
    list(OPTION_ALL, 0).into_iter().filter(|w| w.pid == pid).collect()
}

/// This process's windows that WindowServer currently shows.
pub fn own_on_screen_windows() -> Vec<WindowInfo> {
    let pid = i64::from(std::process::id());
    list(OPTION_ON_SCREEN_ONLY, 0).into_iter().filter(|w| w.pid == pid).collect()
}
