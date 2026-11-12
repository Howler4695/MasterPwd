//! Scheduling work on the main thread through the main *run loop*, in the
//! common modes.
//!
//! Not through the GCD main queue: that queue is serial, so while one of its
//! blocks runs a modal dialog (an import step continuing after a background
//! key derivation, say), no other main-queue block runs — timers, clipboard
//! clearing and idle locking would stall until the dialog closes.  Run-loop
//! timers and `CFRunLoopPerformBlock` blocks in the common modes keep running
//! inside modal sessions and menu tracking.

use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::Mutex;
use std::time::Duration;

use block2::{DynBlock, RcBlock};
use objc2_foundation::{NSRunLoop, NSRunLoopCommonModes, NSTimer};

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRunLoopGetMain() -> *mut c_void;
    fn CFRunLoopPerformBlock(run_loop: *mut c_void, mode: *const c_void, block: &DynBlock<dyn Fn()>);
    fn CFRunLoopWakeUp(run_loop: *mut c_void);
    static kCFRunLoopCommonModes: *const c_void;
}

/// Run `f` on the main thread soon.  Callable from any thread.
pub fn main_async(f: impl FnOnce() + Send + 'static) {
    let f = Mutex::new(Some(f));
    let block = RcBlock::new(move || {
        if let Some(f) = f.lock().ok().and_then(|mut f| f.take()) {
            f();
        }
    });
    // SAFETY: the main run loop exists for the life of the process; the mode
    // is a framework constant; CF copies (retains) the block, which only
    // touches the `Send` closure it owns.
    unsafe {
        let main = CFRunLoopGetMain();
        CFRunLoopPerformBlock(main, kCFRunLoopCommonModes, &block);
        CFRunLoopWakeUp(main);
    }
}

/// Run `f` on the main thread after `delay`.  Call on the main thread.
pub fn after(delay: Duration, f: impl FnOnce() + 'static) {
    let f = std::cell::RefCell::new(Some(f));
    let block = RcBlock::new(move |_timer: NonNull<NSTimer>| {
        if let Some(f) = f.borrow_mut().take() {
            f();
        }
    });
    // SAFETY: a one-shot timer with a valid block, added to the main run loop
    // in the common modes (a framework constant).
    unsafe {
        let timer = NSTimer::timerWithTimeInterval_repeats_block(delay.as_secs_f64(), false, &block);
        NSRunLoop::mainRunLoop().addTimer_forMode(&timer, NSRunLoopCommonModes);
    }
}
