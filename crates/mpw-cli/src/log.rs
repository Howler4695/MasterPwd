//! Diagnostics.  Everything here goes to stderr; stdout carries only the
//! result.  Messages never contain secrets.

use std::sync::atomic::{AtomicI32, Ordering};

/// Verbosity relative to the default (`Info` = 0); `-v` adds, `-q` subtracts.
static VERBOSITY: AtomicI32 = AtomicI32::new(0);

pub const LEVEL_ERROR: i32 = -2;
pub const LEVEL_WARNING: i32 = -1;
pub const LEVEL_INFO: i32 = 0;
pub const LEVEL_DEBUG: i32 = 1;

pub fn set_verbosity(v: i32) {
    VERBOSITY.store(v, Ordering::Relaxed);
}

pub fn enabled(level: i32) -> bool {
    VERBOSITY.load(Ordering::Relaxed) >= level
}

macro_rules! log_at {
    ($level:expr, $($arg:tt)*) => {
        if $crate::log::enabled($level) {
            eprintln!($($arg)*);
        }
    };
}
macro_rules! inf { ($($arg:tt)*) => { $crate::log::log_at!($crate::log::LEVEL_INFO, $($arg)*) }; }
macro_rules! wrn { ($($arg:tt)*) => { $crate::log::log_at!($crate::log::LEVEL_WARNING, $($arg)*) }; }
macro_rules! dbg_log { ($($arg:tt)*) => { $crate::log::log_at!($crate::log::LEVEL_DEBUG, $($arg)*) }; }
pub(crate) use {dbg_log, inf, log_at, wrn};

/// A fatal error: printed (unless very quiet) and turned into the exit code.
#[derive(Debug)]
pub struct Fatal {
    pub code: i32,
    pub message: String,
}

impl Fatal {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn report(&self) {
        if enabled(LEVEL_ERROR) {
            eprintln!("{}", self.message);
        }
    }
}
