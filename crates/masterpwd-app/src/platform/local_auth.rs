//! Device-owner authentication (Touch ID, falling back to the macOS account
//! password) through LocalAuthentication, behind a trait so the smoke test can
//! stub it.
//!
//! This is an app-level gate in front of reading the saved keys: under ad-hoc
//! signing the keys sit in the login keychain and are not bound to the
//! biometric check by the Secure Enclave.

use std::sync::Mutex;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::NSError;
use objc2_local_authentication::{LAContext, LAPolicy};

use super::ns;

pub type Done = Box<dyn FnOnce(Result<(), String>) + Send>;

pub trait DeviceAuthenticator {
    /// `Err(reason)` if it cannot be used here.
    fn availability(&self) -> Result<(), String>;
    /// Prompt; `done` is called once, on an arbitrary thread.
    fn authenticate(&self, reason: &str, done: Done);
}

/// The real thing.
pub struct LocalAuth;

impl DeviceAuthenticator for LocalAuth {
    fn availability(&self) -> Result<(), String> {
        // SAFETY: creating a context and querying a policy has no
        // preconditions.
        unsafe {
            let context = LAContext::new();
            context
                .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication)
                .map_err(|e| format!("Touch ID / password authentication is unavailable: {}.", e.localizedDescription()))
        }
    }

    fn authenticate(&self, reason: &str, done: Done) {
        let done = Mutex::new(Some(done));
        // SAFETY: as above; LAContext is documented as usable from any thread.
        let context = unsafe { LAContext::new() };
        let keep_alive = context.clone();
        let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
            let _context = &keep_alive;
            let result = if ok.as_bool() {
                Ok(())
            } else {
                // SAFETY: on failure LocalAuthentication passes a valid
                // NSError (or NULL).
                let message = unsafe { error.as_ref() }
                    .map_or_else(|| "authentication failed".to_owned(), |e| e.localizedDescription().to_string());
                Err(message)
            };
            if let Some(done) = done.lock().ok().and_then(|mut d| d.take()) {
                done(result);
            }
        });
        // SAFETY: valid policy, reason string and reply block; the block keeps
        // the context alive until it is called.
        unsafe {
            context.evaluatePolicy_localizedReason_reply(LAPolicy::DeviceOwnerAuthentication, &ns(reason), &reply);
        }
    }
}

/// Always answers `result` (smoke test).
pub struct StubAuth(pub Result<(), String>);

impl DeviceAuthenticator for StubAuth {
    fn availability(&self) -> Result<(), String> {
        Ok(())
    }

    fn authenticate(&self, _reason: &str, done: Done) {
        done(self.0.clone());
    }
}
