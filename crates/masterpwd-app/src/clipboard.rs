//! Clipboard hygiene.
//!
//! The original app left copied passwords on the clipboard forever.  We mark
//! them concealed/transient (see `platform::pasteboard`) and clear them after a
//! timeout, on lock and on quit — but only while the pasteboard still holds
//! *our* write (its `changeCount` is unchanged), so we never wipe something
//! the user copied afterwards.

use std::time::{Duration, Instant};

/// The bits of `NSPasteboard` we need.  Abstracted so the policy is testable.
pub trait Pasteboard {
    /// Replace the contents with `text`, marked as concealed and transient.
    /// Returns the pasteboard's change count after the write.
    fn write_secret(&mut self, text: &str) -> Result<i64, String>;
    /// The pasteboard's current change count.
    fn change_count(&self) -> i64;
    /// Remove all contents.
    fn clear(&mut self);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ownership {
    change_count: i64,
    deadline: Option<Instant>,
}

/// Remembers whether the pasteboard holds a secret we put there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardGuard {
    timeout: Option<Duration>,
    owned: Option<Ownership>,
}

impl ClipboardGuard {
    /// `timeout` of `None` (or zero) means "never clear on a timer".
    pub fn new(timeout: Option<Duration>) -> Self {
        Self { timeout: timeout.filter(|t| !t.is_zero()), owned: None }
    }

    pub fn set_timeout(&mut self, timeout: Option<Duration>, now: Instant) {
        self.timeout = timeout.filter(|t| !t.is_zero());
        if let Some(owned) = &mut self.owned {
            owned.deadline = self.timeout.map(|t| now + t);
        }
    }

    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Copy a secret and start the clear timer.
    pub fn copy(&mut self, pb: &mut dyn Pasteboard, text: &str, now: Instant) -> Result<(), String> {
        match pb.write_secret(text) {
            Ok(change_count) => {
                self.owned = Some(Ownership { change_count, deadline: self.timeout.map(|t| now + t) });
                Ok(())
            }
            Err(e) => {
                self.owned = None;
                Err(e)
            }
        }
    }

    /// Is our secret still on the pasteboard?
    pub fn holds_secret(&self, pb: &dyn Pasteboard) -> bool {
        self.owned.is_some_and(|o| o.change_count == pb.change_count())
    }

    /// Clear the pasteboard now if it still holds our secret.  Returns whether
    /// it cleared.  Either way we stop tracking it.
    pub fn clear_if_ours(&mut self, pb: &mut dyn Pasteboard) -> bool {
        let ours = self.holds_secret(pb);
        if ours {
            pb.clear();
        }
        self.owned = None;
        ours
    }

    /// Call periodically.  Clears once the timeout passed.  Returns whether it
    /// cleared.
    pub fn tick(&mut self, pb: &mut dyn Pasteboard, now: Instant) -> bool {
        match self.owned {
            Some(o) if o.change_count != pb.change_count() => {
                // Someone else wrote to the pasteboard: not ours any more.
                self.owned = None;
                false
            }
            Some(Ownership { deadline: Some(deadline), .. }) if now >= deadline => {
                self.clear_if_ours(pb)
            }
            _ => false,
        }
    }
}

/// An in-memory pasteboard for tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct FakePasteboard {
    pub contents: Option<String>,
    pub change_count: i64,
    pub fail: bool,
}

#[cfg(test)]
impl FakePasteboard {
    /// Simulate another app copying something.
    pub fn external_copy(&mut self, text: &str) {
        self.change_count += 1;
        self.contents = Some(text.to_owned());
    }
}

#[cfg(test)]
impl Pasteboard for FakePasteboard {
    fn write_secret(&mut self, text: &str) -> Result<i64, String> {
        if self.fail {
            return Err("pasteboard refused the write".into());
        }
        // clearContents + setString each bump the count on the real thing.
        self.change_count += 2;
        self.contents = Some(text.to_owned());
        Ok(self.change_count)
    }
    fn change_count(&self) -> i64 {
        self.change_count
    }
    fn clear(&mut self) {
        self.change_count += 1;
        self.contents = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);

    #[test]
    fn clears_after_timeout() {
        let t0 = Instant::now();
        let mut pb = FakePasteboard::default();
        let mut guard = ClipboardGuard::new(Some(MIN));
        guard.copy(&mut pb, "secret", t0).unwrap();
        assert!(guard.holds_secret(&pb));
        assert!(!guard.tick(&mut pb, t0 + Duration::from_secs(59)));
        assert_eq!(pb.contents.as_deref(), Some("secret"));
        assert!(guard.tick(&mut pb, t0 + MIN));
        assert_eq!(pb.contents, None);
        // Nothing left to do.
        assert!(!guard.tick(&mut pb, t0 + MIN * 2));
    }

    #[test]
    fn never_clears_someone_elses_copy() {
        let t0 = Instant::now();
        let mut pb = FakePasteboard::default();
        let mut guard = ClipboardGuard::new(Some(MIN));
        guard.copy(&mut pb, "secret", t0).unwrap();
        pb.external_copy("user's own text");
        assert!(!guard.holds_secret(&pb));
        assert!(!guard.tick(&mut pb, t0 + MIN));
        assert!(!guard.clear_if_ours(&mut pb));
        assert_eq!(pb.contents.as_deref(), Some("user's own text"));
    }

    #[test]
    fn clear_on_lock_or_quit_only_if_ours() {
        let t0 = Instant::now();
        let mut pb = FakePasteboard::default();
        let mut guard = ClipboardGuard::new(None);
        guard.copy(&mut pb, "secret", t0).unwrap();
        // No timeout: tick never clears.
        assert!(!guard.tick(&mut pb, t0 + MIN * 100));
        assert!(guard.clear_if_ours(&mut pb));
        assert_eq!(pb.contents, None);
        // Second call is a no-op.
        assert!(!guard.clear_if_ours(&mut pb));
    }

    #[test]
    fn changing_the_timeout_rearms_the_deadline() {
        let t0 = Instant::now();
        let mut pb = FakePasteboard::default();
        let mut guard = ClipboardGuard::new(None);
        guard.copy(&mut pb, "secret", t0).unwrap();
        guard.set_timeout(Some(Duration::from_secs(10)), t0 + MIN);
        assert!(!guard.tick(&mut pb, t0 + MIN + Duration::from_secs(9)));
        assert!(guard.tick(&mut pb, t0 + MIN + Duration::from_secs(10)));
        // A zero timeout means "never".
        assert_eq!(ClipboardGuard::new(Some(Duration::ZERO)).timeout(), None);
    }

    #[test]
    fn failed_write_is_reported_and_not_tracked() {
        let mut pb = FakePasteboard { fail: true, ..Default::default() };
        let mut guard = ClipboardGuard::new(Some(MIN));
        assert!(guard.copy(&mut pb, "secret", Instant::now()).is_err());
        assert!(!guard.holds_secret(&pb));
    }
}
