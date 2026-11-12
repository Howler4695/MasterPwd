//! Users, sites and security questions, plus the export formats and storage.
//!
//! ```no_run
//! use mpw_model::{User, UserKeys, UserStore};
//!
//! let store = UserStore::open_default()?;
//! for u in store.list()?.users {
//!     println!("{} (last used {})", u.summary.full_name, u.summary.last_used);
//! }
//!
//! let mut keys = UserKeys::from_password("Robert Lee Mitchell", "banana colored duckling");
//! let mut user = store.load("Robert Lee Mitchell", &mut keys)?; // Error::WrongMasterPassword if wrong
//! if user.site("example.com").is_none() {
//!     user.add_site("example.com")?;
//! }
//! let password = user.site_password(&mut keys, "example.com")?; // Zeroizing<String>
//! user.use_site("example.com")?;
//! store.save(&user)?;
//! # drop(password);
//! # Ok::<(), mpw_model::Error>(())
//! ```
//!
//! # Design
//!
//! * [`User`], [`Site`] and [`Question`] are plain owned data.  Fields tied to
//!   the master key (full name, key ID, algorithms, stored state) are private
//!   and changed only through methods taking an authenticated [`UserKeys`].
//! * [`UserKeys`] derives one master key per algorithm version lazily and
//!   caches it, or wraps key bytes from the Keychain.  [`User::authenticate`]
//!   must succeed before a key holder can be used with a user.
//! * Results are computed with the key of the *site's* algorithm version.
//! * [`UserFile`] reads `.mpsites` (format 0, 1) and `.mpjson`; [`write`]
//!   writes flat format 1 and JSON.  Unknown JSON members round-trip.
//!   JSON from every library generation is read (classic `sites` format 1,
//!   the old macOS app's `services` format 2, Spectre's format 2/3 with
//!   `_ext_spectre` and `result_type`); JSON is always written in the classic
//!   format-1 `sites` layout, the only one all of them read.
//! * [`UserStore`] stores users atomically with private permissions.
//!
//! # Deviations from the original app
//!
//! * A question's answer uses the question's own result type (the reference
//!   CLI's rule); the Swift app always used a phrase.
//! * A site's inherited, stored user login name is decrypted with the user's
//!   algorithm key, not the site's (they differ for non-ASCII names).
//! * Device-private passwords are never exported, not even in revealed
//!   exports; they are kept in this device's store.
//! * A failed authentication never logs the user out or changes it.
//! * Merging never changes the destination's key ID and re-encrypts stored
//!   values from the import's key to the destination's.

#![forbid(unsafe_code)]

mod error;
mod format;
mod keys;
mod merge;
mod model;
mod ops;
mod store;
mod time;

pub use error::{Error, ParseError, ParseErrorKind, Result};
pub use format::{peek, write, ExportMode, Format, UserFile, UserSummary};
pub use keys::UserKeys;
pub use merge::{merge, MergeSummary};
pub use model::{sort_most_recent_first, Question, Site, User, UserPreferences};
pub use ops::Authentication;
pub use store::{decode_name, encode_name, export_to, read_user_file, Listing, StoredUser, UserStore};
pub use time::Timestamp;

/// Re-exported for convenience: the value types used throughout the API.
pub use mpw_core::{AlgorithmVersion, Counter, Identicon, KeyId, MasterKey, ResultType, Zeroizing};

/// Bounds applied to untrusted input.
pub mod limits {
    /// Largest file read or parsed (8 MiB; real exports are a few kB).
    pub const MAX_FILE_SIZE: usize = 8 * 1024 * 1024;
    /// Most sites per user.
    pub const MAX_SITES: usize = 50_000;
    /// Most questions per site.
    pub const MAX_QUESTIONS: usize = 256;
    /// Longest full name, site name or question keyword, in bytes.
    pub const MAX_NAME_LEN: usize = 2048;
    /// Longest other string value (URL, stored state, header value), in bytes.
    pub const MAX_VALUE_LEN: usize = 64 * 1024;
}
