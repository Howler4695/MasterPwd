//! On-disk storage of users: one `.mpjson` file per user in a directory.
//!
//! * Writes are atomic: a temporary file in the same directory is written,
//!   flushed to disk and renamed over the target, so a crash or a failed write
//!   never leaves a truncated user file.  Files are created `0600`, the store
//!   directory `0700`.
//! * File names are derived from the full name with a reversible, case- and
//!   normalisation-proof encoding (lower-case letters, digits, space, `-`, `_`,
//!   and non-leading `.` are kept; an upper-case letter `X` becomes `^x`; every
//!   other byte becomes `%XX`).  Names whose encoding would be too long are
//!   truncated and suffixed with `~` and a hash; for those the file's embedded
//!   full name is verified before it is overwritten.  The embedded full name
//!   is always authoritative; the file name is never trusted.
//! * Symlinks and other non-regular files in the store are never followed.
//! * Files of the original app (any `*.mpsites` / `*.mpjson` in the
//!   directory) are listed and loaded too; once a user is saved, its old files
//!   are removed in favour of the canonical one.

use crate::error::{Error, ParseErrorKind, Result};
use crate::format::{self, Content, ExportMode, Format, UserFile, UserSummary};
use crate::keys::UserKeys;
use crate::limits;
use crate::merge::{merge, MergeSummary};
use crate::model::{validate_full_name, User};
use crate::time::Timestamp;
use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

/// The longest file-name stem we produce (file systems allow 255 bytes).
const MAX_STEM: usize = 200;
/// Where a hashed stem is cut before `~<hash>`.
const HASHED_PREFIX: usize = 160;

/// A directory of user files.
#[derive(Debug, Clone)]
pub struct UserStore {
    dir: PathBuf,
}

/// A user found in the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredUser {
    pub path: PathBuf,
    pub summary: UserSummary,
}

/// The result of [`UserStore::list`].
#[derive(Debug, Default)]
pub struct Listing {
    /// One entry per full name, most recently used first.
    pub users: Vec<StoredUser>,
    /// Files that look like user files but could not be read.
    pub unreadable: Vec<(PathBuf, Error)>,
}

impl UserStore {
    /// `~/Library/Application Support/MasterPwd/Users`, from `$HOME`.
    pub fn default_dir() -> Result<PathBuf> {
        let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).ok_or(Error::NoHomeDirectory)?;
        Ok(PathBuf::from(home).join("Library/Application Support/MasterPwd/Users"))
    }

    /// The store in [`UserStore::default_dir`].
    pub fn open_default() -> Result<Self> {
        Self::open(Self::default_dir()?)
    }

    /// Use `dir` as a store, creating it (mode `0700`) if it does not exist.
    /// An existing directory's permissions are left alone.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        if !dir.is_dir() {
            DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
        }
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The canonical path of a user's file.
    pub fn path_for(&self, full_name: &str) -> PathBuf {
        self.dir.join(format!("{}.{}", encode_name(full_name), Format::Json.extension()))
    }

    /// Peek at every user file.  Cheap: nothing is authenticated.
    pub fn list(&self) -> Result<Listing> {
        let mut listing = Listing::default();
        let mut found: Vec<StoredUser> = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if !is_user_file_name(entry.file_name().as_os_str()) {
                continue;
            }
            match read_file(&path).and_then(|bytes| format::peek(&bytes)) {
                Ok(summary) => found.push(StoredUser { path, summary }),
                Err(Error::UnsafePath(_)) => {}
                Err(e) => listing.unreadable.push((path, e)),
            }
        }
        // One entry per name: the canonical file wins, then the most recent.
        found.sort_by(|a, b| {
            let canon = |s: &StoredUser| s.path == self.path_for(&s.summary.full_name);
            a.summary
                .full_name
                .cmp(&b.summary.full_name)
                .then(canon(b).cmp(&canon(a)))
                .then(b.summary.last_used.cmp(&a.summary.last_used))
                .then(a.path.cmp(&b.path))
        });
        found.dedup_by(|later, first| later.summary.full_name == first.summary.full_name);
        found.sort_by(|a, b| {
            b.summary
                .last_used
                .cmp(&a.summary.last_used)
                .then(a.summary.full_name.cmp(&b.summary.full_name))
        });
        listing.users = found;
        Ok(listing)
    }

    /// All files holding `full_name`, canonical first.
    fn files_of(&self, full_name: &str) -> Result<Vec<PathBuf>> {
        let canonical = self.path_for(full_name);
        let mut paths = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            if !is_user_file_name(entry.file_name().as_os_str()) {
                continue;
            }
            let path = entry.path();
            if let Ok(summary) = read_file(&path).and_then(|b| format::peek(&b)) {
                if summary.full_name == full_name {
                    paths.push(path);
                }
            }
        }
        paths.sort_by_key(|p| *p != canonical);
        Ok(paths)
    }

    /// Whether a user with this full name is stored.
    pub fn contains(&self, full_name: &str) -> Result<bool> {
        Ok(!self.files_of(full_name)?.is_empty())
    }

    /// Parse a stored user's file (not yet authenticated).
    pub fn open_user(&self, full_name: &str) -> Result<UserFile> {
        let listing = self.list()?;
        let entry = listing
            .users
            .iter()
            .find(|u| u.summary.full_name == full_name)
            .ok_or(Error::UserNotFound)?;
        let file = UserFile::parse(&read_file(&entry.path)?)?;
        if file.summary().full_name != full_name {
            return Err(Error::UserNotFound); // changed under us
        }
        Ok(file)
    }

    /// Load and authenticate a stored user.
    pub fn load(&self, full_name: &str, keys: &mut UserKeys) -> Result<User> {
        self.open_user(full_name)?.load(keys)
    }

    /// Load a stored user without authenticating (see [`UserFile::load_locked`]).
    pub fn load_locked(&self, full_name: &str) -> Result<User> {
        self.open_user(full_name)?.load_locked()
    }

    /// Store a user that is not in the store yet.
    pub fn create(&self, user: &User) -> Result<PathBuf> {
        if self.contains(&user.full_name)? {
            return Err(Error::UserExists);
        }
        self.save(user)
    }

    /// Write the user to its canonical file, atomically replacing any previous
    /// version (this is also "replace on import").  Device-private passwords
    /// are kept, since this is the device's own store.  Older files of the same
    /// user are removed afterwards.
    pub fn save(&self, user: &User) -> Result<PathBuf> {
        validate_full_name(&user.full_name)?;
        let path = self.path_for(&user.full_name);
        if let Some(meta) = lstat(&path)? {
            if !meta.is_file() {
                return Err(Error::UnsafePath(path));
            }
            if is_hashed_name(&path) {
                let owner = read_file(&path).and_then(|b| format::peek(&b));
                if !matches!(&owner, Ok(s) if s.full_name == user.full_name) {
                    return Err(Error::NameCollision(path));
                }
            }
        }
        let data = format::write_with(user, Format::Json, Content::Storage, Timestamp::now())?;
        write_atomic(&path, data.as_bytes())?;
        for old in self.files_of(&user.full_name)? {
            if old != path {
                let _ = fs::remove_file(&old);
            }
        }
        Ok(path)
    }

    /// Remove every file of the user.
    pub fn delete(&self, full_name: &str) -> Result<()> {
        let files = self.files_of(full_name)?;
        if files.is_empty() {
            return Err(Error::UserNotFound);
        }
        for f in files {
            fs::remove_file(f)?;
        }
        Ok(())
    }

    /// Merge an imported user into the stored user of the same full name and
    /// save the result.  `imported_keys` must have unlocked `imported`;
    /// `existing_keys` is authenticated against the stored user here.
    pub fn merge_into(
        &self,
        imported: &User,
        imported_keys: &mut UserKeys,
        existing_keys: &mut UserKeys,
    ) -> Result<(User, MergeSummary)> {
        let mut existing = self.load(&imported.full_name, existing_keys)?;
        let summary = merge(&mut existing, existing_keys, imported, imported_keys)?;
        self.save(&existing)?;
        Ok((existing, summary))
    }
}

/// Write an export of `user` to `path` (atomically, mode `0600`).
pub fn export_to(path: &Path, user: &User, format: Format, mode: ExportMode<'_>) -> Result<()> {
    let data = format::write(user, format, mode)?;
    write_atomic(path, data.as_bytes())
}

/// Read an export file from anywhere (size-limited, regular files only).
pub fn read_user_file(path: &Path) -> Result<UserFile> {
    UserFile::parse(&read_file(path)?)
}

// ------------------------------------------------------------------- naming

/// Encode a full name as a file-name stem (see the module docs).
pub fn encode_name(full_name: &str) -> String {
    let mut out = String::new();
    for (i, ch) in full_name.chars().enumerate() {
        match ch {
            'a'..='z' | '0'..='9' | ' ' | '-' | '_' => out.push(ch),
            '.' if i > 0 => out.push(ch),
            'A'..='Z' => {
                out.push('^');
                out.push(ch.to_ascii_lowercase());
            }
            _ => {
                let mut buf = [0u8; 4];
                for b in ch.encode_utf8(&mut buf).bytes() {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
        }
    }
    if out.len() > MAX_STEM {
        // Cut on a boundary that does not split an escape.
        let mut cut = HASHED_PREFIX;
        while cut > 0 && (out[..cut].ends_with('^') || out[cut.saturating_sub(2)..cut].contains('%')) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str(&format!("~{:016x}", fnv1a(full_name.as_bytes())));
    }
    out
}

/// Decode a stem made by [`encode_name`]; `None` for hashed or foreign names.
pub fn decode_name(stem: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let mut it = stem.bytes();
    while let Some(b) = it.next() {
        match b {
            b'^' => bytes.push(it.next().filter(u8::is_ascii_lowercase)?.to_ascii_uppercase()),
            b'%' => {
                let hex = [it.next()?, it.next()?];
                let hex = std::str::from_utf8(&hex).ok()?;
                if hex.bytes().any(|c| c.is_ascii_lowercase()) {
                    return None;
                }
                bytes.push(u8::from_str_radix(hex, 16).ok()?);
            }
            b'a'..=b'z' | b'0'..=b'9' | b' ' | b'-' | b'_' | b'.' => bytes.push(b),
            _ => return None,
        }
    }
    let name = String::from_utf8(bytes).ok()?;
    (encode_name(&name) == stem).then_some(name)
}

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3))
}

fn is_hashed_name(path: &Path) -> bool {
    path.file_stem().and_then(OsStr::to_str).is_some_and(|s| s.contains('~'))
}

fn is_user_file_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else { return false };
    !name.starts_with('.')
        && matches!(
            Path::new(name).extension().and_then(OsStr::to_str),
            Some("mpjson" | "mpsites")
        )
}

// ----------------------------------------------------------------------- I/O

fn lstat(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(m) => Ok(Some(m)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Read a regular, size-limited file without following a symlink: the file
/// opened must be the very inode `lstat` saw.
fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let meta = lstat(path)?.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    if !meta.file_type().is_file() {
        return Err(Error::UnsafePath(path.to_owned()));
    }
    if meta.len() > limits::MAX_FILE_SIZE as u64 {
        return Err(crate::error::ParseError::new(
            ParseErrorKind::TooLarge { max: limits::MAX_FILE_SIZE },
            None,
            "",
        )
        .into());
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != meta.dev() || opened.ino() != meta.ino() || !opened.is_file() {
        return Err(Error::UnsafePath(path.to_owned()));
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0).min(limits::MAX_FILE_SIZE) + 1));
    (&mut file).take(limits::MAX_FILE_SIZE as u64 + 1).read_to_end(&mut buf)?;
    Ok(buf)
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `data` to `path` atomically: temp file in the same directory (created
/// exclusively, mode 0600), fsync, rename, fsync the directory.
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let base = path.file_name().and_then(OsStr::to_str).unwrap_or("user");
    let tmp = dir.join(format!(
        ".{}.{}-{}.tmp",
        base.chars().take(100).collect::<String>(),
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_never_collide() {
        let names = [
            "Robert Lee Mitchell",
            "robert lee mitchell",
            "..",
            ".hidden",
            "a/b",
            "a\\b",
            "tab\there",
            "nul\0byte",
            "line\nbreak",
            "⛄",
            "e\u{301}",
            "\u{e9}",
            "100% ^caret^",
            "~tilde",
        ];
        let mut stems = std::collections::HashSet::new();
        for n in names {
            let stem = encode_name(n);
            assert!(!stem.starts_with('.'), "{stem}");
            assert!(!stem.contains(['/', '\0', '\n', '\t', '\\']), "{stem}");
            assert!(stems.insert(stem.to_ascii_lowercase()), "case-insensitive collision for {n:?}");
            assert_eq!(decode_name(&stem).as_deref(), Some(n));
        }
    }

    #[test]
    fn long_names_are_hashed_and_bounded() {
        let a = "é".repeat(300);
        let b = format!("{}x", "é".repeat(299));
        let (sa, sb) = (encode_name(&a), encode_name(&b));
        assert!(sa.len() <= MAX_STEM && sb.len() <= MAX_STEM);
        assert_ne!(sa, sb);
        assert!(sa.contains('~'));
        assert_eq!(decode_name(&sa), None);
    }
}
