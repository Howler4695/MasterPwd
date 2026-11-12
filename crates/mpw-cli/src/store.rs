//! User-file persistence, compatible with the reference CLI's location:
//! `~/.mpw.d/<full name>.<ext>` (`cli_user` / `cli_save` in `mpw-cli.c`).
//!
//! Reading uses `mpw_model::read_user_file` (regular files only, symlinks
//! refused, size-limited); writing uses `mpw_model::export_to` (temp file
//! created exclusively with mode 0600, fsync, rename; a rename replaces a
//! directory entry and never follows a symlink).  On top of that this module:
//!
//! * maps the full name to a file name that cannot leave `~/.mpw.d` or be
//!   hidden: `/` becomes `_` (as in the reference), a leading `.` becomes `_`
//!   (deviation: the reference would create a hidden file), control
//!   characters are refused (the model refuses such names anyway), and
//!   over-long names are refused;
//! * refuses a `~/.mpw.d` that is a symlink or not a directory, creates it
//!   `0700`, and warns if it is group/world-writable;
//! * refuses to read or replace a user file that is a symlink;
//! * refuses a file whose embedded full name differs from the one given
//!   (`a/b` and `a_b`, or `Bob` and `bob` on a case-insensitive disk, map to
//!   the same file) instead of silently using the other user's file.

use crate::log::{dbg_log, wrn, Fatal};
use crate::{EX_CANTCREAT, EX_DATAERR, EX_IOERR};
use std::fs::{self, DirBuilder};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The longest file name we create (file systems allow 255 bytes).
const MAX_FILE_NAME: usize = 255;

/// User-file format, as named by `-f`/`-F`/`MPW_FORMAT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    None,
    Flat,
    Json,
}

impl Format {
    /// `MPMarshalFormatDefault` of the reference (built with JSON support).
    pub const DEFAULT: Self = Self::Json;

    /// Case-insensitive prefix match, like `mpw_format_named`.
    pub fn named(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        [
            ("none", Self::None),
            ("flat", Self::Flat),
            ("json", Self::Json),
        ]
        .into_iter()
        .find(|(n, _)| n.starts_with(&lower))
        .map(|(_, f)| f)
    }

    /// `mpw_format_extensions`: the first one is written.
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::None => &[],
            Self::Flat => &["mpsites", "mpsites.txt", "txt"],
            Self::Json => &["mpjson", "mpsites.json", "json"],
        }
    }

    pub fn model(self) -> Option<mpw_model::Format> {
        match self {
            Self::None => None,
            Self::Flat => Some(mpw_model::Format::Flat),
            Self::Json => Some(mpw_model::Format::Json),
        }
    }
}

/// File options from the command line / environment.
#[derive(Debug)]
pub struct Options {
    pub format: Format,
    /// `-F`: read and write only `format`.  `-f`/`MPW_FORMAT`: read `format`
    /// first, fall back to the others, write the default format.
    pub format_fixed: bool,
    /// `-R`: `Some(false)` only when the user explicitly asked for a revealed
    /// (clear-text) file.
    pub redacted: Option<bool>,
}

impl Options {
    pub fn parse(format: Option<&str>, fixed: bool, redacted: Option<&str>) -> Result<Self, Fatal> {
        let format = match format {
            None => Format::DEFAULT,
            Some(name) => Format::named(name)
                .ok_or_else(|| Fatal::new(EX_DATAERR, format!("Invalid sites format: {name}")))?,
        };
        // `mpw_get_bool`: starts with 'y' or 't', or is a positive number.
        let redacted = redacted
            .map(|r| r.starts_with(['y', 't']) || r.trim().parse::<i64>().is_ok_and(|n| n > 0));
        Ok(Self {
            format,
            format_fixed: fixed,
            redacted,
        })
    }

    /// `-F none`: no user file at all.
    pub fn stateless(&self) -> bool {
        self.format_fixed && self.format == Format::None
    }

    /// The format to write (`cli_save`).
    pub fn save_format(&self) -> Format {
        if self.format_fixed {
            self.format
        } else {
            Format::DEFAULT
        }
    }

    /// The formats to try when reading, in order (`cli_user`).
    fn read_formats(&self) -> Vec<Format> {
        let mut formats = vec![self.format];
        if !self.format_fixed {
            // MPMarshalFormatLast .. MPMarshalFormatFirst
            for f in [Format::Json, Format::Flat] {
                if !formats.contains(&f) {
                    formats.push(f);
                }
            }
        }
        formats
    }
}

/// `~/.mpw.d`.
pub fn default_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(|home| PathBuf::from(home).join(".mpw.d"))
}

/// The user-file directory and the file-name stem for one full name.
#[derive(Debug)]
pub struct Location {
    dir: PathBuf,
    stem: String,
}

impl Location {
    pub fn new(dir: PathBuf, full_name: &str) -> Result<Self, Fatal> {
        Ok(Self {
            dir,
            stem: file_stem(full_name)?,
        })
    }

    pub fn path(&self, extension: &str) -> PathBuf {
        self.dir.join(format!("{}.{extension}", self.stem))
    }

    /// Find an existing user file (`cli_user_open` with the fallback rules).
    pub fn find(&self, options: &Options) -> Result<Option<PathBuf>, Fatal> {
        if !self.check_dir(false)? {
            return Ok(None);
        }
        for format in options.read_formats() {
            for ext in format.extensions() {
                let path = self.path(ext);
                match fs::symlink_metadata(&path) {
                    Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
                        return Err(Fatal::new(
                            EX_DATAERR,
                            format!(
                                "Refusing to use {}: it is a symlink or not a regular file.",
                                path.display()
                            ),
                        ));
                    }
                    Ok(_) => return Ok(Some(path)),
                    Err(e) if e.kind() == ErrorKind::NotFound => {
                        dbg_log!(
                            "Couldn't open configuration file:\n  {}: not found",
                            path.display()
                        );
                    }
                    Err(e) => {
                        return Err(Fatal::new(
                            EX_IOERR,
                            format!(
                                "Couldn't open configuration file:\n  {}: {e}",
                                path.display()
                            ),
                        ))
                    }
                }
            }
        }
        Ok(None)
    }

    /// Check the directory; with `create`, make it (mode 0700) if missing.
    /// Returns whether it exists.
    fn check_dir(&self, create: bool) -> Result<bool, Fatal> {
        let display = self.dir.display();
        match fs::symlink_metadata(&self.dir) {
            Ok(meta) if meta.file_type().is_symlink() => Err(Fatal::new(
                EX_CANTCREAT,
                format!("Refusing to use {display}: it is a symlink."),
            )),
            Ok(meta) if !meta.is_dir() => Err(Fatal::new(
                EX_CANTCREAT,
                format!("Refusing to use {display}: it is not a directory."),
            )),
            Ok(meta) => {
                if meta.permissions().mode() & 0o022 != 0 {
                    wrn!("Warning: {display} is writable by other users; consider chmod 700.");
                }
                Ok(true)
            }
            Err(e) if e.kind() == ErrorKind::NotFound && create => {
                DirBuilder::new()
                    .mode(0o700)
                    .create(&self.dir)
                    .map_err(|e| {
                        Fatal::new(EX_CANTCREAT, format!("Couldn't create {display}: {e}"))
                    })?;
                Ok(true)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Fatal::new(
                EX_IOERR,
                format!("Couldn't access {display}: {e}"),
            )),
        }
    }

    /// Write the user file for `format` (`cli_save`), atomically, mode 0600.
    pub fn save(
        &self,
        user: &mpw_model::User,
        format: Format,
        mode: mpw_model::ExportMode<'_>,
    ) -> Result<Option<PathBuf>, Fatal> {
        let (Some(model_format), Some(ext)) = (format.model(), format.extensions().first()) else {
            return Ok(None);
        };
        self.check_dir(true)?;
        let path = self.path(ext);
        if !is_inside(&self.dir, &path) {
            return Err(Fatal::new(
                EX_CANTCREAT,
                "Refusing to write outside the user-file directory.",
            ));
        }
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(Fatal::new(
                    EX_CANTCREAT,
                    format!(
                        "Refusing to replace {}: it is a symlink or not a regular file.",
                        path.display()
                    ),
                ));
            }
        }
        dbg_log!("Updating: {} ({})", path.display(), model_format.name());
        mpw_model::export_to(&path, user, model_format, mode).map_err(|e| {
            Fatal::new(
                EX_CANTCREAT,
                format!(
                    "Couldn't write updated configuration file:\n  {}: {e}",
                    path.display()
                ),
            )
        })?;
        Ok(Some(path))
    }
}

/// The file-name stem for a full name (see the module docs).
pub fn file_stem(full_name: &str) -> Result<String, Fatal> {
    let refuse = |why: &str| {
        Fatal::new(
            EX_DATAERR,
            format!("This full name cannot be used for a user file ({why}); use -F none to work without one."),
        )
    };
    if full_name.trim().is_empty() {
        return Err(refuse("it is blank"));
    }
    if full_name.chars().any(char::is_control) {
        return Err(refuse("it contains control characters"));
    }
    // The reference replaces every '/' with '_'.
    let mut stem = full_name.replace('/', "_");
    // Never create a hidden file (or "." / ".." look-alikes).
    if stem.starts_with('.') {
        stem.replace_range(..1, "_");
    }
    let longest_ext = Format::Json
        .extensions()
        .iter()
        .chain(Format::Flat.extensions())
        .map(|e| e.len() + 1)
        .max()
        .unwrap_or(0);
    if stem.len() + longest_ext > MAX_FILE_NAME {
        return Err(refuse("it is too long for a file name"));
    }
    Ok(stem)
}

/// Whether `path` is inside `dir` (defence in depth for the stem rules).
pub fn is_inside(dir: &Path, path: &Path) -> bool {
    path.parent() == Some(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_names() {
        assert_eq!(Format::named("n"), Some(Format::None));
        assert_eq!(Format::named("FLAT"), Some(Format::Flat));
        assert_eq!(Format::named("j"), Some(Format::Json));
        assert_eq!(Format::named("xml"), None);
    }

    #[test]
    fn fallback_and_fixed() {
        let o = |f: &str, fixed| Options::parse(Some(f), fixed, None).unwrap();
        assert_eq!(
            o("flat", false).read_formats(),
            [Format::Flat, Format::Json]
        );
        assert_eq!(o("flat", false).save_format(), Format::Json);
        assert_eq!(o("flat", true).read_formats(), [Format::Flat]);
        assert_eq!(o("flat", true).save_format(), Format::Flat);
        assert_eq!(
            o("none", false).read_formats(),
            [Format::None, Format::Json, Format::Flat]
        );
        assert!(o("none", true).stateless());
        assert!(!o("none", false).stateless());
    }

    #[test]
    fn redaction_flag() {
        let r = |v: &str| Options::parse(None, false, Some(v)).unwrap().redacted;
        assert_eq!(r("0"), Some(false));
        assert_eq!(r("no"), Some(false));
        assert_eq!(r("1"), Some(true));
        assert_eq!(r("yes"), Some(true));
        assert_eq!(r("true"), Some(true));
        assert_eq!(Options::parse(None, false, None).unwrap().redacted, None);
    }

    #[test]
    fn hostile_names_stay_inside_and_visible() {
        let dir = PathBuf::from("/home/u/.mpw.d");
        for name in [
            "../../etc/passwd",
            "..",
            ".",
            ".hidden",
            "/abs/path",
            "a/b",
            "Robert Lee Mitchell",
            "⛄",
            "..\\..",
        ] {
            let loc = Location::new(dir.clone(), name).unwrap();
            for ext in ["mpjson", "mpsites"] {
                let path = loc.path(ext);
                assert!(is_inside(&dir, &path), "{name:?} -> {path:?}");
                let file = path.file_name().unwrap().to_str().unwrap();
                assert!(!file.starts_with('.'), "{name:?} -> {file}");
                assert!(!file.contains('/'));
            }
        }
        assert_eq!(
            file_stem("Robert Lee Mitchell").unwrap(),
            "Robert Lee Mitchell"
        );
        assert_eq!(file_stem("a/b").unwrap(), "a_b");
        assert_eq!(file_stem("..").unwrap(), "_.");
        for bad in [
            "",
            "   ",
            "tab\there",
            "nul\0",
            "line\nbreak",
            &"x".repeat(250),
        ] {
            assert!(file_stem(bad).is_err(), "{bad:?}");
        }
    }
}
