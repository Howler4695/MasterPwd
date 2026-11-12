//! The export file formats: flat `.mpsites` (format 0 and 1) and JSON `.mpjson`.
//!
//! Reading is split in two steps so a user list can be shown before unlock:
//! [`UserFile::parse`] (or [`peek`]) reads everything without a key, then
//! [`UserFile::load`] authenticates and builds the [`User`].

mod flat;
mod json;

use crate::error::{Error, ParseError, ParseErrorKind, Result};
use crate::keys::UserKeys;
use crate::limits;
use crate::model::{User, UserPreferences};
use crate::time::Timestamp;
use mpw_core::{AlgorithmVersion, Identicon, KeyId, ResultType};
use std::collections::BTreeMap;
use std::path::Path;
use zeroize::Zeroizing;

/// An export file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// Line-based `.mpsites`.  Lossy: no questions, URLs, login types or preferences.
    Flat,
    /// Structured `.mpjson`.  Lossless.
    Json,
}

impl Format {
    /// The extension written for this format (`mpsites` / `mpjson`).
    pub fn extension(self) -> &'static str {
        match self {
            Self::Flat => "mpsites",
            Self::Json => "mpjson",
        }
    }

    /// Guess the format from a file name, accepting the reference's alternative
    /// extensions (`.mpsites.txt`, `.txt`, `.mpsites.json`, `.json`).
    pub fn from_path(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_str()?.to_ascii_lowercase();
        if name.ends_with(".mpsites") || name.ends_with(".txt") {
            Some(Self::Flat)
        } else if name.ends_with(".mpjson") || name.ends_with(".json") {
            Some(Self::Json)
        } else {
            None
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Flat => "flat",
            Self::Json => "json",
        }
    }
}

/// What a file says about its user, readable without the master password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSummary {
    pub format: Format,
    /// The format version stated in the file (flat: 0 or 1; JSON: 1).
    pub format_version: u64,
    pub export_date: Option<Timestamp>,
    /// `false` if the file holds passwords in clear text.
    pub redacted: bool,
    pub full_name: String,
    pub avatar: u32,
    pub identicon: Option<Identicon>,
    pub key_id: Option<KeyId>,
    pub algorithm: AlgorithmVersion,
    pub last_used: Timestamp,
    pub preferences: UserPreferences,
    pub site_count: usize,
    /// Whether the user needs a second factor to unlock, and its slots.
    pub second_factor: crate::second_factor::SecondFactorStatus,
}

/// How to write the user's secrets.
pub enum ExportMode<'k> {
    /// Stored passwords encrypted with the master key (only exportable types;
    /// device-private values are left out).  Safe to share.
    Redacted,
    /// Passwords, logins and answers in clear text.  Needs the authenticated
    /// key holder.  Device-private values are still left out.
    Revealed(&'k mut UserKeys),
    /// For **this device's own store only** (what [`crate::UserStore`] writes):
    /// like `Redacted`, plus the encrypted values of device-private
    /// ([`ResultType::StatefulDevice`]) passwords, logins and answers.  Never use
    /// it for a file meant to leave the device (exports, backups, sync): the
    /// whole point of a device-private value is that it is not exported.
    /// Values are still encrypted; no key is needed.
    Storage,
}

/// Internal: what goes into the secret fields.
pub(crate) enum Content<'k> {
    Export,
    /// Like `Export`, plus device-private state: for this device's own store.
    Storage,
    Revealed(&'k mut UserKeys),
}

/// A clear-text value from a revealed file, to be encrypted once the key is known.
pub(crate) enum Slot {
    SitePassword(String),
    SiteLogin(String),
    /// A flat-format login column: personal if it differs from the generated one.
    FlatLogin(String),
    Answer(String, String),
    UserLogin,
}

pub(crate) struct Pending {
    pub slot: Slot,
    pub value: Zeroizing<String>,
}

/// A parsed export file, not yet authenticated.
pub struct UserFile {
    summary: UserSummary,
    user: User,
    pending: Vec<Pending>,
}

impl std::fmt::Debug for UserFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserFile")
            .field("summary", &self.summary)
            .field("clear_text_values", &self.pending.len())
            .finish_non_exhaustive()
    }
}

/// Parse just enough of a file to describe its user.  Never needs a key.
pub fn peek(bytes: &[u8]) -> Result<UserSummary> {
    Ok(UserFile::parse(bytes)?.summary)
}

impl UserFile {
    /// Parse a flat or JSON export.  The input is untrusted: size, counts and
    /// lengths are bounded, and errors say where (never what).
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > limits::MAX_FILE_SIZE {
            return Err(perr(ParseErrorKind::TooLarge { max: limits::MAX_FILE_SIZE }, None, "").into());
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|e| perr(ParseErrorKind::InvalidUtf8 { offset: e.valid_up_to() }, None, ""))?;
        let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
        let (summary, user, pending) = match text.trim_start().as_bytes().first() {
            Some(b'#') => flat::read(text)?,
            Some(b'{') => json::read(text)?,
            _ => return Err(perr(ParseErrorKind::UnknownFormat, None, "").into()),
        };
        Ok(Self { summary, user, pending })
    }

    pub fn summary(&self) -> &UserSummary {
        &self.summary
    }

    /// Authenticate `keys` against the file's user (adopting the key ID if the
    /// file has none) and build the user.  Clear-text values of a revealed file
    /// are encrypted with the master key.  The file is left untouched, so a
    /// wrong password can simply be retried.
    pub fn load(&self, keys: &mut UserKeys) -> Result<User> {
        let mut user = self.user.clone();
        user.authenticate(keys)?;
        for p in &self.pending {
            apply_pending(&mut user, keys, p)?;
        }
        Ok(user)
    }

    /// Build the user without authenticating.  Only possible when the file holds
    /// no clear-text secrets that would need encrypting.
    pub fn load_locked(&self) -> Result<User> {
        if !self.pending.is_empty() {
            return Err(Error::RevealedNeedsKey);
        }
        Ok(self.user.clone())
    }
}

fn apply_pending(user: &mut User, keys: &mut UserKeys, p: &Pending) -> Result<()> {
    match &p.slot {
        Slot::UserLogin => {
            if user.login_type.is_stateful() {
                let ctx = user.login_ctx();
                user.login_state = Some(ctx.encrypt(keys, &p.value)?);
            }
        }
        Slot::SitePassword(name) => {
            if let Some(site) = user.sites.get_mut(name) {
                if site.result_type.is_stateful() {
                    site.result_state = Some(site.password_ctx().encrypt(keys, &p.value)?);
                }
            }
        }
        Slot::SiteLogin(name) => {
            if let Some(site) = user.sites.get_mut(name) {
                if let Some(t) = site.login_type.filter(|t| t.is_stateful()) {
                    site.login_state = Some(site.login_ctx(t).encrypt(keys, &p.value)?);
                }
            }
        }
        Slot::FlatLogin(name) => {
            let template = if user.login_type.is_template() { user.login_type } else { ResultType::DEFAULT_LOGIN };
            if let Some(site) = user.sites.get_mut(name) {
                let generated = site.login_ctx(template).generate(keys)?;
                if *generated != **p.value {
                    let t = ResultType::StatefulPersonal;
                    site.login_state = Some(site.login_ctx(t).encrypt(keys, &p.value)?);
                    site.login_type = Some(t);
                }
            }
        }
        Slot::Answer(name, keyword) => {
            if let Some(site) = user.sites.get_mut(name) {
                let t = match site.questions.get(keyword) {
                    Some(q) if q.result_type.is_stateful() => q.result_type,
                    _ => return Ok(()),
                };
                let state = site.answer_ctx(keyword, t).encrypt(keys, &p.value)?;
                if let Some(q) = site.questions.get_mut(keyword) {
                    q.state = Some(state);
                }
            }
        }
    }
    Ok(())
}

/// Serialise a user for export.  Redacted exports need no key; revealed ones
/// need the key holder that unlocked the user.
pub fn write(user: &User, format: Format, mode: ExportMode<'_>) -> Result<Zeroizing<String>> {
    let content = match mode {
        ExportMode::Redacted => Content::Export,
        ExportMode::Revealed(keys) => Content::Revealed(keys),
        ExportMode::Storage => Content::Storage,
    };
    write_with(user, format, content, Timestamp::now())
}

pub(crate) fn write_with(user: &User, format: Format, content: Content<'_>, now: Timestamp) -> Result<Zeroizing<String>> {
    let redacted = !matches!(content, Content::Revealed(_));
    let out = outputs(user, content)?;
    match format {
        Format::Flat => flat::write(user, &out, redacted, now),
        Format::Json => json::write(user, &out, redacted, now),
    }
}

/// The values to write into the secret fields, per site.
pub(crate) struct Outputs {
    pub user_login: Option<Zeroizing<String>>,
    pub sites: BTreeMap<String, SiteOut>,
}

#[derive(Default)]
pub(crate) struct SiteOut {
    pub password: Option<Zeroizing<String>>,
    pub login: Option<Zeroizing<String>>,
    pub answers: BTreeMap<String, Option<Zeroizing<String>>>,
}

fn outputs(user: &User, content: Content<'_>) -> Result<Outputs> {
    // Which stored (encrypted) state may be written as-is.
    let keep = |t: ResultType, storage: bool| {
        if storage {
            t.is_stateful()
        } else {
            t.exports_content()
        }
    };
    let state = |s: &Option<String>| s.clone().filter(|s| !s.is_empty()).map(Zeroizing::new);

    let mut out = Outputs { user_login: None, sites: BTreeMap::new() };
    match content {
        Content::Export | Content::Storage => {
            let storage = matches!(content, Content::Storage);
            if keep(user.login_type, storage) {
                out.user_login = state(&user.login_state);
            }
            for (name, site) in &user.sites {
                let mut so = SiteOut::default();
                if keep(site.result_type, storage) {
                    so.password = state(&site.result_state);
                }
                if site.login_type.is_some_and(|t| keep(t, storage)) {
                    so.login = state(&site.login_state);
                }
                for (kw, q) in &site.questions {
                    let answer = if keep(q.result_type, storage) { state(&q.state) } else { None };
                    so.answers.insert(kw.clone(), answer);
                }
                out.sites.insert(name.clone(), so);
            }
        }
        Content::Revealed(keys) => {
            user.check_unlocked(keys)?;
            // Never reveal device-private values; skip results that cannot be
            // produced (no stored value) instead of writing garbage.
            let reveal = |t: ResultType, r: Result<Zeroizing<String>>| -> Result<Option<Zeroizing<String>>> {
                if t.is_device_private() || t.is_derive() {
                    return Ok(None);
                }
                match r {
                    Ok(v) => Ok(Some(v)),
                    Err(Error::NoStoredValue(_)) => Ok(None),
                    Err(e) => Err(e),
                }
            };
            if user.login_type.is_stateful() {
                let t = user.login_type;
                out.user_login = reveal(t, user.user_login(keys))?;
            }
            for (name, site) in &user.sites {
                let mut so = SiteOut::default();
                let t = site.result_type;
                if !(t.is_device_private() || t.is_derive()) {
                    so.password = reveal(t, user.site_password(keys, name))?;
                }
                let login_t = site.login_type.unwrap_or(user.login_type);
                if !login_t.is_device_private() {
                    so.login = reveal(login_t, user.site_login(keys, name))?;
                }
                for (kw, q) in &site.questions {
                    let answer = if q.result_type.is_device_private() || q.result_type.is_derive() {
                        None
                    } else {
                        reveal(q.result_type, user.site_answer(keys, name, kw))?
                    };
                    so.answers.insert(kw.clone(), answer);
                }
                out.sites.insert(name.clone(), so);
            }
        }
    }
    Ok(out)
}

// -------------------------------------------------------------------- helpers

/// A generous estimate of the serialised size, to size output buffers once.
pub(crate) fn size_hint(user: &User, out: &Outputs) -> usize {
    let secrets = |v: &Option<Zeroizing<String>>| v.as_ref().map_or(0, |s| s.len() * 2);
    let mut n = 4096 + user.full_name.len() * 4 + secrets(&out.user_login);
    for (name, site) in &user.sites {
        n += 512 + name.len() * 2 + site.url.as_ref().map_or(0, String::len) * 2;
        n += serde_json::to_string(&site.extra).map_or(0, |s| s.len()) * 2;
        for (kw, q) in &site.questions {
            n += 128 + kw.len() * 2 + serde_json::to_string(&q.extra).map_or(0, |s| s.len()) * 2;
        }
        if let Some(so) = out.sites.get(name) {
            n += secrets(&so.password) + secrets(&so.login);
            n += so.answers.values().map(secrets).sum::<usize>();
        }
    }
    let e = &user.extras;
    for m in [&e.root, &e.export, &e.user] {
        n += serde_json::to_string(m).map_or(0, |s| s.len()) * 2;
    }
    n + e.user_ext_mpw.as_ref().map_or(0, |v| v.to_string().len() * 2)
}

pub(crate) fn perr(kind: ParseErrorKind, line: Option<usize>, location: impl Into<String>) -> ParseError {
    ParseError::new(kind, line, location)
}

/// Timestamps written to files are at least one second after the epoch: the
/// reference reader treats a parsed time of 0 as "invalid" and rejects the file.
pub(crate) fn file_time(t: Timestamp) -> String {
    Timestamp::from_unix(t.as_unix().max(1)).to_rfc3339()
}

pub(crate) fn check_len(s: &str, line: Option<usize>, location: &str) -> Result<(), ParseError> {
    if s.len() > limits::MAX_VALUE_LEN {
        return Err(perr(ParseErrorKind::TooLong { limit: limits::MAX_VALUE_LEN }, line, location));
    }
    Ok(())
}

pub(crate) fn parse_algorithm(v: u64, line: Option<usize>, location: &str) -> Result<AlgorithmVersion, ParseError> {
    u32::try_from(v)
        .ok()
        .and_then(AlgorithmVersion::from_u32)
        .ok_or_else(|| perr(ParseErrorKind::InvalidAlgorithm, line, location))
}

pub(crate) fn parse_type(v: u64, line: Option<usize>, location: &str) -> Result<ResultType, ParseError> {
    u32::try_from(v)
        .ok()
        .and_then(ResultType::from_u32)
        .ok_or_else(|| perr(ParseErrorKind::InvalidResultType(v), line, location))
}

pub(crate) fn parse_key_id(s: &str, line: Option<usize>, location: &str) -> Result<Option<KeyId>, ParseError> {
    if s.trim().is_empty() {
        return Ok(None);
    }
    KeyId::from_hex(s)
        .map(Some)
        .ok_or_else(|| perr(ParseErrorKind::InvalidValue, line, location))
}

pub(crate) fn parse_time(s: &str, line: Option<usize>, location: &str) -> Result<Timestamp, ParseError> {
    Timestamp::parse_rfc3339(s).ok_or_else(|| perr(ParseErrorKind::InvalidValue, line, location))
}
