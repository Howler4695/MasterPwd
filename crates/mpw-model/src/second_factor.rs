//! An opt-in, cryptographically enforced second factor (e.g. a smart card).
//!
//! Master Password is stateless and public: anything that only *checks* a
//! card could be skipped by using another implementation.  So the second
//! factor is part of the secret instead:
//!
//! * Enabling it generates a random 160-bit **second secret**, shown once as a
//!   printable **recovery code** (see [`SecondSecret::recovery_code`]).
//! * The user's **effective master password** becomes
//!   `typed password + " " + recovery code` (exactly one ASCII space, the code in
//!   its canonical printed form).  Key ID, keys and every result derive from it,
//!   so the user can always recover in *any* Master Password app by typing the
//!   password, a space and the code from paper.
//! * Day to day the secret is stored in the user file **wrapped** (public-key
//!   encrypted by the app, e.g. to the encryption certificate of a CAC/PIV
//!   card) in one or more [`Slot`]s.  Unlocking = typed password + the secret
//!   unwrapped by the card, or the typed recovery code.
//!
//! This crate never performs the public-key operations: the app wraps
//! [`SecondSecret::as_bytes`] and gives us the wrapped bytes, and unwraps
//! [`Slot::wrapped`] and gives us the secret back ([`SecondSecret::from_bytes`]).
//!
//! The slots live in the user file under `user._ext_mpw.second_factor`:
//!
//! ```text
//! "second_factor": {
//!   "version": 1,
//!   "check": "<16 hex: SHA-256('mpw-model second factor check v1' || secret)[..8]>",
//!   "slots": [ { "id": "<16 hex>", "kind": "smart_card", "label": "CAC",
//!                "fingerprint": "<64 hex: SHA-256 of the certificate / public key>",
//!                "algorithm": "<opaque, chosen by the app>",
//!                "wrapped": "<base64>", "added": "2026-11-12T10:00:00Z" } ]
//! }
//! ```
//! No certificate or subject name is stored: user files are exported and
//! shared, and a CAC subject holds the holder's name and DoD ID number.
//!
//! **Every operation that enables, disables or rotates the second factor, or
//! changes the master password, changes every generated password of the
//! user** (stored personal values are re-encrypted and kept).

use crate::error::{Error, Result};
use crate::keys::UserKeys;
use crate::model::{JsonMap, User};
use crate::time::Timestamp;
use base64::Engine as _;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Size of the second secret in bytes (160 bits).
pub const SECOND_SECRET_LEN: usize = 20;
/// Most slots per user.
pub const MAX_SLOTS: usize = 32;
/// Largest wrapped secret, in bytes (RSA-4096 needs 512).
pub const MAX_WRAPPED_LEN: usize = 16 * 1024;
const MAX_LABEL_LEN: usize = 256;
const MAX_ALGORITHM_LEN: usize = 128;
const MAX_ID_LEN: usize = 64;
const FORMAT_VERSION: u64 = 1;
const MEMBER: &str = "second_factor";

/// Crockford base32: no I, L, O, U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DATA_CHARS: usize = 32; // 160 bits / 5
const CHECK_CHARS: usize = 3; // 15-bit checksum
const CODE_CHARS: usize = DATA_CHARS + CHECK_CHARS;
const GROUP: usize = 5;

// ------------------------------------------------------------------ secret

/// The 160-bit second secret.  Wiped on drop; `Debug` is redacted; no `Clone`.
#[derive(PartialEq, Eq)]
pub struct SecondSecret {
    bytes: Zeroizing<[u8; SECOND_SECRET_LEN]>,
}

/// Why a typed recovery code was rejected.  Never contains the code.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RecoveryCodeError {
    #[error("the recovery code has {found} characters; it should have {CODE_CHARS} (not counting dashes)")]
    WrongLength { found: usize },
    #[error("character {position} of the recovery code is not valid")]
    InvalidCharacter { position: usize },
    #[error("the recovery code is mistyped (its checksum does not match)")]
    ChecksumMismatch,
}

impl SecondSecret {
    /// A fresh secret from the operating system's CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; SECOND_SECRET_LEN]);
        getrandom::fill(&mut bytes[..]).map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(Self { bytes })
    }

    /// The secret as unwrapped by an authenticator.  Fails unless exactly
    /// [`SECOND_SECRET_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let array: [u8; SECOND_SECRET_LEN] =
            bytes.try_into().map_err(|_| Error::InvalidSlot("the unwrapped secret has the wrong length"))?;
        Ok(Self { bytes: Zeroizing::new(array) })
    }

    /// The raw secret, to wrap to an authenticator.  Handle with care.
    pub fn as_bytes(&self) -> &[u8; SECOND_SECRET_LEN] {
        &self.bytes
    }

    /// The canonical printed recovery code: 35 upper-case Crockford base32
    /// characters (32 for the secret, 3 for a checksum) in 7 dash-separated
    /// groups of 5, e.g. `0000G-40R40-M30E2-09GS6-...`.
    pub fn recovery_code(&self) -> Zeroizing<String> {
        let mut chars = Zeroizing::new(Vec::with_capacity(CODE_CHARS));
        encode_base32(&self.bytes[..], &mut chars);
        let check = checksum(&self.bytes[..]);
        for shift in [10u32, 5, 0] {
            chars.push(ALPHABET[usize::from((check >> shift) as u8 & 31)]);
        }
        let mut out = Zeroizing::new(String::with_capacity(CODE_CHARS + CODE_CHARS / GROUP));
        for (i, c) in chars.iter().enumerate() {
            if i > 0 && i % GROUP == 0 {
                out.push('-');
            }
            out.push(char::from(*c));
        }
        out
    }

    /// Parse a typed recovery code.  Accepts lower case, any dashes and
    /// whitespace, and the look-alikes `O`→`0` and `I`/`L`→`1`.  A mistyped
    /// code is rejected by its checksum, before any key derivation.
    pub fn parse_recovery_code(text: &str) -> Result<Self, RecoveryCodeError> {
        let mut digits = Zeroizing::new(Vec::with_capacity(CODE_CHARS));
        let mut position = 0;
        for ch in text.chars() {
            if ch == '-' || ch.is_whitespace() {
                continue;
            }
            position += 1;
            let c = match ch.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            };
            let value = ALPHABET
                .iter()
                .position(|a| char::from(*a) == c)
                .ok_or(RecoveryCodeError::InvalidCharacter { position })?;
            digits.push(value as u8);
        }
        if digits.len() != CODE_CHARS {
            return Err(RecoveryCodeError::WrongLength { found: digits.len() });
        }
        let mut bytes = Zeroizing::new([0u8; SECOND_SECRET_LEN]);
        let mut acc: u64 = 0;
        let mut bits = 0;
        let mut out = 0;
        for d in &digits[..DATA_CHARS] {
            acc = (acc << 5) | u64::from(*d);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                bytes[out] = (acc >> bits) as u8;
                out += 1;
            }
        }
        acc.zeroize();
        let check = digits[DATA_CHARS..]
            .iter()
            .fold(0u16, |c, d| (c << 5) | u16::from(*d));
        if check != checksum(&bytes[..]) {
            return Err(RecoveryCodeError::ChecksumMismatch);
        }
        Ok(Self { bytes })
    }

    fn check_value(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"mpw-model second factor check v1");
        h.update(&self.bytes[..]);
        h.finalize()[..8].iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Debug for SecondSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecondSecret(<redacted>)")
    }
}

fn encode_base32(bytes: &[u8], out: &mut Vec<u8>) {
    let mut acc: u64 = 0;
    let mut bits = 0;
    for b in bytes {
        acc = (acc << 8) | u64::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize]);
        }
    }
    acc.zeroize();
}

/// 15 bits of SHA-256 over a domain tag and the secret.
fn checksum(secret: &[u8]) -> u16 {
    let mut h = Sha256::new();
    h.update(b"mpw-model recovery code v1");
    h.update(secret);
    let d = h.finalize();
    (u16::from(d[0]) << 7 | u16::from(d[1]) >> 1) & 0x7fff
}

/// The effective master password: `typed_password + " " + recovery code`
/// (canonical form).  Never change this rule: recovery with other Master
/// Password apps depends on it.  Prefer [`UserKeys::from_password_and_secret`].
pub fn effective_master_password(typed_password: &str, secret: &SecondSecret) -> Zeroizing<String> {
    let code = secret.recovery_code();
    let mut out = Zeroizing::new(String::with_capacity(typed_password.len() + 1 + code.len()));
    out.push_str(typed_password);
    out.push(' ');
    out.push_str(&code);
    out
}

// ------------------------------------------------------------------- slots

/// What kind of authenticator holds a slot.  Unknown kinds are kept as-is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SlotKind {
    /// A PKI smart card such as a DoD CAC / PIV card (`"smart_card"`).
    SmartCard,
    /// A kind this version does not know (e.g. a future FIDO2 key).
    Other(String),
}

impl SlotKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::SmartCard => "smart_card",
            Self::Other(s) => s,
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "smart_card" => Self::SmartCard,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// One enrolled authenticator holding the wrapped second secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    id: String,
    kind: SlotKind,
    label: String,
    fingerprint: String,
    algorithm: String,
    wrapped: Vec<u8>,
    added: Timestamp,
    extra: JsonMap,
}

fn valid_text(s: &str, max: usize) -> bool {
    s.len() <= max && !s.chars().any(char::is_control)
}

impl Slot {
    /// A new slot with a random id, added now.
    ///
    /// * `fingerprint`: SHA-256 of the authenticator's certificate or public
    ///   key, 64 hex digits (stored upper-case).
    /// * `algorithm`: the app's identifier of the wrapping scheme (e.g.
    ///   `"rsa-oaep-sha256"`); opaque to this crate.
    /// * `wrapped`: [`SecondSecret::as_bytes`] encrypted to the authenticator.
    ///
    /// This crate cannot check that `wrapped` really holds the secret: unwrap
    /// it once with the card and compare before saving.
    pub fn new(kind: SlotKind, label: &str, fingerprint: &str, algorithm: &str, wrapped: Vec<u8>) -> Result<Self> {
        let mut id = [0u8; 8];
        getrandom::fill(&mut id).map_err(|e| std::io::Error::other(e.to_string()))?;
        let slot = Self {
            id: id.iter().map(|b| format!("{b:02x}")).collect(),
            kind,
            label: label.to_owned(),
            fingerprint: fingerprint.trim().to_ascii_uppercase(),
            algorithm: algorithm.to_owned(),
            wrapped,
            added: Timestamp::now(),
            extra: JsonMap::new(),
        };
        slot.validate()?;
        Ok(slot)
    }

    fn validate(&self) -> Result<()> {
        let bad = |why| Err(Error::InvalidSlot(why));
        if self.id.is_empty()
            || self.id.len() > MAX_ID_LEN
            || !self.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return bad("invalid id");
        }
        if self.kind.as_str().is_empty() || !valid_text(self.kind.as_str(), MAX_ALGORITHM_LEN) {
            return bad("invalid kind");
        }
        if !valid_text(&self.label, MAX_LABEL_LEN) {
            return bad("invalid label");
        }
        if self.fingerprint.len() != 64 || !self.fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
            return bad("the fingerprint must be 64 hex digits (SHA-256)");
        }
        if self.algorithm.is_empty() || !valid_text(&self.algorithm, MAX_ALGORITHM_LEN) {
            return bad("invalid algorithm identifier");
        }
        if self.wrapped.is_empty() || self.wrapped.len() > MAX_WRAPPED_LEN {
            return bad("the wrapped secret is empty or too large");
        }
        Ok(())
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn kind(&self) -> &SlotKind {
        &self.kind
    }
    pub fn label(&self) -> &str {
        &self.label
    }
    /// SHA-256 of the authenticator's certificate / public key, upper-case hex.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    /// The app's wrapping-scheme identifier.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }
    /// The wrapped secret, for the authenticator to unwrap.
    pub fn wrapped(&self) -> &[u8] {
        &self.wrapped
    }
    pub fn added(&self) -> Timestamp {
        self.added
    }
}

/// The second factor of a user: its slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondFactor {
    check: String,
    slots: Vec<Slot>,
    extra: JsonMap,
}

impl SecondFactor {
    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    pub fn slot(&self, id: &str) -> Option<&Slot> {
        self.slots.iter().find(|s| s.id == id)
    }

    /// Whether `secret` is this user's second secret (a cheap check, no key
    /// derivation): use it to tell "the card returned the wrong secret" or a
    /// stale recovery code apart from a wrong password.
    pub fn matches(&self, secret: &SecondSecret) -> bool {
        self.check.eq_ignore_ascii_case(&secret.check_value())
    }
}

/// Whether a user has a second factor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SecondFactorStatus {
    /// No second factor: the typed master password is the master password.
    #[default]
    Disabled,
    /// A second factor is enabled.  Unlock with the typed password and the
    /// secret from a slot or the recovery code.
    Enabled(SecondFactor),
    /// The file has a second-factor member this version cannot read (a newer
    /// version, or damaged).  The user can still be unlocked with the typed
    /// password and the recovery code; the member is kept untouched.
    Unreadable,
}

impl SecondFactorStatus {
    /// The user needs a second secret (or the recovery code) to unlock.
    pub fn is_enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub fn second_factor(&self) -> Option<&SecondFactor> {
        match self {
            Self::Enabled(sf) => Some(sf),
            _ => None,
        }
    }
}

/// An explicit statement that the user has saved the recovery code; required
/// when a second factor would otherwise have no slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryCode {
    /// The user confirmed the recovery code is written down / stored safely.
    ConfirmedSaved,
    /// Not confirmed: operations leaving zero slots are refused.
    NotConfirmed,
}

// ------------------------------------------------------------ JSON member

/// Read `second_factor` out of the user's `_ext_mpw`.  A readable member is
/// removed (it is written back from the status); an unreadable one is left.
pub(crate) fn read_member(ext: &mut Option<Value>) -> SecondFactorStatus {
    let Some(Value::Object(m)) = ext else {
        return SecondFactorStatus::Disabled;
    };
    let Some(member) = m.get(MEMBER) else {
        return SecondFactorStatus::Disabled;
    };
    match parse_member(member) {
        Some(sf) => {
            m.remove(MEMBER);
            SecondFactorStatus::Enabled(sf)
        }
        None => SecondFactorStatus::Unreadable,
    }
}

fn parse_member(v: &Value) -> Option<SecondFactor> {
    let mut m = v.as_object()?.clone();
    if m.remove("version")?.as_u64()? != FORMAT_VERSION {
        return None;
    }
    let check = m.remove("check")?.as_str()?.to_owned();
    if check.len() != 16 || !check.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let slots_v = m.remove("slots")?;
    let list = slots_v.as_array()?;
    if list.len() > MAX_SLOTS {
        return None;
    }
    let mut slots = Vec::with_capacity(list.len());
    for s in list {
        let mut s = s.as_object()?.clone();
        let mut text = |k: &str| -> Option<String> { s.remove(k)?.as_str().map(str::to_owned) };
        let id = text("id")?;
        let kind = SlotKind::parse(&text("kind")?);
        let label = text("label").unwrap_or_default();
        let fingerprint = text("fingerprint")?.to_ascii_uppercase();
        let algorithm = text("algorithm")?;
        let wrapped_b64 = text("wrapped")?;
        let added = text("added").and_then(|t| Timestamp::parse_rfc3339(&t)).unwrap_or_default();
        if wrapped_b64.len() > MAX_WRAPPED_LEN * 2 {
            return None;
        }
        let wrapped = base64::engine::general_purpose::STANDARD.decode(wrapped_b64.trim()).ok()?;
        let slot = Slot { id, kind, label, fingerprint, algorithm, wrapped, added, extra: s };
        slot.validate().ok()?;
        if slots.iter().any(|o: &Slot| o.id == slot.id) {
            return None;
        }
        slots.push(slot);
    }
    Some(SecondFactor { check, slots, extra: m })
}

/// Insert the member into the user's `_ext_mpw` object being written.
pub(crate) fn write_member(status: &SecondFactorStatus, ext: &mut JsonMap) {
    let SecondFactorStatus::Enabled(sf) = status else { return };
    let mut m = Map::new();
    m.insert("version".into(), Value::from(FORMAT_VERSION));
    m.insert("check".into(), Value::String(sf.check.clone()));
    let slots = sf
        .slots
        .iter()
        .map(|s| {
            let mut o = Map::new();
            o.insert("id".into(), Value::String(s.id.clone()));
            o.insert("kind".into(), Value::String(s.kind.as_str().to_owned()));
            o.insert("label".into(), Value::String(s.label.clone()));
            o.insert("fingerprint".into(), Value::String(s.fingerprint.clone()));
            o.insert("algorithm".into(), Value::String(s.algorithm.clone()));
            o.insert(
                "wrapped".into(),
                Value::String(base64::engine::general_purpose::STANDARD.encode(&s.wrapped)),
            );
            o.insert("added".into(), Value::String(s.added.to_rfc3339()));
            for (k, v) in &s.extra {
                o.entry(k.clone()).or_insert_with(|| v.clone());
            }
            Value::Object(o)
        })
        .collect();
    m.insert("slots".into(), Value::Array(slots));
    for (k, v) in &sf.extra {
        m.entry(k.clone()).or_insert_with(|| v.clone());
    }
    ext.insert(MEMBER.into(), Value::Object(m));
}

// --------------------------------------------------------- user operations

fn check_slots(slots: &[Slot], recovery: RecoveryCode) -> Result<()> {
    if slots.is_empty() && recovery != RecoveryCode::ConfirmedSaved {
        return Err(Error::RecoveryCodeNotConfirmed);
    }
    if slots.len() > MAX_SLOTS {
        return Err(Error::InvalidSlot("too many slots"));
    }
    for (i, s) in slots.iter().enumerate() {
        s.validate()?;
        if slots[..i].iter().any(|o| o.id == s.id) {
            return Err(Error::SlotExists);
        }
    }
    Ok(())
}

impl User {
    /// Whether the user has a second factor, and its slots.
    pub fn second_factor_status(&self) -> &SecondFactorStatus {
        &self.second_factor
    }

    /// The key holder to unlock a second-factor user with: the typed password
    /// plus the secret from a slot or a parsed recovery code.  Fails with
    /// [`Error::SecondSecretMismatch`] (cheaply, before any key derivation) if
    /// the secret is not this user's.  Then [`User::authenticate`] as usual.
    pub fn second_factor_keys(&self, typed_password: &str, secret: &SecondSecret) -> Result<UserKeys> {
        match &self.second_factor {
            SecondFactorStatus::Disabled => return Err(Error::SecondFactorNotEnabled),
            SecondFactorStatus::Enabled(sf) if !sf.matches(secret) => return Err(Error::SecondSecretMismatch),
            _ => {}
        }
        Ok(UserKeys::from_password_and_secret(&self.full_name, typed_password, secret))
    }

    /// Check a freshly built key holder against the user without changing it.
    fn verify_keys(&self, keys: &mut UserKeys) -> Result<()> {
        let id = keys.key(self.algorithm)?.key_id();
        match &self.key_id {
            Some(stored) if *stored == id => {
                keys.mark_authenticated(id);
                Ok(())
            }
            Some(_) => Err(Error::WrongMasterPassword),
            None => Err(Error::NotAuthenticated),
        }
    }

    /// Enable a second factor.
    ///
    /// **This changes every generated password of the user** (the master
    /// password becomes `typed_password + " " + recovery code`); stored values
    /// are re-encrypted and kept.  `typed_password` must be the current master
    /// password (it is verified).  `slots` hold `secret` wrapped to the
    /// enrolled authenticators; with no slot the call is refused unless
    /// `recovery` is [`RecoveryCode::ConfirmedSaved`].  All or nothing.  Returns
    /// the new, authenticated key holder.
    pub fn enable_second_factor(
        &mut self,
        typed_password: &str,
        secret: &SecondSecret,
        slots: Vec<Slot>,
        recovery: RecoveryCode,
    ) -> Result<UserKeys> {
        if self.second_factor.is_enabled() {
            return Err(Error::SecondFactorEnabled);
        }
        check_slots(&slots, recovery)?;
        let mut old = UserKeys::from_password(&self.full_name, typed_password);
        self.verify_keys(&mut old)?;
        let mut new = UserKeys::from_password_and_secret(&self.full_name, typed_password, secret);
        let mut updated = self.clone();
        updated.rekey(&mut old, &mut new)?;
        updated.second_factor =
            SecondFactorStatus::Enabled(SecondFactor { check: secret.check_value(), slots, extra: JsonMap::new() });
        *self = updated;
        Ok(new)
    }

    /// Disable the second factor.  **Changes every generated password** (back
    /// to those of `typed_password` alone).  Needs the typed password and the
    /// current secret (both verified).  All or nothing.
    pub fn disable_second_factor(&mut self, typed_password: &str, secret: &SecondSecret) -> Result<UserKeys> {
        let mut old = self.verified_second_factor_keys(typed_password, secret)?;
        let mut new = UserKeys::from_password(&self.full_name, typed_password);
        let mut updated = self.clone();
        updated.rekey(&mut old, &mut new)?;
        updated.second_factor = SecondFactorStatus::Disabled;
        if let Some(Value::Object(m)) = &mut updated.extras.user_ext_mpw {
            m.remove(MEMBER); // an unreadable member
        }
        *self = updated;
        Ok(new)
    }

    /// Change the typed master password, keeping the second secret and slots.
    /// **Changes every generated password.**  All or nothing.
    pub fn change_master_password_with_second_factor(
        &mut self,
        old_typed_password: &str,
        new_typed_password: &str,
        secret: &SecondSecret,
    ) -> Result<UserKeys> {
        let mut old = self.verified_second_factor_keys(old_typed_password, secret)?;
        let mut new = UserKeys::from_password_and_secret(&self.full_name, new_typed_password, secret);
        let mut updated = self.clone();
        updated.rekey(&mut old, &mut new)?;
        *self = updated;
        Ok(new)
    }

    /// Replace the second secret (a new recovery code).  All old slots are
    /// dropped and replaced by `new_slots`, which must wrap `new_secret`.
    /// **Changes every generated password.**  All or nothing.
    pub fn rotate_second_secret(
        &mut self,
        typed_password: &str,
        old_secret: &SecondSecret,
        new_secret: &SecondSecret,
        new_slots: Vec<Slot>,
        recovery: RecoveryCode,
    ) -> Result<UserKeys> {
        check_slots(&new_slots, recovery)?;
        let mut old = self.verified_second_factor_keys(typed_password, old_secret)?;
        let mut new = UserKeys::from_password_and_secret(&self.full_name, typed_password, new_secret);
        let mut updated = self.clone();
        updated.rekey(&mut old, &mut new)?;
        updated.second_factor = SecondFactorStatus::Enabled(SecondFactor {
            check: new_secret.check_value(),
            slots: new_slots,
            extra: JsonMap::new(),
        });
        if let Some(Value::Object(m)) = &mut updated.extras.user_ext_mpw {
            m.remove(MEMBER);
        }
        *self = updated;
        Ok(new)
    }

    fn verified_second_factor_keys(&self, typed_password: &str, secret: &SecondSecret) -> Result<UserKeys> {
        if !self.second_factor.is_enabled() {
            return Err(Error::SecondFactorNotEnabled);
        }
        let mut keys = self.second_factor_keys(typed_password, secret)?;
        self.verify_keys(&mut keys)?;
        Ok(keys)
    }

    fn second_factor_mut(&mut self, keys: &UserKeys) -> Result<&mut SecondFactor> {
        self.check_unlocked(keys)?;
        match &mut self.second_factor {
            SecondFactorStatus::Enabled(sf) => Ok(sf),
            SecondFactorStatus::Disabled => Err(Error::SecondFactorNotEnabled),
            SecondFactorStatus::Unreadable => Err(Error::SecondFactorUnreadable),
        }
    }

    /// Enroll another authenticator (its slot must wrap the current secret).
    /// Does not change any password.
    pub fn add_second_factor_slot(&mut self, keys: &UserKeys, slot: Slot) -> Result<()> {
        slot.validate()?;
        let sf = self.second_factor_mut(keys)?;
        if sf.slots.iter().any(|s| s.id == slot.id || s.fingerprint == slot.fingerprint) {
            return Err(Error::SlotExists);
        }
        if sf.slots.len() >= MAX_SLOTS {
            return Err(Error::InvalidSlot("too many slots"));
        }
        sf.slots.push(slot);
        Ok(())
    }

    /// Remove an authenticator.  Removing the last one needs
    /// [`RecoveryCode::ConfirmedSaved`].  Does not change any password.
    pub fn remove_second_factor_slot(&mut self, keys: &UserKeys, id: &str, recovery: RecoveryCode) -> Result<Slot> {
        let sf = self.second_factor_mut(keys)?;
        let i = sf.slots.iter().position(|s| s.id == id).ok_or(Error::NoSuchSlot)?;
        if sf.slots.len() == 1 && recovery != RecoveryCode::ConfirmedSaved {
            return Err(Error::RecoveryCodeNotConfirmed);
        }
        Ok(sf.slots.remove(i))
    }

    /// Change a slot's label.
    pub fn relabel_second_factor_slot(&mut self, keys: &UserKeys, id: &str, label: &str) -> Result<()> {
        if !valid_text(label, MAX_LABEL_LEN) {
            return Err(Error::InvalidSlot("invalid label"));
        }
        let sf = self.second_factor_mut(keys)?;
        let slot = sf.slots.iter_mut().find(|s| s.id == id).ok_or(Error::NoSuchSlot)?;
        slot.label = label.to_owned();
        Ok(())
    }
}
