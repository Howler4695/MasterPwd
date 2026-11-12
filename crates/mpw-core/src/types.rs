//! Value types shared by the algorithm, the model and the front-ends.
//!
//! The numeric values here are part of the on-disk export formats and of the
//! algorithm itself; they mirror `mpw-types.h` from the reference
//! implementation and must not change.

use std::fmt;
use subtle::ConstantTimeEq;

// ---------------------------------------------------------------- algorithm

/// Version of the Master Password algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u32)]
pub enum AlgorithmVersion {
    /// (2012-03-05) Original implementation.
    V0 = 0,
    /// (2012-07-17) Fixed a multi-byte template-index bug.
    V1 = 1,
    /// (2014-09-24) Fixed the site-name length to count bytes, not characters.
    V2 = 2,
    /// (2015-01-15) Fixed the full-name length to count bytes, not characters.
    V3 = 3,
}

impl AlgorithmVersion {
    pub const FIRST: Self = Self::V0;
    pub const LAST: Self = Self::V3;
    /// The version new users and sites should use.
    pub const CURRENT: Self = Self::V3;
    pub const ALL: [Self; 4] = [Self::V0, Self::V1, Self::V2, Self::V3];

    pub fn from_u32(value: u32) -> Option<Self> {
        Self::ALL.get(value as usize).copied()
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

impl Default for AlgorithmVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl fmt::Display for AlgorithmVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.as_u32())
    }
}

// ------------------------------------------------------------------ purpose

/// What a derived site key is going to be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyPurpose {
    /// Generate a key for authentication (the site password).
    Authentication = 0,
    /// Generate a name for identification (the login name).
    Identification = 1,
    /// Generate a recovery token (a security-question answer).
    Recovery = 2,
}

impl KeyPurpose {
    /// The scope string mixed into the key derivation for this purpose.
    pub fn scope(self) -> &'static str {
        match self {
            Self::Authentication => "com.lyndir.masterpassword",
            Self::Identification => "com.lyndir.masterpassword.login",
            Self::Recovery => "com.lyndir.masterpassword.answer",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Identification => "identification",
            Self::Recovery => "recovery",
        }
    }

    /// Parse a purpose from (a prefix of) its name, e.g. `a`, `auth`, `i`, `r`.
    pub fn from_name(name: &str) -> Option<Self> {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return None;
        }
        [Self::Authentication, Self::Identification, Self::Recovery]
            .into_iter()
            .find(|p| p.name().starts_with(&name))
    }
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// -------------------------------------------------------------- result type

const CLASS_TEMPLATE: u32 = 1 << 4;
const CLASS_STATEFUL: u32 = 1 << 5;
const CLASS_DERIVE: u32 = 1 << 6;
const FEATURE_EXPORT_CONTENT: u32 = 1 << 10;
const FEATURE_DEVICE_PRIVATE: u32 = 1 << 11;
const FEATURE_ALTERNATIVE: u32 = 1 << 12;

/// The kind of result to produce from a site key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ResultType {
    /// 16: `pg^VMAUBk5x3p%HP%i4=`
    TemplateMaximum = CLASS_TEMPLATE,
    /// 17: `BiroYena8:Kixa`
    TemplateLong = 0x1 | CLASS_TEMPLATE,
    /// 18: `BirSuj0-`
    TemplateMedium = 0x2 | CLASS_TEMPLATE,
    /// 19: `Bir8`
    TemplateShort = 0x3 | CLASS_TEMPLATE,
    /// 20: `pO98MoD0`
    TemplateBasic = 0x4 | CLASS_TEMPLATE,
    /// 21: `2798`
    TemplatePin = 0x5 | CLASS_TEMPLATE,
    /// 30: `birsujano`
    TemplateName = 0xE | CLASS_TEMPLATE,
    /// 31: `bir yennoquce fefi`
    TemplatePhrase = 0xF | CLASS_TEMPLATE,
    /// 1056: a user-chosen password, stored encrypted with the site key.
    StatefulPersonal = CLASS_STATEFUL | FEATURE_EXPORT_CONTENT,
    /// 2081: a user-chosen password that must never leave this device.
    StatefulDevice = 0x1 | CLASS_STATEFUL | FEATURE_DEVICE_PRIVATE,
    /// 4160: derive a unique binary key.
    DeriveKey = CLASS_DERIVE | FEATURE_ALTERNATIVE,
}

impl ResultType {
    /// Default type for a site password.
    pub const DEFAULT: Self = Self::TemplateLong;
    /// Default type for a generated login name.
    pub const DEFAULT_LOGIN: Self = Self::TemplateName;
    /// Default type for a security-question answer.
    pub const DEFAULT_ANSWER: Self = Self::TemplatePhrase;

    pub const ALL: [Self; 11] = [
        Self::TemplateMaximum,
        Self::TemplateLong,
        Self::TemplateMedium,
        Self::TemplateShort,
        Self::TemplateBasic,
        Self::TemplatePin,
        Self::TemplateName,
        Self::TemplatePhrase,
        Self::StatefulPersonal,
        Self::StatefulDevice,
        Self::DeriveKey,
    ];

    pub fn from_u32(value: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_u32() == value)
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }

    /// The result is generated from a template; no state is stored.
    pub fn is_template(self) -> bool {
        self.as_u32() & CLASS_TEMPLATE != 0
    }

    /// The result is a user-supplied value stored encrypted under the site key.
    pub fn is_stateful(self) -> bool {
        self.as_u32() & CLASS_STATEFUL != 0
    }

    /// The result is a derived binary key.
    pub fn is_derive(self) -> bool {
        self.as_u32() & CLASS_DERIVE != 0
    }

    /// The encrypted state may be written to an export file.
    pub fn exports_content(self) -> bool {
        self.as_u32() & FEATURE_EXPORT_CONTENT != 0
    }

    /// The state must never be exported from this device.
    pub fn is_device_private(self) -> bool {
        self.as_u32() & FEATURE_DEVICE_PRIVATE != 0
    }

    /// Not suitable as the primary authentication result.
    pub fn is_alternative(self) -> bool {
        self.as_u32() & FEATURE_ALTERNATIVE != 0
    }

    /// One-letter abbreviation as accepted by the `mpw` CLI's `-t` option.
    pub fn abbreviation(self) -> &'static str {
        match self {
            Self::TemplateMaximum => "x",
            Self::TemplateLong => "l",
            Self::TemplateMedium => "m",
            Self::TemplateShort => "s",
            Self::TemplateBasic => "b",
            Self::TemplatePin => "i",
            Self::TemplateName => "n",
            Self::TemplatePhrase => "p",
            Self::StatefulPersonal => "P",
            Self::StatefulDevice => "D",
            Self::DeriveKey => "K",
        }
    }

    pub fn short_name(self) -> &'static str {
        match self {
            Self::TemplateMaximum => "maximum",
            Self::TemplateLong => "long",
            Self::TemplateMedium => "medium",
            Self::TemplateShort => "short",
            Self::TemplateBasic => "basic",
            Self::TemplatePin => "pin",
            Self::TemplateName => "name",
            Self::TemplatePhrase => "phrase",
            Self::StatefulPersonal => "personal",
            Self::StatefulDevice => "device",
            Self::DeriveKey => "key",
        }
    }

    pub fn long_name(self) -> &'static str {
        match self {
            Self::TemplateMaximum => "Maximum Security Password",
            Self::TemplateLong => "Long Password",
            Self::TemplateMedium => "Medium Password",
            Self::TemplateShort => "Short Password",
            Self::TemplateBasic => "Basic Password",
            Self::TemplatePin => "PIN",
            Self::TemplateName => "Name",
            Self::TemplatePhrase => "Phrase",
            Self::StatefulPersonal => "Personal Password",
            Self::StatefulDevice => "Device Private Password",
            Self::DeriveKey => "Crypto Key",
        }
    }

    /// Parse a type from its one-letter abbreviation (case-sensitive) or from
    /// (a prefix of) its short name (case-insensitive), like the `mpw` CLI.
    pub fn from_name(name: &str) -> Option<Self> {
        let name = name.trim();
        if name.is_empty() {
            return None;
        }
        if let Some(t) = Self::ALL.into_iter().find(|t| t.abbreviation() == name) {
            return Some(t);
        }
        let lower = name.to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|t| t.short_name().starts_with(&lower))
    }
}

impl Default for ResultType {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for ResultType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.long_name())
    }
}

// ------------------------------------------------------------------ counter

/// A site counter.  Incrementing it yields a fresh password for the site.
pub type Counter = u32;
/// Use a time-based counter value, turning the site into a TOTP generator.
pub const COUNTER_TOTP: Counter = 0;
/// The initial value of a site's counter.
pub const COUNTER_INITIAL: Counter = 1;
pub const COUNTER_DEFAULT: Counter = COUNTER_INITIAL;

// ------------------------------------------------------------------- key id

/// Fingerprint of a master key: the upper-case hex SHA-256 of its bytes.
///
/// A key ID is stored in user files so a typed master password can be checked
/// without storing the password.  Comparison is case-insensitive and runs in
/// constant time.
#[derive(Clone)]
pub struct KeyId(String);

impl KeyId {
    /// Wrap a hex digest.  Returns `None` unless it is 64 hex digits.
    pub fn from_hex(hex: &str) -> Option<Self> {
        let hex = hex.trim();
        (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| Self(hex.to_ascii_uppercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Build the key ID from a raw SHA-256 digest.
    pub(crate) fn from_digest(digest: &[u8; 32]) -> Self {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut hex = String::with_capacity(64);
        for &b in digest {
            hex.push(char::from(HEX[usize::from(b >> 4)]));
            hex.push(char::from(HEX[usize::from(b & 0x0F)]));
        }
        Self(hex)
    }
}

impl PartialEq for KeyId {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for KeyId {}

// Consistent with `PartialEq`: the digest is always stored upper-cased, so
// equal IDs have identical strings.
impl std::hash::Hash for KeyId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.0)
    }
}

// ---------------------------------------------------------------- identicon

/// Colours are compatible with the original ANSI SGR codes (30 + value).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IdenticonColor {
    Red = 1,
    Green = 2,
    Yellow = 3,
    Blue = 4,
    Magenta = 5,
    Cyan = 6,
    Mono = 7,
}

impl IdenticonColor {
    pub const ALL: [Self; 7] = [
        Self::Red,
        Self::Green,
        Self::Yellow,
        Self::Blue,
        Self::Magenta,
        Self::Cyan,
        Self::Mono,
    ];

    pub fn from_u8(value: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|c| *c as u8 == value)
    }
}

/// A small pictogram derived from the full name and master password.
///
/// It lets the user spot a mistyped master password at a glance.  It is a
/// *hint only*: it reveals a few bits about the password, so it is shown only
/// after a short pause in typing and is never a substitute for the key ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identicon {
    pub left_arm: String,
    pub body: String,
    pub right_arm: String,
    pub accessory: String,
    pub color: IdenticonColor,
}

impl Identicon {
    /// The four glyphs as displayed: left arm, body, right arm, accessory.
    pub fn text(&self) -> String {
        format!(
            "{}{}{}{}",
            self.left_arm, self.body, self.right_arm, self.accessory
        )
    }

    /// The export-file encoding: `<color>:<left><body><right><accessory>`.
    pub fn encode(&self) -> String {
        format!("{}:{}", self.color as u8, self.text())
    }

    /// Parse the export-file encoding produced by [`Identicon::encode`].
    pub fn decode(encoded: &str) -> Option<Self> {
        let (color, glyphs) = encoded.split_once(':')?;
        let color = IdenticonColor::from_u8(color.trim().parse().ok()?)?;
        let mut chars = glyphs.chars();
        let mut next = || chars.next().map(String::from);
        let identicon = Self {
            left_arm: next()?,
            body: next()?,
            right_arm: next()?,
            accessory: next()?,
            color,
        };
        chars.next().is_none().then_some(identicon)
    }
}

impl fmt::Display for Identicon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_type_values_match_the_reference() {
        let expected = [16, 17, 18, 19, 20, 21, 30, 31, 1056, 2081, 4160];
        for (t, v) in ResultType::ALL.into_iter().zip(expected) {
            assert_eq!(t.as_u32(), v, "{t:?}");
            assert_eq!(ResultType::from_u32(v), Some(t));
        }
        assert_eq!(ResultType::from_u32(0), None);
    }

    #[test]
    fn result_type_names() {
        assert_eq!(
            ResultType::from_name("x"),
            Some(ResultType::TemplateMaximum)
        );
        assert_eq!(ResultType::from_name("p"), Some(ResultType::TemplatePhrase));
        assert_eq!(
            ResultType::from_name("P"),
            Some(ResultType::StatefulPersonal)
        );
        assert_eq!(
            ResultType::from_name("Long"),
            Some(ResultType::TemplateLong)
        );
        assert_eq!(
            ResultType::from_name("med"),
            Some(ResultType::TemplateMedium)
        );
        assert_eq!(ResultType::from_name(""), None);
        assert_eq!(ResultType::from_name("nope"), None);
    }

    #[test]
    fn key_id_normalises_and_validates() {
        let lower = "98eef4d1df46d849574a82a03c3177056b15dffca29bb3899de4628453675302";
        let id = KeyId::from_hex(lower).unwrap();
        assert_eq!(id.as_str(), lower.to_ascii_uppercase());
        assert_eq!(id, KeyId::from_hex(&lower.to_ascii_uppercase()).unwrap());
        assert!(KeyId::from_hex("abc").is_none());
        assert!(KeyId::from_hex(&"g".repeat(64)).is_none());
    }

    #[test]
    fn identicon_round_trips() {
        let identicon = Identicon {
            left_arm: "╔".into(),
            body: "░".into(),
            right_arm: "╝".into(),
            accessory: "⌚".into(),
            color: IdenticonColor::Green,
        };
        assert_eq!(identicon.encode(), "2:╔░╝⌚");
        assert_eq!(Identicon::decode(&identicon.encode()), Some(identicon));
        assert_eq!(Identicon::decode("9:╔░╝⌚"), None);
        assert_eq!(Identicon::decode("2:╔░╝"), None);
    }
}
