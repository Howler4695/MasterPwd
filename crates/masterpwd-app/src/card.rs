//! Smart cards (CAC / PIV) as a second factor: the platform-independent part.
//!
//! [`SmartCards`] is the seam: the app uses the Security framework / CryptoTokenKit
//! implementation (`platform::smart_card`); tests and the smoke test use a
//! software implementation that runs the *same* wrap/unwrap code against
//! ephemeral software keys.
//!
//! Rules this module encodes:
//! * Secrets are only ever **encrypted to** a card's decryption key (RSA-OAEP-
//!   SHA256, or ECIES through the token's ECDH).  Signature-only keys are never
//!   used, and nothing is derived from signatures.
//! * An unwrap consumes at most one PIN attempt; callers never retry it
//!   automatically (a CAC locks after three wrong PINs).
//! * A card's display label (holder name, DoD ID…) is for the screen only: it
//!   is not `Debug`-printed, logged or persisted.

use std::fmt;

use mpw_core::Zeroizing;

use crate::x509::KeyUsage;

/// How a secret is wrapped to a card key.  The ids are persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WrapAlgorithm {
    /// RSA-OAEP with SHA-256 (never PKCS#1 v1.5).
    RsaOaepSha256,
    /// ECIES: ephemeral ECDH, X9.63 KDF with SHA-256, AES-GCM (Apple's
    /// `ECIESEncryptionStandardVariableIVX963SHA256AESGCM`).
    EciesStandardSha256AesGcm,
    /// The cofactor-ECDH variant (identical for the NIST P curves).
    EciesCofactorSha256AesGcm,
}

impl WrapAlgorithm {
    pub const ALL: [Self; 3] = [Self::RsaOaepSha256, Self::EciesStandardSha256AesGcm, Self::EciesCofactorSha256AesGcm];

    pub fn id(self) -> &'static str {
        match self {
            Self::RsaOaepSha256 => "rsa-oaep-sha256",
            Self::EciesStandardSha256AesGcm => "ecies-x963-sha256-aesgcm",
            Self::EciesCofactorSha256AesGcm => "ecies-cofactor-x963-sha256-aesgcm",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.id() == id)
    }

    pub fn is_rsa(self) -> bool {
        self == Self::RsaOaepSha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Rsa { bits: u32 },
    Ec { bits: u32 },
}

impl fmt::Display for KeyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa { bits } => write!(f, "RSA-{bits}"),
            Self::Ec { bits } => write!(f, "EC P-{bits}"),
        }
    }
}

/// Which PIV certificate slot a key appears to be in (from the token's item
/// labels; best effort).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivSlot {
    /// 9A, PIV Authentication: signs logins.
    Authentication,
    /// 9C, Digital Signature.
    Signature,
    /// 9D, Key Management: decrypts (email encryption).  What we want.
    KeyManagement,
    /// 9E, Card Authentication.
    CardAuthentication,
    /// 82–95, retired key-management keys.
    Retired,
    Unknown,
}

impl PivSlot {
    /// Guess from a token item label (e.g. "Certificate For Key Management").
    pub fn from_label(label: &str) -> Self {
        let l = label.to_ascii_lowercase();
        if l.contains("key management") || l.contains("encryption") {
            Self::KeyManagement
        } else if l.contains("retired") {
            Self::Retired
        } else if l.contains("card authentication") {
            Self::CardAuthentication
        } else if l.contains("digital signature") || l.contains("signature") {
            Self::Signature
        } else if l.contains("authentication") {
            Self::Authentication
        } else {
            Self::Unknown
        }
    }

    /// Fallback for cards whose item labels do not name the slot (seen on a
    /// DoD CAC): infer the role from the certificate's key usage.  An
    /// authentication certificate cannot be told from a card-authentication
    /// one this way; both sign and neither is ever used for wrapping.
    pub fn from_usage(usage: Option<KeyUsage>) -> Self {
        match usage {
            Some(u) if (u.key_encipherment || u.key_agreement) && !u.digital_signature => Self::KeyManagement,
            Some(u) if u.digital_signature && u.non_repudiation => Self::Signature,
            Some(u) if u.digital_signature => Self::Authentication,
            _ => Self::Unknown,
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::Authentication => "PIV Authentication (9A)",
            Self::Signature => "Digital Signature (9C)",
            Self::KeyManagement => "Key Management / Encryption (9D)",
            Self::CardAuthentication => "Card Authentication (9E)",
            Self::Retired => "Retired Key Management",
            Self::Unknown => "unknown slot",
        }
    }
}

/// A key on an inserted card (or a software test key).
#[derive(Clone, PartialEq, Eq)]
pub struct CardKey {
    /// CryptoTokenKit token id (identifies the inserted card instance).
    pub token_id: String,
    /// SHA-256 of the certificate (software keys: of the public key).
    pub fingerprint: [u8; 32],
    /// For the screen only (contains the holder's name / ID): never logged
    /// or persisted.
    pub label: String,
    pub slot: PivSlot,
    pub kind: KeyKind,
    pub usage: Option<KeyUsage>,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    /// Wrapping algorithms the private key can *decrypt* with.
    pub algorithms: Vec<WrapAlgorithm>,
    /// Public key: PKCS#1 RSAPublicKey or X9.63 EC point.
    pub public_key: Vec<u8>,
}

impl fmt::Debug for CardKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CardKey")
            .field("token_id", &self.token_id)
            .field("fingerprint", &hex(&self.fingerprint[..8]))
            .field("label", &"<redacted>")
            .field("slot", &self.slot)
            .field("kind", &self.kind)
            .field("usage", &self.usage)
            .field("algorithms", &self.algorithms)
            .finish_non_exhaustive()
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Fingerprint as shown to people: `AB:CD:…` (first 8 bytes).
pub fn short_fingerprint(fp: &[u8; 32]) -> String {
    fp[..8].iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

impl CardKey {
    /// Is the certificate's key usage compatible with decrypting for us?
    pub fn usage_allows_decryption(&self) -> bool {
        match (self.usage, self.kind) {
            (None, _) => true,
            (Some(u), KeyKind::Rsa { .. }) => u.key_encipherment || u.data_encipherment,
            (Some(u), KeyKind::Ec { .. }) => u.key_agreement,
        }
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.not_after.is_some_and(|t| t < now)
    }

    /// The algorithm to wrap with, if this key can be used at all.
    pub fn preferred_algorithm(&self) -> Option<WrapAlgorithm> {
        let order: &[WrapAlgorithm] = match self.kind {
            KeyKind::Rsa { bits } if bits >= 2048 => &[WrapAlgorithm::RsaOaepSha256],
            KeyKind::Rsa { .. } => &[],
            KeyKind::Ec { .. } => {
                &[WrapAlgorithm::EciesStandardSha256AesGcm, WrapAlgorithm::EciesCofactorSha256AesGcm]
            }
        };
        order.iter().copied().find(|a| self.algorithms.contains(a))
    }

    /// What we would wrap to.
    pub fn recipient(&self) -> Option<Recipient> {
        Some(Recipient { algorithm: self.preferred_algorithm()?, kind: self.kind, public_key: self.public_key.clone() })
    }
}

/// Everything needed to wrap a secret to a card key, without the card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    pub algorithm: WrapAlgorithm,
    pub kind: KeyKind,
    pub public_key: Vec<u8>,
}

/// Pick the key to enrol: usable for decryption, key usage compatible, not
/// expired; key-management slot first.  `Err` explains why none is usable.
pub fn choose(keys: &[CardKey], now: i64) -> Result<usize, String> {
    if keys.is_empty() {
        return Err("No smart card certificate was found.  Insert your card and try again.".into());
    }
    let mut best: Option<(u8, usize)> = None;
    let mut reasons = Vec::new();
    for (i, k) in keys.iter().enumerate() {
        if k.preferred_algorithm().is_none() {
            reasons.push(format!("{}: {} cannot decrypt with RSA-OAEP-SHA256 or ECIES", k.slot.describe(), k.kind));
            continue;
        }
        if !k.usage_allows_decryption() {
            reasons.push(format!("{}: signature-only certificate", k.slot.describe()));
            continue;
        }
        if k.is_expired(now) {
            reasons.push(format!("{}: certificate expired", k.slot.describe()));
            continue;
        }
        let rank = match k.slot {
            PivSlot::KeyManagement => 0,
            PivSlot::Unknown => 1,
            PivSlot::Retired => 2,
            _ => 3,
        };
        if best.is_none() || best.is_some_and(|(r, _)| rank < r) {
            best = Some((rank, i));
        }
    }
    best.map(|(_, i)| i).ok_or_else(|| {
        format!(
            "This card has no certificate that can decrypt (only signature keys?), so it cannot protect your \
             master key.  Details: {}.",
            reasons.join("; ")
        )
    })
}

/// Why an unwrap failed.  Each one is worded differently for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwrapError {
    /// The PIN dialog was cancelled.  No attempt was used.
    Cancelled,
    /// Wrong PIN.  (The card counts attempts; we never retry by ourselves.)
    WrongPin,
    /// The card was removed (or is not the enrolled card).
    CardNotPresent,
    /// Too many wrong PINs: the card is blocked.
    CardLocked,
    /// The card answered but could not decrypt: different key, or the stored
    /// data is damaged.
    DecryptFailed,
    Other(String),
}

impl fmt::Display for UnwrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("You cancelled the smart card PIN prompt."),
            Self::WrongPin => f.write_str(
                "The PIN was not accepted.  Be careful: your card locks after a few wrong PINs (3 on a CAC).",
            ),
            Self::CardNotPresent => f.write_str("The enrolled smart card is not inserted (or was removed)."),
            Self::CardLocked => f.write_str(
                "The smart card is locked after too many wrong PINs.  Use your recovery code; your card \
                 issuer can reset the PIN.",
            ),
            Self::DecryptFailed => f.write_str(
                "The smart card could not decrypt this user's key: wrong card, or the stored data is damaged.",
            ),
            Self::Other(e) => write!(f, "Smart card error: {e}"),
        }
    }
}

/// Map a Security / CryptoTokenKit error to an [`UnwrapError`].
///
/// Codes: `errSecUserCanceled` (-128), `errSecAuthFailed` (-25293),
/// `errSecItemNotFound` (-25300), CryptoTokenKit `TKErrorCode*`
/// (CanceledByUser -4, AuthenticationFailed -5, ObjectNotFound -6,
/// TokenNotFound -7).  A blocked PIN has no dedicated public code; it is
/// recognised from the message (unverified without a card).
pub fn map_error(domain: &str, code: i64, description: &str) -> UnwrapError {
    let d = description.to_ascii_lowercase();
    if d.contains("blocked") || d.contains("locked") {
        return UnwrapError::CardLocked;
    }
    let ctk = domain.contains("CryptoTokenKit") || domain.contains("TKError");
    match (ctk, code) {
        (_, -128) | (true, -4) => UnwrapError::Cancelled,
        (_, -25293) | (true, -5) => UnwrapError::WrongPin,
        (_, -25300) | (true, -6) | (true, -7) => UnwrapError::CardNotPresent,
        _ if d.contains("decrypt") || d.contains("decod") || d.contains("verif") => UnwrapError::DecryptFailed,
        // Generic CFError from SecKeyCreateDecryptedData on bad input.
        (false, -50) | (false, -26275) | (false, -67673) => UnwrapError::DecryptFailed,
        _ => UnwrapError::Other(format!("{domain} {code}")),
    }
}

/// The seam over the Security framework / CryptoTokenKit.
pub trait SmartCards: Send + Sync {
    /// Reader names (diagnostic).
    fn readers(&self) -> Result<Vec<String>, String>;
    /// Token ids of inserted cards (cheap; for presence tracking).
    fn tokens(&self) -> Vec<String>;
    /// Keys on inserted cards (reads certificates; no PIN).
    fn keys(&self) -> Result<Vec<CardKey>, String>;
    /// Encrypt `secret` to `recipient` (public operation; no card needed).
    fn wrap(&self, recipient: &Recipient, secret: &[u8]) -> Result<Vec<u8>, String>;
    /// Decrypt with the private key of the card key `fingerprint`: may show
    /// the system PIN prompt.  Exactly one attempt; never call it in a loop.
    /// Blocking: call off the main thread.
    fn unwrap(&self, fingerprint: &[u8; 32], algorithm: WrapAlgorithm, blob: &[u8])
        -> Result<Zeroizing<Vec<u8>>, UnwrapError>;
}

/// No smart card support (until the platform provides one).
pub struct NoCards;

impl SmartCards for NoCards {
    fn readers(&self) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
    fn tokens(&self) -> Vec<String> {
        Vec::new()
    }
    fn keys(&self) -> Result<Vec<CardKey>, String> {
        Ok(Vec::new())
    }
    fn wrap(&self, _: &Recipient, _: &[u8]) -> Result<Vec<u8>, String> {
        Err("smart cards are not supported here".into())
    }
    fn unwrap(&self, _: &[u8; 32], _: WrapAlgorithm, _: &[u8]) -> Result<Zeroizing<Vec<u8>>, UnwrapError> {
        Err(UnwrapError::CardNotPresent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(slot: PivSlot, kind: KeyKind, usage: Option<KeyUsage>, algorithms: Vec<WrapAlgorithm>) -> CardKey {
        CardKey {
            token_id: "t".into(),
            fingerprint: [1; 32],
            label: "Holder Name 1234567890".into(),
            slot,
            kind,
            usage,
            not_before: None,
            not_after: None,
            algorithms,
            public_key: vec![],
        }
    }

    const SIGN: KeyUsage = KeyUsage {
        digital_signature: true,
        non_repudiation: true,
        key_encipherment: false,
        data_encipherment: false,
        key_agreement: false,
    };
    const ENC: KeyUsage = KeyUsage { key_encipherment: true, ..SIGN };

    #[test]
    fn prefers_the_key_management_key_and_never_signature_keys() {
        let rsa = KeyKind::Rsa { bits: 2048 };
        let all = vec![WrapAlgorithm::RsaOaepSha256];
        let keys = vec![
            key(PivSlot::Authentication, rsa, Some(SIGN), all.clone()),
            key(PivSlot::Signature, rsa, Some(SIGN), all.clone()),
            key(PivSlot::KeyManagement, rsa, Some(ENC), all.clone()),
        ];
        assert_eq!(choose(&keys, 0), Ok(2));
        let err = choose(&keys[..2], 0).unwrap_err();
        assert!(err.contains("signature-only"), "{err}");
        assert!(choose(&[], 0).is_err());
    }

    #[test]
    fn algorithm_choice() {
        let ec = key(
            PivSlot::KeyManagement,
            KeyKind::Ec { bits: 256 },
            None,
            vec![WrapAlgorithm::EciesCofactorSha256AesGcm],
        );
        assert_eq!(ec.preferred_algorithm(), Some(WrapAlgorithm::EciesCofactorSha256AesGcm));
        // Weak RSA and keys without a decrypt algorithm are refused.
        let weak = key(PivSlot::KeyManagement, KeyKind::Rsa { bits: 1024 }, None, vec![WrapAlgorithm::RsaOaepSha256]);
        assert_eq!(weak.preferred_algorithm(), None);
        let none = key(PivSlot::KeyManagement, KeyKind::Rsa { bits: 2048 }, None, vec![]);
        assert!(choose(&[none], 0).unwrap_err().contains("cannot decrypt"));
        for a in WrapAlgorithm::ALL {
            assert_eq!(WrapAlgorithm::from_id(a.id()), Some(a));
        }
    }

    #[test]
    fn expired_keys_are_skipped() {
        let mut k = key(PivSlot::KeyManagement, KeyKind::Ec { bits: 384 }, None, vec![WrapAlgorithm::EciesStandardSha256AesGcm]);
        k.not_after = Some(100);
        assert!(choose(&[k], 200).unwrap_err().contains("expired"));
    }

    #[test]
    fn labels_are_not_debug_printed() {
        let k = key(PivSlot::KeyManagement, KeyKind::Ec { bits: 256 }, None, vec![]);
        assert!(!format!("{k:?}").contains("Holder"));
    }

    #[test]
    fn error_mapping() {
        assert_eq!(map_error("NSOSStatusErrorDomain", -128, ""), UnwrapError::Cancelled);
        assert_eq!(map_error("CryptoTokenKit", -4, ""), UnwrapError::Cancelled);
        assert_eq!(map_error("CryptoTokenKit", -5, ""), UnwrapError::WrongPin);
        assert_eq!(map_error("NSOSStatusErrorDomain", -25293, ""), UnwrapError::WrongPin);
        assert_eq!(map_error("CryptoTokenKit", -7, ""), UnwrapError::CardNotPresent);
        assert_eq!(map_error("CryptoTokenKit", -5, "PIN blocked"), UnwrapError::CardLocked);
        assert_eq!(map_error("NSOSStatusErrorDomain", -50, "RSAdecrypt wrong input"), UnwrapError::DecryptFailed);
        assert!(matches!(map_error("x", 1, "y"), UnwrapError::Other(_)));
        assert!(UnwrapError::WrongPin.to_string().contains("locks"));
    }

    #[test]
    fn piv_slot_from_labels() {
        assert_eq!(PivSlot::from_label("Certificate For Key Management"), PivSlot::KeyManagement);
        assert_eq!(PivSlot::from_label("Certificate For Digital Signature"), PivSlot::Signature);
        assert_eq!(PivSlot::from_label("Certificate For PIV Authentication"), PivSlot::Authentication);
        assert_eq!(PivSlot::from_label("Certificate For Card Authentication"), PivSlot::CardAuthentication);
        assert_eq!(PivSlot::from_label("whatever"), PivSlot::Unknown);

        // Fallback by key usage, as needed for a real CAC.
        let usage = |sig, nr, enc| Some(KeyUsage {
            digital_signature: sig,
            non_repudiation: nr,
            key_encipherment: enc,
            data_encipherment: false,
            key_agreement: false,
        });
        assert_eq!(PivSlot::from_usage(usage(false, false, true)), PivSlot::KeyManagement);
        assert_eq!(PivSlot::from_usage(usage(true, true, false)), PivSlot::Signature);
        assert_eq!(PivSlot::from_usage(usage(true, false, false)), PivSlot::Authentication);
        assert_eq!(PivSlot::from_usage(None), PivSlot::Unknown);
    }
}
