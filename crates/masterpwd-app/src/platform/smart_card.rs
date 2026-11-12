//! Smart cards through the Security framework and CryptoTokenKit.
//!
//! * Enumeration: token-backed identities (`kSecAttrAccessGroupToken`), i.e.
//!   the certificates the PIV token driver (`com.apple.CryptoTokenKit.pivtoken`)
//!   exposes for an inserted CAC/PIV card.  Reading certificates needs no PIN.
//!   The Secure Enclave token (`com.apple.setoken…`) is not a smart card and is
//!   filtered out.
//! * Wrap: `SecKeyCreateEncryptedData` with the certificate's public key
//!   (RSA-OAEP-SHA256 or ECIES X9.63-SHA256-AES-GCM); no card needed.
//! * Unwrap: `SecKeyCreateDecryptedData` with the token's private key.  The
//!   system shows the PIN prompt; we never see, cache or retry the PIN.
//!   Exactly one call per user action.  Blocking: run it off the main thread.
//!
//! [`SoftwareCards`] runs the very same wrap/unwrap functions against
//! ephemeral software keys (never stored in a keychain) for tests and the
//! smoke test.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::CFError;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use mpw_core::Zeroizing;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey};
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPublic, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyTypeRSA,
};
use security_framework_sys::key::{kSecKeyOperationTypeDecrypt, SecKeyCreateWithData, SecKeyIsAlgorithmSupported};
use sha2::{Digest, Sha256};

use crate::card::{map_error, CardKey, KeyKind, PivSlot, Recipient, SmartCards, UnwrapError, WrapAlgorithm};
use crate::x509;

fn sec_algorithm(a: WrapAlgorithm) -> Algorithm {
    match a {
        WrapAlgorithm::RsaOaepSha256 => Algorithm::RSAEncryptionOAEPSHA256,
        WrapAlgorithm::EciesStandardSha256AesGcm => Algorithm::ECIESEncryptionStandardVariableIVX963SHA256AESGCM,
        WrapAlgorithm::EciesCofactorSha256AesGcm => Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
    }
}

/// Which wrapping algorithms `private_key` can decrypt with.
fn supported_algorithms(private_key: &SecKey) -> Vec<WrapAlgorithm> {
    WrapAlgorithm::ALL
        .into_iter()
        .filter(|a| {
            // SAFETY: valid key ref; the algorithm is a framework constant.
            unsafe {
                SecKeyIsAlgorithmSupported(
                    private_key.as_concrete_TypeRef(),
                    kSecKeyOperationTypeDecrypt,
                    sec_algorithm(*a).into(),
                ) != 0
            }
        })
        .collect()
}

/// A public `SecKey` from its external representation.
fn public_key_from(recipient: &Recipient) -> Result<SecKey, String> {
    let (key_type, bits) = match recipient.kind {
        // SAFETY: framework constants.
        KeyKind::Rsa { bits } => (unsafe { kSecAttrKeyTypeRSA }, bits),
        KeyKind::Ec { bits } => (unsafe { kSecAttrKeyTypeECSECPrimeRandom }, bits),
    };
    // SAFETY: wrapping framework constant CFStrings (get rule).
    let attributes = unsafe {
        CFDictionary::from_CFType_pairs(&[
            (CFString::wrap_under_get_rule(kSecAttrKeyType), CFString::wrap_under_get_rule(key_type).as_CFType()),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyClass),
                CFString::wrap_under_get_rule(kSecAttrKeyClassPublic).as_CFType(),
            ),
            (CFString::wrap_under_get_rule(kSecAttrKeySizeInBits), CFNumber::from(bits as i64).as_CFType()),
        ])
    };
    let data = CFData::from_buffer(&recipient.public_key);
    let mut error = std::ptr::null_mut();
    // SAFETY: valid CFData/CFDictionary; on failure `error` is a +1 CFError.
    let key = unsafe { SecKeyCreateWithData(data.as_concrete_TypeRef(), attributes.as_concrete_TypeRef(), &mut error) };
    if key.is_null() {
        // SAFETY: create rule, as documented.
        let e = unsafe { CFError::wrap_under_create_rule(error) };
        return Err(format!("the card's public key is not usable: {}", e.description()));
    }
    // SAFETY: a +1 SecKeyRef we now own.
    Ok(unsafe { SecKey::wrap_under_create_rule(key) })
}

/// Encrypt `secret` to `recipient`.  Shared by the real and software cards.
pub fn wrap_to(recipient: &Recipient, secret: &[u8]) -> Result<Vec<u8>, String> {
    let key = public_key_from(recipient)?;
    key.encrypt_data(sec_algorithm(recipient.algorithm), secret)
        .map_err(|e| format!("could not encrypt to the card key: {}", e.description()))
}

/// Decrypt `blob` with `private_key`: ONE attempt.  Shared by the real and
/// software cards; for a token key this is where the PIN prompt appears.
pub fn unwrap_with(private_key: &SecKey, algorithm: WrapAlgorithm, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, UnwrapError> {
    private_key
        .decrypt_data(sec_algorithm(algorithm), blob)
        .map(Zeroizing::new)
        .map_err(|e| map_error(&e.domain().to_string(), e.code() as i64, &e.description().to_string()))
}

fn is_smart_card_token(token_id: &str) -> bool {
    !token_id.is_empty() && !token_id.starts_with("com.apple.setoken")
}

fn attribute_string(dict: &CFDictionary, key: &str) -> Option<String> {
    let key = CFString::new(key);
    let value = dict.find(key.as_CFTypeRef())?;
    // SAFETY: the value is a live CF object owned by `dict`.
    let value = unsafe { CFType::wrap_under_get_rule(*value) };
    value.downcast::<CFString>().map(|s| s.to_string())
}

/// The system's smart cards.
#[derive(Default)]
pub struct SystemCards;

thread_local! {
    static WATCHER: Option<objc2::rc::Retained<objc2_crypto_token_kit::TKTokenWatcher>> =
        // SAFETY: creating a token watcher has no preconditions.
        Some(unsafe { objc2_crypto_token_kit::TKTokenWatcher::new() });
}

impl SystemCards {
    /// The token identities with their private keys (no PIN needed).
    fn identities(&self) -> Result<Vec<(CardKey, SecKey)>, String> {
        let mut search = ItemSearchOptions::new();
        search.class(ItemClass::identity()).access_group_token().load_refs(true).limit(Limit::All);
        let results = match search.search() {
            Ok(r) => r,
            Err(e) if e.code() == -25300 => return Ok(Vec::new()), // errSecItemNotFound
            Err(e) => return Err(format!("searching smart card certificates failed: {e} ({})", e.code())),
        };
        let mut out = Vec::new();
        for result in results {
            let SearchResult::Ref(Reference::Identity(identity)) = result else { continue };
            let (Ok(cert), Ok(private_key)) = (identity.certificate(), identity.private_key()) else { continue };
            let attributes = private_key.attributes();
            let token_id = attribute_string(&attributes, "tkid").unwrap_or_default();
            if !is_smart_card_token(&token_id) {
                continue;
            }
            let item_label = attribute_string(&attributes, "labl").unwrap_or_default();
            let der = cert.to_der();
            let info = x509::parse(&der);
            let (kind, public_key) = match info.as_ref().and_then(|i| i.public_key.clone()) {
                Some(x509::PublicKey::Rsa { bits, der }) => (KeyKind::Rsa { bits }, der),
                Some(x509::PublicKey::Ec { bits, point }) => (KeyKind::Ec { bits }, point),
                None => continue,
            };
            let mut slot = PivSlot::from_label(&item_label);
            if slot == PivSlot::Unknown {
                slot = PivSlot::from_label(&cert.subject_summary());
            }
            let name = info.as_ref().and_then(|i| i.common_name.clone()).unwrap_or_else(|| cert.subject_summary());
            out.push((
                CardKey {
                    token_id,
                    fingerprint: Sha256::digest(&der).into(),
                    label: format!("{name} — {}", slot.describe()),
                    slot,
                    kind,
                    usage: info.as_ref().and_then(|i| i.key_usage),
                    not_before: info.as_ref().and_then(|i| i.not_before),
                    not_after: info.as_ref().and_then(|i| i.not_after),
                    algorithms: supported_algorithms(&private_key),
                    public_key,
                },
                private_key,
            ));
        }
        Ok(out)
    }
}

impl SmartCards for SystemCards {
    fn readers(&self) -> Result<Vec<String>, String> {
        // SAFETY: class method without arguments; nil without the
        // com.apple.security.smartcard entitlement.
        let manager = unsafe { objc2_crypto_token_kit::TKSmartCardSlotManager::defaultManager() }
            .ok_or("smart card readers are not accessible (missing com.apple.security.smartcard entitlement?)")?;
        // SAFETY: property getter.
        let names = unsafe { manager.slotNames() };
        Ok(names.iter().map(|n| n.to_string()).collect())
    }

    fn tokens(&self) -> Vec<String> {
        WATCHER.with(|w| match w {
            // SAFETY: property getter on a live watcher (main thread).
            Some(w) => unsafe { w.tokenIDs() }.iter().map(|t| t.to_string()).filter(|t| is_smart_card_token(t)).collect(),
            None => Vec::new(),
        })
    }

    fn keys(&self) -> Result<Vec<CardKey>, String> {
        Ok(self.identities()?.into_iter().map(|(k, _)| k).collect())
    }

    fn wrap(&self, recipient: &Recipient, secret: &[u8]) -> Result<Vec<u8>, String> {
        wrap_to(recipient, secret)
    }

    fn unwrap(&self, fingerprint: &[u8; 32], algorithm: WrapAlgorithm, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, UnwrapError> {
        let identities = self.identities().map_err(UnwrapError::Other)?;
        let (_, private_key) =
            identities.into_iter().find(|(k, _)| k.fingerprint == *fingerprint).ok_or(UnwrapError::CardNotPresent)?;
        unwrap_with(&private_key, algorithm, blob)
    }
}

// ------------------------------------------------------------- software

/// Ephemeral software keys behind the same seam (tests, smoke test).  The keys
/// live only in memory and vanish with the process.
pub struct SoftwareCards {
    keys: Vec<(CardKey, SecKey)>,
    present: Arc<AtomicBool>,
}

impl SoftwareCards {
    /// Generate RSA-2048, EC P-256 and EC P-384 keys.
    pub fn generate() -> Result<Self, String> {
        let mut keys = Vec::new();
        for (key_type, bits) in [(KeyType::rsa(), 2048u32), (KeyType::ec(), 256), (KeyType::ec(), 384)] {
            let mut options = GenerateKeyOptions::default();
            options.set_key_type(key_type).set_size_in_bits(bits);
            // No location: the key is not stored in any keychain.
            let private_key = SecKey::new(&options).map_err(|e| format!("key generation failed: {}", e.description()))?;
            let public = private_key.public_key().ok_or("no public key")?;
            let public_bytes = public.external_representation().ok_or("no public key data")?.to_vec();
            let kind = if bits == 2048 { KeyKind::Rsa { bits } } else { KeyKind::Ec { bits } };
            let key = CardKey {
                token_id: "software".into(),
                fingerprint: Sha256::digest(&public_bytes).into(),
                label: format!("Software test key ({kind})"),
                slot: PivSlot::KeyManagement,
                kind,
                usage: None,
                not_before: None,
                not_after: None,
                algorithms: supported_algorithms(&private_key),
                public_key: public_bytes,
            };
            keys.push((key, private_key));
        }
        Ok(Self { keys, present: Arc::new(AtomicBool::new(true)) })
    }

    /// Simulate removing / inserting the card.
    pub fn set_present(&self, present: bool) {
        self.present.store(present, Ordering::SeqCst);
    }

    pub fn presence(&self) -> Arc<AtomicBool> {
        self.present.clone()
    }
}

impl SmartCards for SoftwareCards {
    fn readers(&self) -> Result<Vec<String>, String> {
        Ok(vec!["Software reader".into()])
    }

    fn tokens(&self) -> Vec<String> {
        if self.present.load(Ordering::SeqCst) { vec!["software".into()] } else { Vec::new() }
    }

    fn keys(&self) -> Result<Vec<CardKey>, String> {
        Ok(if self.present.load(Ordering::SeqCst) { self.keys.iter().map(|(k, _)| k.clone()).collect() } else { Vec::new() })
    }

    fn wrap(&self, recipient: &Recipient, secret: &[u8]) -> Result<Vec<u8>, String> {
        wrap_to(recipient, secret)
    }

    fn unwrap(&self, fingerprint: &[u8; 32], algorithm: WrapAlgorithm, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, UnwrapError> {
        if !self.present.load(Ordering::SeqCst) {
            return Err(UnwrapError::CardNotPresent);
        }
        let (_, key) = self.keys.iter().find(|(k, _)| k.fingerprint == *fingerprint).ok_or(UnwrapError::CardNotPresent)?;
        unwrap_with(key, algorithm, blob)
    }
}

// ----------------------------------------------------------- diagnostic

fn date(t: Option<i64>) -> String {
    t.map_or_else(|| "?".into(), |t| mpw_model::Timestamp::from_unix(t).to_rfc3339())
}

/// `--smart-cards`: print readers, cards and keys; `verbose` adds subject
/// names (which identify the holder).
pub fn diagnose(verbose: bool) -> i32 {
    let cards = SystemCards;
    println!("Master Password smart card diagnostic");
    println!("Hardware tokens are read through CryptoTokenKit; nothing is decrypted and no PIN is asked.\n");
    match cards.readers() {
        Ok(r) if r.is_empty() => println!("Readers: none"),
        Ok(r) => r.iter().for_each(|n| println!("Reader: {n}")),
        Err(e) => println!("Readers: {e}"),
    }
    let tokens = cards.tokens();
    println!("Inserted smart card tokens: {}", if tokens.is_empty() { "none".into() } else { tokens.join(", ") });
    let keys = match cards.keys() {
        Ok(k) => k,
        Err(e) => {
            println!("Certificates: ERROR {e}");
            return 1;
        }
    };
    println!("Certificates with private keys: {}", keys.len());
    let now = mpw_model::Timestamp::now().as_unix();
    for (i, k) in keys.iter().enumerate() {
        println!("\n#{i}  token {}", k.token_id);
        if verbose {
            println!("    label:        {}", k.label);
        }
        println!("    fingerprint:  SHA-256 {}", crate::card::hex(&k.fingerprint));
        println!("    slot (guess): {}", k.slot.describe());
        println!("    key:          {}", k.kind);
        println!("    key usage:    {:?}", k.usage);
        println!("    valid:        {} … {}{}", date(k.not_before), date(k.not_after), if k.is_expired(now) { " (EXPIRED)" } else { "" });
        let algs: Vec<&str> = k.algorithms.iter().map(|a| a.id()).collect();
        println!("    decrypts with: {}", if algs.is_empty() { "nothing we use".into() } else { algs.join(", ") });
        println!("    usable:       {}", match (k.preferred_algorithm(), k.usage_allows_decryption()) {
            (Some(a), true) => format!("yes ({})", a.id()),
            (None, _) => "no (no supported decryption algorithm)".into(),
            (_, false) => "no (signature-only key usage)".into(),
        });
    }
    match crate::card::choose(&keys, now) {
        Ok(i) => println!("\nChosen key: #{i}"),
        Err(e) => println!("\nChosen key: none: {e}"),
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip_with_software_keys() {
        let cards = SoftwareCards::generate().unwrap();
        let secret = [7u8; 32];
        for key in cards.keys().unwrap() {
            let alg = key.preferred_algorithm().unwrap_or_else(|| panic!("{key:?} has no algorithm"));
            let recipient = key.recipient().unwrap();
            let blob = cards.wrap(&recipient, &secret).unwrap();
            assert_ne!(&blob[..], &secret[..]);
            let out = cards.unwrap(&key.fingerprint, alg, &blob).unwrap();
            assert_eq!(&out[..], &secret[..], "{}", key.kind);
            // Each wrap is randomised.
            assert_ne!(cards.wrap(&recipient, &secret).unwrap(), blob);
        }
    }

    #[test]
    fn software_keys_support_the_expected_algorithms() {
        let cards = SoftwareCards::generate().unwrap();
        let keys = cards.keys().unwrap();
        assert!(keys[0].algorithms.contains(&WrapAlgorithm::RsaOaepSha256));
        assert!(keys[1].algorithms.contains(&WrapAlgorithm::EciesStandardSha256AesGcm));
        assert_eq!(crate::card::choose(&keys, 0).map(|i| keys[i].slot), Ok(PivSlot::KeyManagement));
    }

    #[test]
    fn wrong_key_and_corrupted_blobs_fail_cleanly() {
        let cards = SoftwareCards::generate().unwrap();
        let keys = cards.keys().unwrap();
        let secret = [9u8; 32];
        for (a, b) in [(0usize, 0usize), (1, 2), (2, 1)] {
            let (ka, kb) = (&keys[a], &keys[b]);
            let blob = cards.wrap(&ka.recipient().unwrap(), &secret).unwrap();
            if a != b {
                // Encrypted to one key, decrypted with another.
                let r = cards.unwrap(&kb.fingerprint, ka.preferred_algorithm().unwrap(), &blob);
                assert!(matches!(r, Err(UnwrapError::DecryptFailed | UnwrapError::Other(_))), "{r:?}");
            }
            let mut corrupt = blob.clone();
            let last = corrupt.len() - 1;
            corrupt[last] ^= 1;
            let r = cards.unwrap(&ka.fingerprint, ka.preferred_algorithm().unwrap(), &corrupt);
            assert!(matches!(r, Err(UnwrapError::DecryptFailed | UnwrapError::Other(_))), "{r:?}");
            let r = cards.unwrap(&ka.fingerprint, ka.preferred_algorithm().unwrap(), &blob[..blob.len() / 2]);
            assert!(r.is_err());
        }
        cards.set_present(false);
        assert_eq!(cards.unwrap(&keys[0].fingerprint, WrapAlgorithm::RsaOaepSha256, b"x"), Err(UnwrapError::CardNotPresent));
        assert!(cards.tokens().is_empty());
    }

    #[test]
    fn system_enumeration_without_a_card_is_empty_not_an_error() {
        let keys = SystemCards.keys().expect("enumeration should not fail");
        assert!(keys.is_empty(), "a card is inserted? {keys:?}");
    }
}
