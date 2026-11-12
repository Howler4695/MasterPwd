//! Key derivation and result encoding.
//!
//! Port of `mpw-algorithm.c` and `mpw-algorithm_v0..v3.c`.  The differences
//! between the versions are, in short:
//!
//! | version | master-key salt `#fullName` | site salt `#siteName`/`#context` | template seed bytes |
//! | ------- | --------------------------- | -------------------------------- | ------------------- |
//! | v0      | characters                  | characters                       | v0 quirk (see [`v0_seed_index`]) |
//! | v1      | characters                  | characters                       | plain `u8`          |
//! | v2      | characters                  | bytes                            | plain `u8`          |
//! | v3      | bytes                       | bytes                            | plain `u8`          |
//!
//! Stateful results and derived keys are identical across all versions.

use crate::templates::{class_characters, templates};
use crate::types::COUNTER_TOTP;
use crate::{
    AlgorithmVersion, Counter, Error, Identicon, IdenticonColor, KeyId, KeyPurpose, ResultType,
};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Size of a master key in bytes.
pub const MASTER_KEY_SIZE: usize = 64;

/// Size of a site key in bytes (the output of HMAC-SHA-256).
const SITE_KEY_SIZE: usize = 32;

/// scrypt cost parameters: N = 2^15 = 32768, r = 8, p = 2.
const SCRYPT_LOG_N: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 2;

/// The TOTP window: counter 0 is replaced by the current time rounded down to
/// a multiple of this many seconds.
const OTP_WINDOW: u32 = 5 * 60;

/// AES block length; the reference uses AES-128, i.e. a 16-byte key.
const AES_BLOCK: usize = 16;
const AES_KEY: usize = 16;

/// Default and bounds for [`ResultType::DeriveKey`] key sizes, in bits.
const DERIVE_KEY_BITS_DEFAULT: i64 = 512;
const DERIVE_KEY_BITS_MIN: i64 = 128;
const DERIVE_KEY_BITS_MAX: i64 = 512;

type HmacSha256 = Hmac<Sha256>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type SiteKey = Zeroizing<[u8; SITE_KEY_SIZE]>;

/// A user's master key for one algorithm version.
///
/// The key is wiped from memory when dropped.  It deliberately implements
/// neither `Debug` (beyond a redacted form), `Display` nor `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; MASTER_KEY_SIZE],
    #[zeroize(skip)]
    algorithm: AlgorithmVersion,
}

impl MasterKey {
    /// Derive the master key from the user's full name and master password.
    ///
    /// This is deliberately slow (scrypt N=32768, r=8, p=2); call it off the
    /// UI thread.
    pub fn derive(
        full_name: &str,
        master_password: &str,
        algorithm: AlgorithmVersion,
    ) -> Result<Self, Error> {
        if full_name.is_empty() {
            return Err(Error::EmptyFullName);
        }
        if master_password.is_empty() {
            return Err(Error::EmptyMasterPassword);
        }

        // salt = scope . #fullName . fullName
        // v0-v2 count the name in UTF-8 characters, v3 in bytes.
        let name_length = match algorithm {
            AlgorithmVersion::V0 | AlgorithmVersion::V1 | AlgorithmVersion::V2 => {
                utf8_char_count(full_name)?
            }
            AlgorithmVersion::V3 => byte_count(full_name)?,
        };
        let scope = KeyPurpose::Authentication.scope();
        let mut salt = Vec::with_capacity(scope.len() + 4 + full_name.len());
        salt.extend_from_slice(scope.as_bytes());
        salt.extend_from_slice(&name_length.to_be_bytes());
        salt.extend_from_slice(full_name.as_bytes());

        let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, MASTER_KEY_SIZE)
            .map_err(|e| Error::KeyDerivation(e.to_string()))?;
        let mut key = Self {
            bytes: [0; MASTER_KEY_SIZE],
            algorithm,
        };
        scrypt::scrypt(master_password.as_bytes(), &salt, &params, &mut key.bytes)
            .map_err(|e| Error::KeyDerivation(e.to_string()))?;
        Ok(key)
    }

    /// Rebuild a key from raw bytes, e.g. when restoring it from the keychain.
    pub fn from_bytes(bytes: [u8; MASTER_KEY_SIZE], algorithm: AlgorithmVersion) -> Self {
        Self { bytes, algorithm }
    }

    /// The raw key material.  Handle with care.
    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_SIZE] {
        &self.bytes
    }

    /// The algorithm version this key was derived with.  Site results must be
    /// requested from a key of the site's own algorithm version.
    pub fn algorithm(&self) -> AlgorithmVersion {
        self.algorithm
    }

    /// The key's fingerprint.
    pub fn key_id(&self) -> KeyId {
        let digest: [u8; 32] = Sha256::digest(self.bytes).into();
        KeyId::from_digest(&digest)
    }

    /// Compute a site result: a generated password, login name or answer for
    /// template types, the decrypted stored value for stateful types (pass the
    /// stored state as `result_param`), or a derived key for
    /// [`ResultType::DeriveKey`].
    ///
    /// `context` is the security-question keyword for recovery results.
    pub fn site_result(
        &self,
        site_name: &str,
        counter: Counter,
        purpose: KeyPurpose,
        context: Option<&str>,
        result_type: ResultType,
        result_param: Option<&str>,
    ) -> Result<Zeroizing<String>, Error> {
        // The reference treats empty strings as absent.
        let result_param = result_param.filter(|p| !p.is_empty());
        let site_key = self.site_key(site_name, counter, purpose, context)?;

        if result_type.is_template() {
            self.template_result(&site_key, result_type)
        } else if result_type.is_stateful() {
            self.decrypt_state(result_param.ok_or(Error::MissingResultParam)?)
        } else if result_type.is_derive() {
            derived_key(&site_key, result_type, result_param)
        } else {
            Err(Error::UnsupportedResultType(result_type.as_u32()))
        }
    }

    /// Encrypt a user-chosen value into the state to store for a stateful
    /// result type.  Feed the returned state back to [`MasterKey::site_result`]
    /// as `result_param` to recover `plaintext`.
    pub fn site_state(
        &self,
        site_name: &str,
        counter: Counter,
        purpose: KeyPurpose,
        context: Option<&str>,
        result_type: ResultType,
        plaintext: &str,
    ) -> Result<String, Error> {
        // The reference derives (and then ignores) the site key here; we only
        // validate the same inputs it would have rejected.
        let _ = (counter, purpose, context);
        if site_name.is_empty() {
            return Err(Error::EmptySiteName);
        }
        if !result_type.is_stateful() {
            return Err(Error::UnsupportedResultType(result_type.as_u32()));
        }
        if plaintext.is_empty() {
            return Err(Error::MissingResultParam);
        }
        self.encrypt_state(plaintext.as_bytes())
    }

    // ------------------------------------------------------------ internals

    /// `site-key = HMAC-SHA-256(master-key, scope . #siteName . siteName . counter [. #context . context])`
    fn site_key(
        &self,
        site_name: &str,
        counter: Counter,
        purpose: KeyPurpose,
        context: Option<&str>,
    ) -> Result<SiteKey, Error> {
        if site_name.is_empty() {
            return Err(Error::EmptySiteName);
        }
        let context = context.filter(|c| !c.is_empty());
        let counter = if counter == COUNTER_TOTP {
            totp_counter()
        } else {
            counter
        };

        // v0 and v1 count the site name and context in characters, v2+ in bytes.
        let length = |s: &str| match self.algorithm {
            AlgorithmVersion::V0 | AlgorithmVersion::V1 => utf8_char_count(s),
            AlgorithmVersion::V2 | AlgorithmVersion::V3 => byte_count(s),
        };

        let scope = purpose.scope();
        let mut salt = Vec::with_capacity(
            scope.len() + 4 + site_name.len() + 4 + context.map_or(0, |c| 4 + c.len()),
        );
        salt.extend_from_slice(scope.as_bytes());
        salt.extend_from_slice(&length(site_name)?.to_be_bytes());
        salt.extend_from_slice(site_name.as_bytes());
        salt.extend_from_slice(&counter.to_be_bytes());
        if let Some(context) = context {
            salt.extend_from_slice(&length(context)?.to_be_bytes());
            salt.extend_from_slice(context.as_bytes());
        }

        let mut mac = HmacSha256::new_from_slice(&self.bytes)
            .map_err(|_| Error::Internal("HMAC key rejected".into()))?;
        mac.update(&salt);
        let mut site_key: SiteKey = Zeroizing::new([0; SITE_KEY_SIZE]);
        let mut output = mac.finalize().into_bytes();
        site_key.copy_from_slice(&output);
        output.as_mut_slice().zeroize();
        Ok(site_key)
    }

    /// Encode a password from the site key using the result type's templates.
    fn template_result(
        &self,
        site_key: &SiteKey,
        result_type: ResultType,
    ) -> Result<Zeroizing<String>, Error> {
        let unsupported = || Error::UnsupportedResultType(result_type.as_u32());
        let templates = templates(result_type).ok_or_else(unsupported)?;
        let seed = |i: usize| -> Result<usize, Error> {
            let byte = *site_key
                .get(i)
                .ok_or_else(|| Error::Internal("template too long for site key".into()))?;
            Ok(match self.algorithm {
                AlgorithmVersion::V0 => usize::from(v0_seed_index(byte)),
                _ => usize::from(byte),
            })
        };

        let template = pick(templates, seed(0)?)
            .ok_or_else(unsupported)?
            .as_bytes();
        let mut password = Zeroizing::new(String::with_capacity(template.len()));
        for (c, &class) in template.iter().enumerate() {
            let characters = class_characters(class)
                .ok_or_else(|| Error::Internal("unknown character class".into()))?
                .as_bytes();
            let character = *pick(characters, seed(c + 1)?)
                .ok_or_else(|| Error::Internal("empty character class".into()))?;
            password.push(char::from(character));
        }
        Ok(password)
    }

    /// `mpw_site_state_v0`: AES-128-CBC (key = first 16 bytes of the master
    /// key, zero IV, PKCS#7 padding), then base64.
    fn encrypt_state(&self, plaintext: &[u8]) -> Result<String, Error> {
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

        let padded_len = (plaintext.len() / AES_BLOCK + 1) * AES_BLOCK;
        let mut buf = Zeroizing::new(vec![0u8; padded_len]);
        buf.get_mut(..plaintext.len())
            .ok_or_else(|| Error::Internal("buffer too small".into()))?
            .copy_from_slice(plaintext);

        let cipher = Aes128CbcEnc::new_from_slices(self.aes_key()?, &[0u8; AES_BLOCK])
            .map_err(|_| Error::Internal("invalid AES key length".into()))?;
        let ciphertext = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .map_err(|_| Error::Internal("AES padding failed".into()))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(ciphertext))
    }

    /// `mpw_site_crypted_password_v0`: the inverse of [`Self::encrypt_state`].
    fn decrypt_state(&self, state: &str) -> Result<Zeroizing<String>, Error> {
        use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};

        // Compatibility: the reference returns a state whose length is not a
        // multiple of four verbatim, because old .mpsites files stored some
        // values (e.g. login names) unencrypted.
        if state.len() % 4 != 0 {
            return Ok(Zeroizing::new(state.to_owned()));
        }

        let mut buf = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(state)
                .map_err(|_| Error::InvalidState)?,
        );
        if buf.is_empty() || buf.len() % AES_BLOCK != 0 {
            return Err(Error::InvalidState);
        }

        let cipher = Aes128CbcDec::new_from_slices(self.aes_key()?, &[0u8; AES_BLOCK])
            .map_err(|_| Error::Internal("invalid AES key length".into()))?;
        let plain_len = {
            let decrypted = cipher
                .decrypt_padded_mut::<NoPadding>(&mut buf)
                .map_err(|_| Error::InvalidState)?;
            pkcs7_unpadded_len(decrypted).ok_or(Error::InvalidState)?
        };
        let plain = buf.get(..plain_len).ok_or(Error::InvalidState)?;
        let text = std::str::from_utf8(plain).map_err(|_| Error::InvalidState)?;

        let mut result = Zeroizing::new(String::with_capacity(text.len()));
        result.push_str(text);
        Ok(result)
    }

    fn aes_key(&self) -> Result<&[u8], Error> {
        self.bytes
            .get(..AES_KEY)
            .ok_or_else(|| Error::Internal("master key too short".into()))
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey({}, <redacted>)", self.algorithm)
    }
}

/// `mpw_site_derived_password_v0`: BLAKE2b keyed with the site key, of
/// `result_param` bits (default 512), base64-encoded.
fn derived_key(
    site_key: &SiteKey,
    result_type: ResultType,
    result_param: Option<&str>,
) -> Result<Zeroizing<String>, Error> {
    if result_type != ResultType::DeriveKey {
        return Err(Error::UnsupportedResultType(result_type.as_u32()));
    }
    let param = result_param.ok_or(Error::MissingResultParam)?;
    let mut bits = c_strtol(param);
    if bits == 0 {
        bits = DERIVE_KEY_BITS_DEFAULT;
    }
    if !(DERIVE_KEY_BITS_MIN..=DERIVE_KEY_BITS_MAX).contains(&bits) || bits % 8 != 0 {
        return Err(Error::InvalidResultParam(
            "the key size must be 128-512 bits, a multiple of 8",
        ));
    }
    let size = usize::try_from(bits / 8).map_err(|_| Error::Internal("key size".into()))?;

    // libsodium crypto_generichash_blake2b_salt_personal with an empty message,
    // an all-zero salt and an all-zero personalisation == plain keyed BLAKE2b.
    let hash = blake2b_simd::Params::new()
        .hash_length(size)
        .key(site_key.as_slice())
        .salt(&[0; 16])
        .personal(&[0; 16])
        .hash(&[]);
    // NOTE: `blake2b_simd::Hash` is `Copy` and cannot be wiped reliably; it
    // holds the derived key until its stack slot is reused.
    let mut key = Zeroizing::new(hash.as_bytes().to_vec());

    let mut encoded = Zeroizing::new(String::with_capacity(size.div_ceil(3) * 4));
    base64::engine::general_purpose::STANDARD.encode_string(key.as_slice(), &mut encoded);
    key.zeroize();
    Ok(encoded)
}

/// Compute the identicon for a full name and master password.
///
/// `seed = HMAC-SHA-256(key = master password, message = full name)`.
///
/// Note: the reference returns an "unset" identicon when either input is
/// empty.  This signature cannot express that; for empty inputs we still
/// compute a (meaningless but deterministic) identicon.  Callers should not
/// display it before both inputs are non-empty.
pub fn identicon(full_name: &str, master_password: &str) -> Identicon {
    const LEFT_ARMS: [&str; 4] = ["╔", "╚", "╰", "═"];
    const BODIES: [&str; 6] = ["█", "░", "▒", "▓", "☺", "☻"];
    const RIGHT_ARMS: [&str; 4] = ["╗", "╝", "╯", "═"];
    const ACCESSORIES: [&str; 57] = [
        "◈", "◎", "◐", "◑", "◒", "◓", "☀", "☁", "☂", "☃", "☄", "★", "☆", "☎", "☏", "⎈", "⌂", "☘",
        "☢", "☣", "☕", "⌚", "⌛", "⏰", "⚡", "⛄", "⛅", "☔", "♔", "♕", "♖", "♗", "♘", "♙",
        "♚", "♛", "♜", "♝", "♞", "♟", "♨", "♩", "♪", "♫", "⚐", "⚑", "⚔", "⚖", "⚙", "⚠", "⌘", "⏎",
        "✄", "✆", "✈", "✉", "✌",
    ];

    let mut seed = [0u8; 32];
    // HMAC accepts keys of any length, so this cannot fail; fall back to an
    // all-zero seed rather than panicking if it ever did.
    if let Ok(mut mac) = HmacSha256::new_from_slice(master_password.as_bytes()) {
        mac.update(full_name.as_bytes());
        let mut out = mac.finalize().into_bytes();
        seed.copy_from_slice(&out);
        out.as_mut_slice().zeroize();
    }

    let pick_str = |list: &[&'static str], b: u8| -> &'static str {
        pick(list, usize::from(b)).copied().unwrap_or("")
    };
    let colors = IdenticonColor::ALL;
    let identicon = Identicon {
        left_arm: pick_str(&LEFT_ARMS, seed[0]).to_owned(),
        body: pick_str(&BODIES, seed[1]).to_owned(),
        right_arm: pick_str(&RIGHT_ARMS, seed[2]).to_owned(),
        accessory: pick_str(&ACCESSORIES, seed[3]).to_owned(),
        color: pick(&colors, usize::from(seed[4]))
            .copied()
            .unwrap_or(IdenticonColor::Mono),
    };
    seed.zeroize();
    identicon
}

// ------------------------------------------------------------------ helpers

/// `list[index % list.len()]`, or `None` for an empty list.
fn pick<T>(list: &[T], index: usize) -> Option<&T> {
    list.get(index.checked_rem(list.len())?)
}

/// The v0 template/character index for a site-key byte.
///
/// The reference (v0) reads the byte through a signed `char`, widens it to
/// `uint16_t` (sign-extending), writes that big-endian into the bytes of a
/// `uint16_t` and reads it back in host (little-endian) order.  The net effect
/// is a byte-swapped, sign-extended value: `0x05 -> 0x0500`, `0x85 -> 0x85FF`.
/// This is the "multi-byte template-index bug" fixed in v1, and it is part of
/// the v0 algorithm.
fn v0_seed_index(byte: u8) -> u16 {
    #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
    let widened = i16::from(byte as i8) as u16;
    widened.swap_bytes()
}

/// Number of UTF-8 characters, as `mpw_utf8_strchars` computes it for valid
/// UTF-8 (which every `&str` is).
fn utf8_char_count(s: &str) -> Result<u32, Error> {
    u32::try_from(s.chars().count()).map_err(|_| Error::Internal("input too long".into()))
}

fn byte_count(s: &str) -> Result<u32, Error> {
    u32::try_from(s.len()).map_err(|_| Error::Internal("input too long".into()))
}

/// The TOTP counter: now, rounded down to the OTP window, as a `u32`
/// (the reference truncates `time_t` to `uint32_t` the same way).
fn totp_counter() -> Counter {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    #[allow(clippy::cast_possible_truncation)]
    let now = now as u32;
    (now / OTP_WINDOW) * OTP_WINDOW
}

/// Strict PKCS#7 check; returns the unpadded length.
///
/// The reference only strips `n` bytes when the last byte `n <= 16` and never
/// verifies the padding.  Every state it ever produced carries valid PKCS#7
/// padding, so the strict check is compatible while also rejecting most
/// wrong-key decryptions.
fn pkcs7_unpadded_len(block: &[u8]) -> Option<usize> {
    let pad = usize::from(*block.last()?);
    if pad == 0 || pad > AES_BLOCK || pad > block.len() {
        return None;
    }
    let body = block.len() - pad;
    let padding = block.get(body..)?;
    padding
        .iter()
        .all(|&b| usize::from(b) == pad)
        .then_some(body)
}

/// `strtol(s, NULL, 10)`, saturating like C on overflow.
fn c_strtol(s: &str) -> i64 {
    let s = s.trim_start_matches([' ', '\t', '\n', '\x0B', '\x0C', '\r']);
    let (negative, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let mut value: i64 = 0;
    for b in digits.bytes().take_while(u8::is_ascii_digit) {
        let digit = i64::from(b - b'0');
        value = match value.checked_mul(10).and_then(|v| v.checked_add(digit)) {
            Some(v) => v,
            None => return if negative { i64::MIN } else { i64::MAX },
        };
    }
    if negative {
        -value
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v0_seed_index_reproduces_the_reference_quirk() {
        assert_eq!(v0_seed_index(0x00), 0x0000);
        assert_eq!(v0_seed_index(0x05), 0x0500);
        assert_eq!(v0_seed_index(0x7F), 0x7F00);
        assert_eq!(v0_seed_index(0x80), 0x80FF);
        assert_eq!(v0_seed_index(0xFF), 0xFFFF);
    }

    #[test]
    fn strtol_matches_c() {
        assert_eq!(c_strtol("256"), 256);
        assert_eq!(c_strtol("  128bits"), 128);
        assert_eq!(c_strtol("-8"), -8);
        assert_eq!(c_strtol("+64"), 64);
        assert_eq!(c_strtol("abc"), 0);
        assert_eq!(c_strtol(""), 0);
        assert_eq!(c_strtol("-"), 0);
        assert_eq!(c_strtol("99999999999999999999999"), i64::MAX);
    }

    #[test]
    fn pkcs7() {
        assert_eq!(pkcs7_unpadded_len(&[b'a', 1]), Some(1));
        assert_eq!(pkcs7_unpadded_len(&[b'a', 2, 2]), Some(1));
        assert_eq!(pkcs7_unpadded_len(&[b'a', 1, 2]), None);
        assert_eq!(pkcs7_unpadded_len(&[b'a', 0]), None);
        assert_eq!(pkcs7_unpadded_len(&[17; 17]), None);
        assert_eq!(pkcs7_unpadded_len(&[]), None);
    }
}
