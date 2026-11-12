//! Just enough X.509 DER to describe a smart-card certificate: validity,
//! common name, key usage, and the subject public key.
//!
//! Input comes from a card and is untrusted: every length is checked, nothing
//! is indexed without bounds, nesting is shallow and fixed.  Parse failures
//! are `None`, never panics.

/// A DER element: tag byte and contents.
#[derive(Debug, Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

/// Read one element; returns it and the rest.
fn read(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((Tlv { tag, content: &rest[..len] }, &rest[len..]))
}

/// All elements of a constructed element's contents.
fn children(content: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let (tlv, r) = read(rest)?;
        out.push(tlv);
        rest = r;
        if out.len() > 64 {
            return None;
        }
    }
    Some(out)
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const OID: u8 = 0x06;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const INTEGER: u8 = 0x02;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;

const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];

/// The X.509 keyUsage extension.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyUsage {
    pub digital_signature: bool,
    pub non_repudiation: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
}

/// The subject public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// `bits` of modulus; `der` is the PKCS#1 RSAPublicKey (what
    /// `SecKeyCreateWithData` takes for RSA).
    Rsa { bits: u32, der: Vec<u8> },
    /// Curve size; `point` is the X9.63 uncompressed point.
    Ec { bits: u32, point: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub common_name: Option<String>,
    /// Unix seconds.
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    /// `None`: no keyUsage extension (any use allowed).
    pub key_usage: Option<KeyUsage>,
    pub public_key: Option<PublicKey>,
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn parse_time(t: &Tlv<'_>) -> Option<i64> {
    let s = std::str::from_utf8(t.content).ok()?.strip_suffix('Z')?;
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (year, rest) = match t.tag {
        UTC_TIME if s.len() == 12 => {
            let yy: i64 = s[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..])
        }
        GENERALIZED_TIME if s.len() == 14 => (s[..4].parse().ok()?, &s[4..]),
        _ => return None,
    };
    let n = |i: usize| rest.get(i..i + 2)?.parse::<i64>().ok();
    let (mo, d, h, mi, se) = (n(0)?, n(2)?, n(4)?, n(6)?, n(8)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    Some(days_from_civil(year, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

fn common_name(name: &Tlv<'_>) -> Option<String> {
    for rdn in children(name.content)? {
        if rdn.tag != SET {
            continue;
        }
        for atv in children(rdn.content)? {
            let parts = children(atv.content)?;
            if let [oid, value] = parts.as_slice() {
                if oid.tag == OID && oid.content == OID_CN {
                    return String::from_utf8(value.content.to_vec()).ok();
                }
            }
        }
    }
    None
}

fn key_usage(extensions: &Tlv<'_>) -> Option<KeyUsage> {
    // [3] EXPLICIT { SEQUENCE OF Extension }
    let seq = read(extensions.content)?.0;
    for ext in children(seq.content)? {
        let parts = children(ext.content)?;
        let (oid, value) = match parts.as_slice() {
            [oid, value] | [oid, _, value] => (oid, value),
            _ => continue,
        };
        if oid.tag != OID || oid.content != OID_KEY_USAGE || value.tag != OCTET_STRING {
            continue;
        }
        let bits = read(value.content)?.0;
        if bits.tag != BIT_STRING {
            return None;
        }
        let b = bits.content.get(1).copied().unwrap_or(0);
        return Some(KeyUsage {
            digital_signature: b & 0x80 != 0,
            non_repudiation: b & 0x40 != 0,
            key_encipherment: b & 0x20 != 0,
            data_encipherment: b & 0x10 != 0,
            key_agreement: b & 0x08 != 0,
        });
    }
    None
}

fn strip_integer(bytes: &[u8]) -> &[u8] {
    let mut b = bytes;
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    b
}

fn public_key(spki: &Tlv<'_>) -> Option<PublicKey> {
    let parts = children(spki.content)?;
    let [alg, key] = parts.as_slice() else { return None };
    let alg = children(alg.content)?;
    if key.tag != BIT_STRING || key.content.first() != Some(&0) {
        return None;
    }
    let key_bytes = &key.content[1..];
    let oid = alg.first().filter(|o| o.tag == OID)?.content;
    if oid == OID_RSA {
        let rsa = read(key_bytes)?.0;
        let modulus = children(rsa.content)?.into_iter().find(|t| t.tag == INTEGER)?;
        let n = strip_integer(modulus.content);
        let bits = (n.len() * 8) as u32 - n.first().map_or(8, |b| b.leading_zeros());
        Some(PublicKey::Rsa { bits, der: key_bytes.to_vec() })
    } else if oid == OID_EC {
        let curve = alg.get(1).filter(|c| c.tag == OID)?.content;
        let size = match curve {
            c if c == OID_P256 => 256,
            c if c == OID_P384 => 384,
            c if c == OID_P521 => 521,
            _ => return None,
        };
        Some(PublicKey::Ec { bits: size, point: key_bytes.to_vec() })
    } else {
        None
    }
}

/// Describe a DER certificate.  `None` if it is not one we can read.
pub fn parse(der: &[u8]) -> Option<CertInfo> {
    let (cert, _) = read(der)?;
    if cert.tag != SEQUENCE {
        return None;
    }
    let tbs = *children(cert.content)?.first()?;
    let fields = children(tbs.content)?;
    // Skip the optional [0] version.
    let f: Vec<&Tlv<'_>> = fields.iter().skip_while(|t| t.tag == 0xa0).collect();
    // serial, signature, issuer, validity, subject, spki, ...
    let validity = children(f.get(3)?.content)?;
    let subject = f.get(4)?;
    let spki = f.get(5)?;
    let extensions = fields.iter().find(|t| t.tag == 0xa3);
    Some(CertInfo {
        common_name: common_name(subject),
        not_before: validity.first().and_then(parse_time),
        not_after: validity.get(1).and_then(parse_time),
        key_usage: extensions.and_then(key_usage),
        public_key: public_key(spki),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EC: &[u8] = include_bytes!("../testdata/test-ec.der");
    const SIG: &[u8] = include_bytes!("../testdata/test-sig.der");
    const RSA: &[u8] = include_bytes!("../testdata/test-rsa.der");

    #[test]
    fn reads_test_certificates() {
        let ec = parse(EC).unwrap();
        assert_eq!(ec.common_name.as_deref(), Some("TEST KEYMGMT"));
        let usage = ec.key_usage.unwrap();
        assert!(usage.key_agreement && !usage.digital_signature);
        // Nov 12 18:22:39 2026 GMT
        assert_eq!(ec.not_before, Some(1_794_507_759));
        assert_eq!(ec.not_after.unwrap() - ec.not_before.unwrap(), 365 * 86_400);
        match ec.public_key.unwrap() {
            PublicKey::Ec { bits, point } => assert_eq!((bits, point.len(), point[0]), (256, 65, 4)),
            other => panic!("{other:?}"),
        }

        let sig = parse(SIG).unwrap();
        let usage = sig.key_usage.unwrap();
        assert!(usage.digital_signature && usage.non_repudiation && !usage.key_agreement);

        let rsa = parse(RSA).unwrap();
        assert!(rsa.key_usage.unwrap().key_encipherment);
        match rsa.public_key.unwrap() {
            PublicKey::Rsa { bits, der } => {
                assert_eq!(bits, 1024);
                assert_eq!(der[0], SEQUENCE);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn garbage_is_rejected_not_panicked_on() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
        for cut in 0..EC.len() {
            let _ = parse(&EC[..cut]);
        }
        let mut flipped = EC.to_vec();
        for i in 0..flipped.len() {
            flipped[i] ^= 0x5a;
            let _ = parse(&flipped);
            flipped[i] ^= 0x5a;
        }
    }
}
