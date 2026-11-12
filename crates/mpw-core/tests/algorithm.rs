//! Behaviour tests beyond the reference vectors: stateful results, derived
//! keys, identicons, TOTP and input validation.
//!
//! Expected values for stateful states, derived keys and the identicon were
//! computed independently (Python `hashlib.scrypt`/`hmac`/`blake2b` and
//! `openssl enc -aes-128-cbc`), since `mpw_tests.xml` has no vectors for them.

use mpw_core::{
    identicon, AlgorithmVersion, Error, IdenticonColor, KeyPurpose, MasterKey, ResultType,
    COUNTER_DEFAULT, COUNTER_TOTP, MASTER_KEY_SIZE,
};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

const NAME: &str = "Robert Lee Mitchell";
const PASSWORD: &str = "banana colored duckling";
const SITE: &str = "masterpasswordapp.com";

/// scrypt is slow: derive each (name, password, version) once per test binary.
fn key(name: &str, password: &str, version: AlgorithmVersion) -> MasterKey {
    type Cache = Mutex<HashMap<(String, String, AlgorithmVersion), [u8; MASTER_KEY_SIZE]>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    let bytes = *cache
        .entry((name.into(), password.into(), version))
        .or_insert_with(|| {
            *MasterKey::derive(name, password, version)
                .unwrap()
                .as_bytes()
        });
    MasterKey::from_bytes(bytes, version)
}

fn result(key: &MasterKey, result_type: ResultType, param: Option<&str>) -> Result<String, Error> {
    key.site_result(
        SITE,
        COUNTER_DEFAULT,
        KeyPurpose::Authentication,
        None,
        result_type,
        param,
    )
    .map(|r| r.to_string())
}

fn state(key: &MasterKey, result_type: ResultType, plaintext: &str) -> Result<String, Error> {
    key.site_state(
        SITE,
        COUNTER_DEFAULT,
        KeyPurpose::Authentication,
        None,
        result_type,
        plaintext,
    )
}

// ------------------------------------------------------------------ stateful

#[test]
fn stateful_state_matches_independent_aes_128_cbc() {
    let k = key(NAME, PASSWORD, AlgorithmVersion::V3);
    for (plain, expected) in [
        ("hunter2", "q7EPkUsq6BtkK0/cX/pqzA=="),
        // Block-aligned plaintext gets a full padding block.
        (
            "0123456789abcdef",
            "kyPvEmWUc8ekKqfMU5sRwMnFZnwIQ08fGOdnhLwUgkg=",
        ),
        ("pässwörd ⛄", "zNyHEXGVAQAVQ38YdLsTbA=="),
    ] {
        assert_eq!(
            state(&k, ResultType::StatefulPersonal, plain).unwrap(),
            expected
        );
        assert_eq!(
            result(&k, ResultType::StatefulPersonal, Some(expected)).unwrap(),
            plain
        );
    }
}

#[test]
fn stateful_round_trips_for_every_version_and_type() {
    for version in AlgorithmVersion::ALL {
        let k = key(NAME, PASSWORD, version);
        for t in [ResultType::StatefulPersonal, ResultType::StatefulDevice] {
            for plain in [
                "x",
                "correct horse battery staple",
                "ünïcødé ⛄ 🎉",
                &"a".repeat(100),
            ] {
                let s = state(&k, t, plain).unwrap();
                assert_eq!(result(&k, t, Some(&s)).unwrap(), plain, "{version} {t:?}");
            }
        }
    }
}

#[test]
fn stateful_wrong_key_is_rejected() {
    let right = key(NAME, PASSWORD, AlgorithmVersion::V3);
    let wrong = key(NAME, "not the password", AlgorithmVersion::V3);
    for plain in [
        "hunter2",
        "0123456789abcdef",
        "a longer secret value, three blocks!!",
    ] {
        let s = state(&right, ResultType::StatefulPersonal, plain).unwrap();
        assert_eq!(
            result(&wrong, ResultType::StatefulPersonal, Some(&s)),
            Err(Error::InvalidState),
            "{plain}"
        );
    }
}

#[test]
fn stateful_garbage_state() {
    let k = key(NAME, PASSWORD, AlgorithmVersion::V3);
    let t = ResultType::StatefulPersonal;
    // Not base64 (length is a multiple of 4).
    assert_eq!(result(&k, t, Some("!!!!")), Err(Error::InvalidState));
    // Valid base64, but not a whole number of AES blocks.
    assert_eq!(result(&k, t, Some("AAAA")), Err(Error::InvalidState));
    // One block of zeros: decrypts to garbage padding.
    assert_eq!(
        result(&k, t, Some("AAAAAAAAAAAAAAAAAAAAAA==")),
        Err(Error::InvalidState)
    );
    // Compatibility: the reference returns a non-base64-length state verbatim
    // (old .mpsites stored some values unencrypted).
    assert_eq!(result(&k, t, Some("bob")).unwrap(), "bob");
    // Missing / empty state.
    assert_eq!(result(&k, t, None), Err(Error::MissingResultParam));
    assert_eq!(result(&k, t, Some("")), Err(Error::MissingResultParam));
    // Empty plaintext and non-stateful types cannot be encrypted.
    assert_eq!(state(&k, t, ""), Err(Error::MissingResultParam));
    assert_eq!(
        state(&k, ResultType::TemplateLong, "x"),
        Err(Error::UnsupportedResultType(17))
    );
}

// --------------------------------------------------------------- derive key

#[test]
fn derive_key_matches_independent_blake2b() {
    let k = key(NAME, PASSWORD, AlgorithmVersion::V3);
    let k512 =
        "+ReEtX5rzMxoi4LS2gMV/K6RdDnjD1Sp+MjdfdsN8ZP0GdmooKyM2QTpgsLLKZ7a5hjMxPzcxNRnCdcEj6Rd3g==";
    let t = ResultType::DeriveKey;
    assert_eq!(result(&k, t, Some("512")).unwrap(), k512);
    assert_eq!(result(&k, t, Some("0")).unwrap(), k512, "0 means 512");
    assert_eq!(
        result(&k, t, Some("abc")).unwrap(),
        k512,
        "strtol: non-numeric is 0"
    );
    assert_eq!(
        result(&k, t, Some("256")).unwrap(),
        "TCFYP7cKH8FQ8WYwILAlSfqAcz14K0yPGYV3sBvuyQA="
    );
    assert_eq!(
        result(&k, t, Some("128")).unwrap(),
        "avUxijvG6uFrayMepVqlXA=="
    );
    for bad in ["64", "520", "129", "-128", "99999999999999999999"] {
        assert!(
            matches!(result(&k, t, Some(bad)), Err(Error::InvalidResultParam(_))),
            "{bad}"
        );
    }
    assert_eq!(result(&k, t, None), Err(Error::MissingResultParam));
}

// ---------------------------------------------------------------- templates

#[test]
fn template_results_ignore_the_result_param() {
    let k = key(NAME, PASSWORD, AlgorithmVersion::V3);
    assert_eq!(
        result(&k, ResultType::TemplateLong, Some("whatever")).unwrap(),
        "Jejr5[RepuSosp"
    );
}

#[test]
fn empty_context_is_no_context() {
    let k = key(NAME, PASSWORD, AlgorithmVersion::V3);
    let answer = |context| {
        k.site_result(
            SITE,
            1,
            KeyPurpose::Recovery,
            context,
            ResultType::TemplatePhrase,
            None,
        )
        .unwrap()
        .to_string()
    };
    assert_eq!(answer(None), "xin diyjiqoja hubu");
    assert_eq!(answer(Some("")), "xin diyjiqoja hubu");
    assert_eq!(answer(Some("question")), "xogx tem cegyiva jab");
}

#[test]
fn totp_counter_uses_the_five_minute_window() {
    let k = key(NAME, PASSWORD, AlgorithmVersion::V3);
    let at = |counter| {
        k.site_result(
            SITE,
            counter,
            KeyPurpose::Authentication,
            None,
            ResultType::TemplatePin,
            None,
        )
        .unwrap()
        .to_string()
    };
    let window = || {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        now / 300 * 300
    };
    let before = window();
    let totp = at(COUNTER_TOTP);
    let after = window();
    assert!(totp == at(before) || totp == at(after));
}

// ---------------------------------------------------------- unicode & versions

#[test]
fn ascii_names_give_the_same_key_in_every_version() {
    let ids: Vec<_> = AlgorithmVersion::ALL
        .into_iter()
        .map(|v| key(NAME, PASSWORD, v).key_id())
        .collect();
    assert!(ids.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn multibyte_name_length_quirk_v2_vs_v3() {
    // v0-v2 count the full name in characters, v3 in bytes.
    let v2 = key("Jöhn ⛄", PASSWORD, AlgorithmVersion::V2).key_id();
    let v3 = key("Jöhn ⛄", PASSWORD, AlgorithmVersion::V3).key_id();
    let v0 = key("Jöhn ⛄", PASSWORD, AlgorithmVersion::V0).key_id();
    assert_ne!(v2, v3);
    assert_eq!(v0, v2);
}

#[test]
fn multibyte_site_name_quirk_v1_vs_v2() {
    // v0-v1 count the site name in characters, v2+ in bytes.  Use the same
    // master key bytes for both so only the site salt differs.
    let bytes = *key(NAME, PASSWORD, AlgorithmVersion::V3).as_bytes();
    let site = |v| {
        MasterKey::from_bytes(bytes, v)
            .site_result(
                "⛄.example",
                1,
                KeyPurpose::Authentication,
                None,
                ResultType::TemplateLong,
                None,
            )
            .unwrap()
            .to_string()
    };
    assert_ne!(site(AlgorithmVersion::V1), site(AlgorithmVersion::V2));
    assert_eq!(site(AlgorithmVersion::V2), site(AlgorithmVersion::V3));
    // ASCII site names agree.
    let ascii = |v| {
        MasterKey::from_bytes(bytes, v)
            .site_result(
                SITE,
                1,
                KeyPurpose::Authentication,
                None,
                ResultType::TemplateLong,
                None,
            )
            .unwrap()
            .to_string()
    };
    assert_eq!(ascii(AlgorithmVersion::V1), ascii(AlgorithmVersion::V3));
}

// ---------------------------------------------------------------- identicon

#[test]
fn identicon_matches_reference_algorithm() {
    let i = identicon(NAME, PASSWORD);
    assert_eq!(i.text(), "╚☻╯⛄");
    assert_eq!(i.color, IdenticonColor::Green);
    assert_eq!(i.encode(), "2:╚☻╯⛄");
    assert_ne!(identicon(NAME, "banana colored ducklinG"), i);
    // Total on any input; never panics.
    let _ = identicon("", "");
    let _ = identicon("⛄", "\u{0}");
}

// --------------------------------------------------------------- validation

#[test]
fn input_validation() {
    assert_eq!(
        MasterKey::derive("", PASSWORD, AlgorithmVersion::V3).unwrap_err(),
        Error::EmptyFullName
    );
    assert_eq!(
        MasterKey::derive(NAME, "", AlgorithmVersion::V3).unwrap_err(),
        Error::EmptyMasterPassword
    );
    let k = key(NAME, PASSWORD, AlgorithmVersion::V3);
    for t in ResultType::ALL {
        assert_eq!(
            k.site_result("", 1, KeyPurpose::Authentication, None, t, Some("x"))
                .unwrap_err(),
            Error::EmptySiteName
        );
    }
    assert_eq!(
        k.site_state(
            "",
            1,
            KeyPurpose::Authentication,
            None,
            ResultType::StatefulPersonal,
            "x"
        )
        .unwrap_err(),
        Error::EmptySiteName
    );
}

#[test]
fn every_result_type_and_counter_extreme_is_panic_free() {
    for version in AlgorithmVersion::ALL {
        let k = key(NAME, PASSWORD, version);
        for t in ResultType::ALL {
            for counter in [1, u32::MAX] {
                for purpose in [
                    KeyPurpose::Authentication,
                    KeyPurpose::Identification,
                    KeyPurpose::Recovery,
                ] {
                    let r = k.site_result("⛄", counter, purpose, Some("ctx"), t, Some("256"));
                    if t.is_template() {
                        let r = r.unwrap();
                        assert!(!r.is_empty() && r.is_ascii());
                    }
                }
            }
        }
    }
}

#[test]
fn debug_output_is_redacted() {
    let k = key(NAME, PASSWORD, AlgorithmVersion::V3);
    assert_eq!(format!("{k:?}"), "MasterKey(v3, <redacted>)");
}
