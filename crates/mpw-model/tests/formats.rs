mod common;

use common::*;
use mpw_model::{
    peek, write, AlgorithmVersion, Error, ExportMode, Format, ParseErrorKind, ResultType, Timestamp, User,
    UserFile,
};
use serde_json::Value;

fn load(name: &str) -> User {
    UserFile::parse(&fixture(name)).unwrap().load(&mut robert()).unwrap()
}

fn json(s: &str) -> Value {
    let mut v: Value = serde_json::from_str(s).unwrap();
    v["export"].as_object_mut().unwrap().remove("date");
    v
}

fn parse_err(bytes: &[u8]) -> ParseErrorKind {
    match UserFile::parse(bytes) {
        Err(Error::Parse(e)) => e.kind,
        Err(e) => panic!("unexpected error {e:?}"),
        Ok(_) => panic!("parsed"),
    }
}

// ------------------------------------------------------------------ fixtures

#[test]
fn flat1_redacted_fixture() {
    let summary = peek(&fixture("flat1-redacted.mpsites")).unwrap();
    assert_eq!(summary.format, Format::Flat);
    assert_eq!(summary.format_version, 1);
    assert!(summary.redacted);
    assert_eq!(summary.full_name, NAME);
    assert_eq!(summary.avatar, 3);
    assert_eq!(summary.key_id.as_ref().unwrap().as_str(), KEY_ID);
    assert_eq!(summary.identicon.as_ref().unwrap().encode(), "2:╚☻╯⛄");
    assert_eq!(summary.export_date, Timestamp::parse_rfc3339("2019-05-11T11:14:56Z"));
    assert_eq!(summary.site_count, 3);

    let mut keys = robert();
    let user = UserFile::parse(&fixture("flat1-redacted.mpsites")).unwrap().load(&mut keys).unwrap();
    assert_eq!(user.site_password(&mut keys, MPA).unwrap().as_str(), MPA_V3_LONG);
    assert_eq!(user.site_login(&mut keys, MPA).unwrap().as_str(), MPA_LOGIN);
    assert_eq!(user.site_password(&mut keys, "personal.example").unwrap().as_str(), PERSONAL_PW);
    assert_eq!(user.site_login(&mut keys, "personal.example").unwrap().as_str(), PERSONAL_LOGIN);
    let pin = user.site("pin.example").unwrap();
    assert_eq!((pin.counter, pin.result_type, pin.uses), (4, ResultType::TemplateBasic, 0));
    assert_eq!(user.site(MPA).unwrap().uses, 7);
}

#[test]
fn flat1_redacted_round_trips_byte_for_byte() {
    let user = load("flat1-redacted.mpsites");
    let out = write(&user, Format::Flat, ExportMode::Redacted).unwrap();
    assert_eq!(without_date(&out), without_date(&fixture_str("flat1-redacted.mpsites")));
}

#[test]
fn flat1_revealed_fixture_is_reencrypted_and_round_trips() {
    let mut keys = robert();
    let file = UserFile::parse(&fixture("flat1-revealed.mpsites")).unwrap();
    assert!(!file.summary().redacted);
    assert!(matches!(file.load_locked(), Err(Error::RevealedNeedsKey)));
    let user = file.load(&mut keys).unwrap();
    // Personal values are now encrypted state; the generated login was recognised.
    let personal = user.site("personal.example").unwrap();
    assert_eq!(personal.login_type(), Some(ResultType::StatefulPersonal));
    assert!(personal.has_password_state() && personal.has_login_state());
    assert_eq!(user.site(MPA).unwrap().login_type(), None);
    assert_eq!(user.site_password(&mut keys, "personal.example").unwrap().as_str(), PERSONAL_PW);
    assert_eq!(user.site_login(&mut keys, "personal.example").unwrap().as_str(), PERSONAL_LOGIN);

    let out = write(&user, Format::Flat, ExportMode::Revealed(&mut keys)).unwrap();
    assert_eq!(without_date(&out), without_date(&fixture_str("flat1-revealed.mpsites")));

    // And redacted, the same user is the redacted fixture's personal site.
    let redacted = write(&user, Format::Flat, ExportMode::Redacted).unwrap();
    assert!(redacted.contains(PERSONAL_STATE) && redacted.contains(PERSONAL_LOGIN_STATE));
    assert!(!redacted.contains(PERSONAL_PW));
}

#[test]
fn flat0_fixture() {
    let mut keys = robert();
    let file = UserFile::parse(&fixture("flat0.mpsites")).unwrap();
    assert_eq!(file.summary().format_version, 0);
    assert_eq!(file.summary().algorithm, AlgorithmVersion::V1);
    let user = file.load(&mut keys).unwrap();
    let mpa = user.site(MPA).unwrap();
    assert_eq!((mpa.algorithm(), mpa.counter, mpa.uses), (AlgorithmVersion::V0, 1, 5));
    // The site's own (v0) algorithm is used, not the user's.
    assert_eq!(user.site_password(&mut keys, MPA).unwrap().as_str(), MPA_V0_LONG);
    assert_eq!(user.site_password(&mut keys, "personal.example").unwrap().as_str(), PERSONAL_PW);
    assert_eq!(user.last_used, Timestamp::parse_rfc3339("2014-09-01T12:00:00Z").unwrap());
}

#[test]
fn json_c_redacted_fixture() {
    let mut keys = robert();
    let user = UserFile::parse(&fixture("c-redacted.mpjson")).unwrap().load(&mut keys).unwrap();
    assert!(user.preferences.mask_passwords && !user.preferences.biometric_lock);
    assert_eq!(user.preferences.autofill, None);
    let mpa = user.site(MPA).unwrap();
    assert_eq!(mpa.url.as_deref(), Some("https://masterpasswordapp.com"));
    // C's explicit 30 equals "use the user's (generated) login".
    assert_eq!(mpa.login_type(), None);
    assert_eq!(mpa.questions().count(), 3);
    assert_eq!(user.site_password(&mut keys, MPA).unwrap().as_str(), MPA_V3_LONG);
    assert_eq!(user.site_answer(&mut keys, MPA, "").unwrap().as_str(), MPA_ANSWER);
    assert_eq!(user.site_answer(&mut keys, MPA, "question").unwrap().as_str(), MPA_ANSWER_QUESTION);
    assert_eq!(user.site_answer(&mut keys, MPA, "mother").unwrap().as_str(), "Smith");
    assert_eq!(user.site_password(&mut keys, "personal.example").unwrap().as_str(), PERSONAL_PW);
    assert_eq!(user.site_login(&mut keys, "personal.example").unwrap().as_str(), PERSONAL_LOGIN);
    // A v0 site is computed with the v0 algorithm.
    let old = "old.masterpasswordapp.com";
    let v0 = user.site_password(&mut keys, old).unwrap();
    let mut upgraded = user.clone();
    upgraded.set_site_algorithm(&mut keys, old, AlgorithmVersion::V3).unwrap();
    assert_ne!(*v0, *upgraded.site_password(&mut keys, old).unwrap());
    assert!(matches!(user.site_password(&mut keys, "device.example"), Err(Error::NoStoredValue(_))));
}

#[test]
fn json_redacted_round_trip_keeps_unknown_members() {
    let user = load("c-redacted.mpjson");
    let out = write(&user, Format::Json, ExportMode::Redacted).unwrap();
    assert_eq!(json(&out), json(&fixture_str("c-redacted.mpjson")));
    // Our known members first, unknown ones kept in their original order after them.
    let text = out.as_str();
    for unknown in ["_ext_otherapp", "futurePref", "_ext_nested", "_ext_futureapp", "_ext_toplevel"] {
        assert!(text.contains(unknown), "{unknown} lost");
    }
    // Load → save → load is a fixed point.
    let again = UserFile::parse(out.as_bytes()).unwrap().load(&mut robert()).unwrap();
    assert_eq!(again, {
        let mut u = user.clone();
        u.authenticate(&mut robert()).unwrap();
        u
    });
}

#[test]
fn json_revealed_fixture_is_reencrypted() {
    let mut keys = robert();
    let user = load("c-revealed.mpjson");
    let mut u = user.clone();
    u.authenticate(&mut keys).unwrap();
    assert_eq!(u.site_password(&mut keys, "personal.example").unwrap().as_str(), PERSONAL_PW);
    assert_eq!(u.site_login(&mut keys, "personal.example").unwrap().as_str(), PERSONAL_LOGIN);
    assert_eq!(u.site_answer(&mut keys, MPA, "mother").unwrap().as_str(), "Smith");
    // Encryption is deterministic: the same state as the redacted C export.
    let redacted = write(&u, Format::Json, ExportMode::Redacted).unwrap();
    let v: Value = serde_json::from_str(&redacted).unwrap();
    assert_eq!(v["sites"]["personal.example"]["password"], PERSONAL_STATE);
    assert_eq!(v["sites"][MPA]["questions"]["mother"]["answer"], MOTHER_STATE);
    // Generated values from the revealed file were not stored.
    assert!(v["sites"][MPA].get("password").is_none());
    assert!(v["sites"][MPA]["questions"]["question"].get("answer").is_none());
}

#[test]
fn json_revealed_round_trip() {
    let mut keys = robert();
    let user = UserFile::parse(&fixture("c-revealed.mpjson")).unwrap().load(&mut keys).unwrap();
    let out = write(&user, Format::Json, ExportMode::Revealed(&mut keys)).unwrap();
    assert_eq!(json(&out), json(&fixture_str("c-revealed.mpjson")));
}

#[test]
fn swift_services_file_is_read_and_written_as_sites() {
    let user = load("swift-services.mpjson");
    assert_eq!(user.preferences.autofill, Some(true));
    assert_eq!(user.preferences.attacker.as_deref(), Some("private"));
    assert_eq!(user.site(MPA).unwrap().login_type(), None);
    let mut keys = robert();
    let mut u = user.clone();
    u.authenticate(&mut keys).unwrap();
    assert_eq!(u.site_login(&mut keys, MPA).unwrap().as_str(), MPA_LOGIN);
    let out = write(&user, Format::Json, ExportMode::Redacted).unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    assert!(v.get("services").is_none());
    // "Inherit" is written as the equivalent, universally readable 30 (generated name)...
    assert_eq!(v["sites"][MPA]["login_type"], 30);
    // ...and as 0 when the user has a personal login (which the C reader cannot represent anyway).
    let mut u2 = u.clone();
    u2.set_user_login_name(&mut keys, "rob").unwrap();
    let v: Value = serde_json::from_str(&write(&u2, Format::Json, ExportMode::Redacted).unwrap()).unwrap();
    assert_eq!(v["sites"][MPA]["login_type"], 0);
    assert_eq!(v["user"]["login_type"], 1056);
    let back = UserFile::parse(v.to_string().as_bytes()).unwrap().load(&mut keys).unwrap();
    assert_eq!(back.site_login(&mut keys, MPA).unwrap().as_str(), "rob");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["user"]["_ext_mpw"]["autofill"], true);
    assert!(v["user"]["_ext_mpw"].get("maskPasswords").is_none());
}

#[test]
fn both_sites_and_services_is_rejected() {
    let text = r#"{"user":{"full_name":"x","last_used":"2020-01-01T00:00:00Z"},"sites":{},"services":{}}"#;
    assert_eq!(parse_err(text.as_bytes()), ParseErrorKind::AmbiguousSites);
}

// --------------------------------------------------------------- conversions

#[test]
fn cross_format_conversions() {
    let mut keys = robert();
    let original = load("c-redacted.mpjson");

    // JSON → flat (redacted) → back: the flat format keeps sites, types,
    // counters, algorithms, usage and personal passwords.
    let flat = write(&original, Format::Flat, ExportMode::Redacted).unwrap();
    let back = UserFile::parse(flat.as_bytes()).unwrap().load(&mut keys).unwrap();
    assert_eq!(back.sites().count(), original.sites().count());
    for site in original.sites() {
        let b = back.site(site.name()).unwrap();
        assert_eq!((b.algorithm(), b.counter, b.result_type, b.uses), (site.algorithm(), site.counter, site.result_type, site.uses));
        assert_eq!(b.last_used, site.last_used);
    }
    for name in [MPA, "personal.example", "old.masterpasswordapp.com"] {
        assert_eq!(
            *back.site_password(&mut keys, name).unwrap(),
            *original_unlocked(&original, &mut keys).site_password(&mut keys, name).unwrap()
        );
    }
    assert_eq!(back.site_login(&mut keys, "personal.example").unwrap().as_str(), PERSONAL_LOGIN);

    // Flat (revealed) → JSON (revealed) → JSON (redacted) keeps the values.
    let revealed_flat = write(&back, Format::Flat, ExportMode::Revealed(&mut keys)).unwrap();
    let from_flat = UserFile::parse(revealed_flat.as_bytes()).unwrap().load(&mut keys).unwrap();
    let revealed_json = write(&from_flat, Format::Json, ExportMode::Revealed(&mut keys)).unwrap();
    let from_json = UserFile::parse(revealed_json.as_bytes()).unwrap().load(&mut keys).unwrap();
    assert_eq!(from_json.site_password(&mut keys, "personal.example").unwrap().as_str(), PERSONAL_PW);
    assert_eq!(from_json.site_login(&mut keys, "personal.example").unwrap().as_str(), PERSONAL_LOGIN);
    assert_eq!(from_json.site_login(&mut keys, MPA).unwrap().as_str(), MPA_LOGIN);
    assert_eq!(from_json.site(MPA).unwrap().login_type(), None);
}

fn original_unlocked(u: &User, keys: &mut mpw_model::UserKeys) -> User {
    let mut u = u.clone();
    u.authenticate(keys).unwrap();
    u
}

#[test]
fn redacted_and_revealed_round_trips_of_a_new_user() {
    let mut keys = robert();
    let mut user = User::new(NAME).unwrap();
    user.authenticate(&mut keys).unwrap();
    user.add_site("a.example").unwrap();
    user.add_site("b.example").unwrap().counter = 3;
    user.set_site_password(&mut keys, "b.example", ResultType::StatefulPersonal, "s3cret\u{e9}").unwrap();
    user.set_answer(&mut keys, "a.example", "pet", "Rex").unwrap();
    user.set_user_login_name(&mut keys, "rob").unwrap();
    for format in [Format::Json, Format::Flat] {
        for revealed in [false, true] {
            let out = if revealed {
                write(&user, format, ExportMode::Revealed(&mut keys)).unwrap()
            } else {
                write(&user, format, ExportMode::Redacted).unwrap()
            };
            assert_eq!(out.contains("s3cret"), revealed, "{format:?} {revealed}");
            let back = UserFile::parse(out.as_bytes()).unwrap().load(&mut keys).unwrap();
            assert_eq!(back.site_password(&mut keys, "b.example").unwrap().as_str(), "s3cret\u{e9}");
            assert_eq!(back.site("b.example").unwrap().counter, 3);
            assert_eq!(*back.site_password(&mut keys, "a.example").unwrap(), *user.site_password(&mut keys, "a.example").unwrap());
            if format == Format::Json {
                assert_eq!(back.site_answer(&mut keys, "a.example", "pet").unwrap().as_str(), "Rex");
                assert_eq!(back.user_login(&mut keys).unwrap().as_str(), "rob");
                assert_eq!(back.site_login(&mut keys, "a.example").unwrap().as_str(), "rob");
                if !revealed {
                    assert_eq!(back, user);
                }
            }
        }
    }
}

// --------------------------------------------------------- export semantics

#[test]
fn device_private_values_are_never_exported() {
    let mut keys = robert();
    let mut user = User::new(NAME).unwrap();
    user.authenticate(&mut keys).unwrap();
    user.add_site("bank.example").unwrap();
    user.set_site_password(&mut keys, "bank.example", ResultType::StatefulDevice, "device-only").unwrap();
    for format in [Format::Json, Format::Flat] {
        let redacted = write(&user, format, ExportMode::Redacted).unwrap();
        let revealed = write(&user, format, ExportMode::Revealed(&mut keys)).unwrap();
        assert!(!revealed.contains("device-only"), "{format:?}");
        let state = user.clone();
        // The encrypted state is not in the redacted export either.
        let back = UserFile::parse(redacted.as_bytes()).unwrap().load(&mut keys).unwrap();
        assert!(!back.site("bank.example").unwrap().has_password_state());
        assert!(state.site("bank.example").unwrap().has_password_state());
    }
}

#[test]
fn question_answers_export_by_question_type_not_site_type() {
    // Regression: the reference exported a question's state only if the *site*
    // type had the export-content feature.
    let mut keys = robert();
    let user = load("c-redacted.mpjson");
    assert_eq!(user.site(MPA).unwrap().result_type, ResultType::TemplateLong);
    let out = write(&user, Format::Json, ExportMode::Redacted).unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["sites"][MPA]["questions"]["mother"]["answer"], MOTHER_STATE);
    let _ = &mut keys;
}

#[test]
fn epoch_timestamps_are_written_readable_by_the_reference() {
    // The reference reader rejects a parsed time of 0 as "invalid".
    let mut user = User::new(NAME).unwrap();
    user.last_used = Timestamp::EPOCH;
    user.add_site("a.example").unwrap().last_used = Timestamp::from_unix(-5);
    let out = write(&user, Format::Json, ExportMode::Redacted).unwrap();
    assert!(out.contains("1970-01-01T00:00:01Z"));
    assert!(!out.contains("1970-01-01T00:00:00Z") && !out.contains("1969"));
}

#[test]
fn flat_refuses_unrepresentable_values() {
    let mut keys = robert();
    let mut user = User::new(NAME).unwrap();
    user.authenticate(&mut keys).unwrap();
    user.add_site(" leading.example").unwrap();
    assert!(matches!(write(&user, Format::Flat, ExportMode::Redacted), Err(Error::NotRepresentable { .. })));
    user.remove_site(" leading.example");
    user.add_site("ok.example").unwrap();
    user.set_site_password(&mut keys, "ok.example", ResultType::StatefulPersonal, "tab\there").unwrap();
    assert!(write(&user, Format::Flat, ExportMode::Redacted).is_ok());
    assert!(matches!(
        write(&user, Format::Flat, ExportMode::Revealed(&mut keys)),
        Err(Error::NotRepresentable { .. })
    ));
    // JSON has no such limits.
    let json_out = write(&user, Format::Json, ExportMode::Revealed(&mut keys)).unwrap();
    let back = UserFile::parse(json_out.as_bytes()).unwrap().load(&mut keys).unwrap();
    assert_eq!(back.site_password(&mut keys, "ok.example").unwrap().as_str(), "tab\there");
}

#[test]
fn revealed_export_needs_the_unlocking_keys() {
    let user = load("c-redacted.mpjson");
    let mut other = robert_other();
    assert!(matches!(
        write(&user, Format::Json, ExportMode::Revealed(&mut other)),
        Err(Error::NotAuthenticated)
    ));
}

// ------------------------------------------------------------- tolerant input

#[test]
fn flat_tolerates_crlf_bom_and_a_missing_final_newline() {
    let text = fixture_str("flat1-redacted.mpsites");
    let crlf = format!("\u{feff}{}", text.replace('\n', "\r\n"));
    let crlf = crlf.trim_end_matches("\r\n");
    let user = UserFile::parse(crlf.as_bytes()).unwrap().load_locked().unwrap();
    // Regression: the reference drops the last line if it has no newline.
    assert!(user.site("pin.example").is_some());
    assert_eq!(user.sites().count(), 3);
    assert_eq!(user.full_name(), NAME);
    assert_eq!(user.key_id().unwrap().as_str(), KEY_ID);
}

#[test]
fn json_tolerates_bom_and_floats_written_with_g() {
    let text = r#"{"export":{"redacted":true},"user":{"full_name":"Robert Lee Mitchell","algorithm":3.0,"last_used":"2020-01-01T00:00:00Z"},
        "sites":{"a":{"counter":4.0,"type":17,"uses":1e2,"last_used":"2020-01-01T00:00:00Z"}}}"#;
    let user = UserFile::parse(format!("\u{feff}{text}").as_bytes()).unwrap().load_locked().unwrap();
    assert_eq!(user.site("a").unwrap().counter, 4);
    assert_eq!(user.site("a").unwrap().uses, 100);
}

#[test]
fn peek_does_not_need_a_key() {
    for f in ["flat0.mpsites", "flat1-redacted.mpsites", "flat1-revealed.mpsites", "c-redacted.mpjson", "c-revealed.mpjson"] {
        let s = peek(&fixture(f)).unwrap();
        assert_eq!(s.full_name, NAME, "{f}");
        assert_eq!(s.key_id.unwrap().as_str(), KEY_ID, "{f}");
    }
    assert!(!peek(&fixture("c-revealed.mpjson")).unwrap().redacted);
    assert!(peek(&fixture("c-redacted.mpjson")).unwrap().preferences.mask_passwords);
}

// ------------------------------------------------------------ hostile input

#[test]
fn rejects_malformed_input_with_typed_errors() {
    assert_eq!(parse_err(b""), ParseErrorKind::UnknownFormat);
    assert_eq!(parse_err(b"hello"), ParseErrorKind::UnknownFormat);
    assert_eq!(parse_err(b"[1,2]"), ParseErrorKind::UnknownFormat);
    assert_eq!(parse_err(b"# x\n##\n# Full Name: a\n# Format: \xff\n##\n"), ParseErrorKind::InvalidUtf8 { offset: 32 });
    assert!(matches!(parse_err(b"{\"user\": "), ParseErrorKind::Json(_)));
    assert_eq!(parse_err(b"{}"), ParseErrorKind::Missing);
    assert_eq!(parse_err(br#"{"user":{"full_name":"a\nb"}}"#), ParseErrorKind::InvalidValue);
    assert_eq!(parse_err(br#"{"user":{"full_name":"a","algorithm":9}}"#), ParseErrorKind::InvalidAlgorithm);
    assert_eq!(parse_err(br#"{"user":{"full_name":"a","key_id":"zz"}}"#), ParseErrorKind::InvalidValue);
    assert_eq!(parse_err(br#"{"user":{"full_name":"a","default_type":99}}"#), ParseErrorKind::InvalidResultType(99));
    assert_eq!(parse_err(br#"{"user":{"full_name":"a","last_used":"yesterday"}}"#), ParseErrorKind::InvalidValue);
    assert_eq!(parse_err(br#"{"export":{"redacted":"no"},"user":{"full_name":"a"}}"#), ParseErrorKind::InvalidValue);
    for counter in ["-1", "4294967296", "1.5", "\"1\"", "1e300"] {
        let text = format!(r#"{{"user":{{"full_name":"a"}},"sites":{{"s":{{"counter":{counter}}}}}}}"#);
        assert_eq!(parse_err(text.as_bytes()), ParseErrorKind::InvalidValue, "{counter}");
    }
    assert_eq!(parse_err(br#"{"user":{"full_name":"a"},"sites":{"":{}}}"#), ParseErrorKind::InvalidValue);
    assert_eq!(parse_err(br#"{"user":{"full_name":"a"},"sites":{"s":[]}}"#), ParseErrorKind::InvalidValue);

    let flat = |body: &str| format!("##\n# Full Name: a\n# Format: 1\n##\n{body}");
    assert_eq!(parse_err(flat("2019-01-01T00:00:00Z 1 17:3 \t x\t\n").as_bytes()), ParseErrorKind::InvalidValue);
    assert_eq!(parse_err(flat("2019-01-01T00:00:00Z 1 17:3:1:9 \t x\t\n").as_bytes()), ParseErrorKind::InvalidValue);
    assert_eq!(parse_err(flat("2019-01-01T00:00:00Z x 17:3:1 \t x\t\n").as_bytes()), ParseErrorKind::InvalidValue);
    assert_eq!(parse_err(flat("2019-13-01T00:00:00Z 1 17:3:1 \t x\t\n").as_bytes()), ParseErrorKind::InvalidValue);
    assert_eq!(parse_err(flat("2019-01-01T00:00:00Z 1 99:3:1 \t x\t\n").as_bytes()), ParseErrorKind::InvalidResultType(99));
    assert_eq!(parse_err(flat("2019-01-01T00:00:00Z 1 17:4:1 \t x\t\n").as_bytes()), ParseErrorKind::InvalidAlgorithm);
    assert_eq!(parse_err(flat("2019-01-01T00:00:00Z 1 17:3:1 \t \t\n").as_bytes()), ParseErrorKind::InvalidValue);
    assert_eq!(parse_err(b"##\n# Format: 1\n##\n"), ParseErrorKind::Missing);
    assert_eq!(parse_err(b"##\n# Full Name: a\n# Format: 2\n##\n"), ParseErrorKind::UnsupportedFlatFormat(2));
    assert_eq!(parse_err(b"# just a comment\n"), ParseErrorKind::Missing);
}

#[test]
fn parse_errors_carry_location_but_never_values() {
    let secret = "hunter2-very-secret";
    let text = format!(
        "##\n# Full Name: a\n# Format: 1\n# Passwords: VISIBLE\n##\n2019-01-01T00:00:00Z 1 17:3:1 \t x\t{secret}\n2019-01-01T00:00:00Z 1 17:3:x \t y\t{secret}\n"
    );
    let err = UserFile::parse(text.as_bytes()).err().unwrap();
    let Error::Parse(p) = &err else { panic!("{err:?}") };
    assert_eq!(p.line, Some(7));
    assert!(p.location.contains("counter"));
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains(secret), "{shown}");
    assert!(shown.contains("line 7"), "{shown}");

    let json = format!(r#"{{"user":{{"full_name":"a"}},"export":{{"redacted":false}},"sites":{{"s":{{"password":"{secret}","uses":-1}}}}}}"#);
    let err = UserFile::parse(json.as_bytes()).err().unwrap();
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains(secret) && shown.contains("uses"), "{shown}");
}

#[test]
fn rejects_oversized_and_absurd_input() {
    let big = vec![b'#'; mpw_model::limits::MAX_FILE_SIZE + 1];
    assert!(matches!(parse_err(&big), ParseErrorKind::TooLarge { .. }));

    let mut many = String::from(r#"{"user":{"full_name":"a"},"sites":{"#);
    for i in 0..=mpw_model::limits::MAX_SITES {
        many.push_str(&format!("\"s{i}\":{{}},"));
    }
    many.pop();
    many.push_str("}}");
    assert!(matches!(parse_err(many.as_bytes()), ParseErrorKind::TooMany { what: "sites", .. }));

    let long = "x".repeat(mpw_model::limits::MAX_VALUE_LEN + 1);
    let text = format!(r#"{{"user":{{"full_name":"a"}},"sites":{{"s":{{"password":"{long}"}}}}}}"#);
    assert!(matches!(parse_err(text.as_bytes()), ParseErrorKind::TooLong { .. }));

    // Deep nesting in an unknown member: bounded recursion, typed error, no stack overflow.
    let deep = format!(r#"{{"user":{{"full_name":"a"}},"_ext_x":{}{}}}"#, "[".repeat(100_000), "]".repeat(100_000));
    assert!(matches!(parse_err(deep.as_bytes()), ParseErrorKind::Json(_)));
}

#[test]
fn mutated_inputs_never_panic() {
    let seeds: Vec<Vec<u8>> = ["flat0.mpsites", "flat1-redacted.mpsites", "flat1-revealed.mpsites", "c-redacted.mpjson", "c-revealed.mpjson"]
        .iter()
        .map(|f| fixture(f))
        .collect();
    let mut rng = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let mut keys = robert();
    let specials = [b'\t', b'\n', b'\r', b':', b'#', b'{', b'}', b'"', b'0', b'9', b' ', 0xff, 0x00];
    for i in 0..4000 {
        let mut data = seeds[i % seeds.len()].clone();
        for _ in 0..(1 + next() % 4) {
            if data.is_empty() {
                break;
            }
            let at = (next() as usize) % data.len();
            match next() % 4 {
                0 => data[at] = specials[(next() as usize) % specials.len()],
                1 => data.truncate(at),
                2 => {
                    data.remove(at);
                }
                _ => data.insert(at, specials[(next() as usize) % specials.len()]),
            }
        }
        if let Ok(file) = UserFile::parse(&data) {
            let _ = file.load_locked();
            if let Ok(user) = file.load(&mut keys) {
                let _ = write(&user, Format::Json, ExportMode::Redacted);
                let _ = write(&user, Format::Flat, ExportMode::Revealed(&mut keys));
            }
        }
    }
}
