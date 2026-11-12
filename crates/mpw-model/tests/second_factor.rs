//! The opt-in second factor (smart card / recovery code).
mod common;

use common::*;
use mpw_model::second_factor::{MAX_SLOTS, SECOND_SECRET_LEN};
use mpw_model::{
    effective_master_password, merge, peek, write, Authentication, Error, ExportMode, Format, RecoveryCode,
    RecoveryCodeError, ResultType, SecondFactorStatus, SecondSecret, Slot, SlotKind, User, UserFile, UserKeys,
};
use serde_json::Value;

/// The pinned vector: secret bytes 00 01 .. 13.
const PINNED_CODE: &str = "000G4-0R40M-30E20-9185G-R38E1-W8124-GKQ4P";
/// Key ID of NAME with master password "banana colored duckling 000G4-...-GKQ4P".
const PINNED_KEY_ID: &str = "86738BF1C8F24122D467952B4DEC8C8A5DDE4A6054340FABCB935D58C1123EF8";

fn pinned() -> SecondSecret {
    SecondSecret::from_bytes(&(0u8..20).collect::<Vec<_>>()).unwrap()
}

fn other_secret() -> SecondSecret {
    SecondSecret::from_bytes(&[0xA5; SECOND_SECRET_LEN]).unwrap()
}

/// Test double for a card: XOR with the card number.
fn wrap(secret: &SecondSecret, card: u8) -> Slot {
    let wrapped = secret.as_bytes().iter().map(|b| b ^ card).collect();
    Slot::new(SlotKind::SmartCard, &format!("Card {card}"), &format!("{card:02x}").repeat(32), "test-xor", wrapped).unwrap()
}

fn unwrap(slot: &Slot, card: u8) -> SecondSecret {
    SecondSecret::from_bytes(&slot.wrapped().iter().map(|b| b ^ card).collect::<Vec<_>>()).unwrap()
}

/// A user with stored values of every kind, unlocked with NAME/PASSWORD.
fn rich_user() -> (User, UserKeys) {
    let mut keys = robert();
    let mut user = User::new(NAME).unwrap();
    user.authenticate(&mut keys).unwrap();
    user.add_site(MPA).unwrap();
    user.add_site("personal.example").unwrap();
    user.set_site_password(&mut keys, "personal.example", ResultType::StatefulPersonal, PERSONAL_PW).unwrap();
    user.set_site_login_name(&mut keys, "personal.example", PERSONAL_LOGIN).unwrap();
    user.set_answer(&mut keys, MPA, "mother", "Smith").unwrap();
    user.set_user_login_name(&mut keys, "rob").unwrap();
    (user, keys)
}

fn assert_values(user: &User, keys: &mut UserKeys) {
    assert_eq!(user.site_password(keys, "personal.example").unwrap().as_str(), PERSONAL_PW);
    assert_eq!(user.site_login(keys, "personal.example").unwrap().as_str(), PERSONAL_LOGIN);
    assert_eq!(user.site_answer(keys, MPA, "mother").unwrap().as_str(), "Smith");
    assert_eq!(user.user_login(keys).unwrap().as_str(), "rob");
}

fn enabled() -> (User, UserKeys) {
    let (mut user, _) = rich_user();
    let keys = user.enable_second_factor(PASSWORD, &pinned(), vec![wrap(&pinned(), 7)], RecoveryCode::NotConfirmed).unwrap();
    (user, keys)
}

// ------------------------------------------------------------ recovery code

#[test]
fn recovery_code_format() {
    let code = pinned().recovery_code();
    assert_eq!(code.as_str(), PINNED_CODE);
    for _ in 0..50 {
        let s = SecondSecret::generate().unwrap();
        let c = s.recovery_code();
        let groups: Vec<_> = c.split('-').collect();
        assert_eq!(groups.len(), 7);
        assert!(groups.iter().all(|g| g.len() == 5));
        assert!(c.chars().all(|ch| ch == '-' || "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(ch)), "{}", *c);
        assert_eq!(SecondSecret::parse_recovery_code(&c).unwrap(), s);
    }
    assert_ne!(SecondSecret::generate().unwrap(), SecondSecret::generate().unwrap());
    assert_eq!(SecondSecret::from_bytes(&[0xff; 20]).unwrap().recovery_code().as_str(), "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZF8R");
}

#[test]
fn recovery_code_parsing_normalises() {
    let p = |s: &str| SecondSecret::parse_recovery_code(s);
    let canonical = PINNED_CODE;
    for variant in [
        canonical.to_owned(),
        canonical.to_lowercase(),
        canonical.replace('-', ""),
        format!("  {}\n", canonical.replace('-', " - ")),
        canonical.replace('0', "O").replace('1', "l"),
        canonical.replace('0', "o").replace('1', "I"),
        "000G40R40M30E209185GR38E1W8124GKQ4P".chars().map(|c| format!("{c}-")).collect(),
    ] {
        assert_eq!(p(&variant).unwrap(), pinned(), "{variant:?}");
    }
}

#[test]
fn recovery_code_rejects_mistakes_before_any_derivation() {
    let p = |s: &str| SecondSecret::parse_recovery_code(s).unwrap_err();
    assert_eq!(p(""), RecoveryCodeError::WrongLength { found: 0 });
    assert_eq!(p(&PINNED_CODE[..40]), RecoveryCodeError::WrongLength { found: 34 });
    assert_eq!(p(&format!("{PINNED_CODE}A")), RecoveryCodeError::WrongLength { found: 36 });
    assert_eq!(p(&PINNED_CODE.replacen('0', "U", 1)), RecoveryCodeError::InvalidCharacter { position: 1 });
    assert_eq!(p(&PINNED_CODE.replace("-GKQ4P", "-GKQ4!")), RecoveryCodeError::InvalidCharacter { position: 35 });
    // Every single-character substitution and adjacent transposition is caught.
    let chars: Vec<char> = PINNED_CODE.replace('-', "").chars().collect();
    for i in 0..chars.len() {
        let mut c = chars.clone();
        c[i] = if c[i] == 'A' { 'B' } else { 'A' };
        let s: String = c.iter().collect();
        assert!(SecondSecret::parse_recovery_code(&s).is_err(), "substitution at {i}");
        if i + 1 < chars.len() && chars[i] != chars[i + 1] {
            let mut c = chars.clone();
            c.swap(i, i + 1);
            let s: String = c.iter().collect();
            assert_eq!(SecondSecret::parse_recovery_code(&s).unwrap_err(), RecoveryCodeError::ChecksumMismatch);
        }
    }
    // Errors and Debug output never contain the code.
    let err: Error = p(&PINNED_CODE.replace("GKQ4P", "GKQ4Q")).into();
    let shown = format!("{err} {err:?} {:?}", pinned());
    assert!(!shown.contains("GKQ4") && !shown.contains("000G4"), "{shown}");
    assert!(SecondSecret::from_bytes(&[1; 19]).is_err());
}

#[test]
fn effective_master_password_is_pinned() {
    let effective = effective_master_password(PASSWORD, &pinned());
    assert_eq!(effective.as_str(), format!("{PASSWORD} {PINNED_CODE}"));
    // Any Master Password app given that literal string derives the same key.
    let mut literal = UserKeys::from_password(NAME, &format!("banana colored duckling {PINNED_CODE}"));
    let mut ours = UserKeys::from_password_and_secret(NAME, PASSWORD, &pinned());
    let v3 = mpw_model::AlgorithmVersion::V3;
    assert_eq!(literal.key(v3).unwrap().key_id().as_str(), PINNED_KEY_ID);
    assert_eq!(*ours.key_bytes(v3).unwrap(), *literal.key_bytes(v3).unwrap());
    // The identicon is that of the typed password.
    assert_eq!(ours.identicon(), UserKeys::from_password(NAME, PASSWORD).identicon());
}

// --------------------------------------------------------- enable / unlock

#[test]
fn enable_unlock_and_disable() {
    let (mut user, _) = rich_user();
    let generated = user.site_password(&mut robert_authenticated(&mut user.clone()), MPA).unwrap();
    let mut keys = user
        .enable_second_factor(PASSWORD, &pinned(), vec![wrap(&pinned(), 7)], RecoveryCode::NotConfirmed)
        .unwrap();
    assert_eq!(user.key_id().unwrap().as_str(), PINNED_KEY_ID);
    assert!(user.is_unlocked_by(&keys));
    assert_values(&user, &mut keys);
    assert_ne!(*user.site_password(&mut keys, MPA).unwrap(), *generated, "every generated password changes");
    let sf = user.second_factor_status().second_factor().unwrap();
    assert_eq!(sf.slots().len(), 1);

    // Unlock: the card's slot plus the typed password.
    let slot = &sf.slots()[0];
    assert_eq!(slot.label(), "Card 7");
    let secret = unwrap(slot, 7);
    assert!(sf.matches(&secret));
    let mut fresh = user.clone();
    let mut k = fresh.second_factor_keys(PASSWORD, &secret).unwrap();
    assert_eq!(fresh.authenticate(&mut k).unwrap(), Authentication::Verified);
    // Or the recovery code from paper.
    let typed = SecondSecret::parse_recovery_code(&PINNED_CODE.to_lowercase()).unwrap();
    assert!(user.clone().authenticate(&mut user.second_factor_keys(PASSWORD, &typed).unwrap()).is_ok());
    // The password alone, a wrong password, or the wrong card/code fail.
    assert!(matches!(user.clone().authenticate(&mut robert()), Err(Error::WrongMasterPassword)));
    let mut wrong_pw = user.second_factor_keys("not it", &secret).unwrap();
    assert!(matches!(user.clone().authenticate(&mut wrong_pw), Err(Error::WrongMasterPassword)));
    assert!(matches!(user.second_factor_keys(PASSWORD, &unwrap(slot, 8)), Err(Error::SecondSecretMismatch)));
    let mut bypass = UserKeys::from_password_and_secret(NAME, PASSWORD, &other_secret());
    assert!(matches!(user.clone().authenticate(&mut bypass), Err(Error::WrongMasterPassword)));

    // The plain operation is refused for a second-factor user.
    let before = user.clone();
    assert!(matches!(user.change_master_password(&mut keys, &mut robert()), Err(Error::SecondFactorEnabled)));
    assert!(matches!(
        user.enable_second_factor(PASSWORD, &other_secret(), vec![], RecoveryCode::ConfirmedSaved),
        Err(Error::SecondFactorEnabled)
    ));
    assert_eq!(user, before);

    // Disable: back to the original key ID; stored values intact.
    assert!(matches!(user.disable_second_factor(PASSWORD, &other_secret()), Err(Error::SecondSecretMismatch)));
    assert!(matches!(user.disable_second_factor("not it", &pinned()), Err(Error::WrongMasterPassword)));
    assert_eq!(user, before);
    let mut plain = user.disable_second_factor(PASSWORD, &pinned()).unwrap();
    assert_eq!(user.key_id().unwrap().as_str(), KEY_ID);
    assert_eq!(*user.second_factor_status(), SecondFactorStatus::Disabled);
    assert_values(&user, &mut plain);
    assert_eq!(*user.site_password(&mut plain, MPA).unwrap(), *generated);
    let v: Value = serde_json::from_str(&write(&user, Format::Json, ExportMode::Redacted).unwrap()).unwrap();
    assert!(v["user"]["_ext_mpw"].get("second_factor").is_none());
}

fn robert_authenticated(user: &mut User) -> UserKeys {
    let mut k = robert();
    user.authenticate(&mut k).unwrap();
    k
}

#[test]
fn enable_requires_slots_or_a_saved_recovery_code_and_the_right_password() {
    let (mut user, _) = rich_user();
    let before = user.clone();
    assert!(matches!(
        user.enable_second_factor(PASSWORD, &pinned(), vec![], RecoveryCode::NotConfirmed),
        Err(Error::RecoveryCodeNotConfirmed)
    ));
    assert!(matches!(
        user.enable_second_factor(OTHER_PASSWORD, &pinned(), vec![wrap(&pinned(), 1)], RecoveryCode::NotConfirmed),
        Err(Error::WrongMasterPassword)
    ));
    let dup = wrap(&pinned(), 1);
    assert!(matches!(
        user.enable_second_factor(PASSWORD, &pinned(), vec![dup.clone(), dup], RecoveryCode::NotConfirmed),
        Err(Error::SlotExists)
    ));
    assert_eq!(user, before);
    // Recovery-code-only mode, explicitly.
    let mut keys = user.enable_second_factor(PASSWORD, &pinned(), vec![], RecoveryCode::ConfirmedSaved).unwrap();
    assert!(user.second_factor_status().second_factor().unwrap().slots().is_empty());
    assert_values(&user, &mut keys);
}

#[test]
fn enable_is_all_or_nothing() {
    let text = format!(
        r#"{{"user":{{"full_name":"{NAME}","key_id":"{KEY_ID}","last_used":"2020-01-01T00:00:00Z"}},
            "sites":{{"broken.example":{{"type":1056,"password":"AAAAAAAAAAAAAAAAAAAAAA==","last_used":"2020-01-01T00:00:00Z"}}}}}}"#
    );
    let mut user = UserFile::parse(text.as_bytes()).unwrap().load(&mut robert()).unwrap();
    let before = user.clone();
    let err = user.enable_second_factor(PASSWORD, &pinned(), vec![wrap(&pinned(), 1)], RecoveryCode::NotConfirmed);
    assert!(matches!(err, Err(Error::ReencryptFailed { site: Some(ref s), .. }) if s == "broken.example"), "{err:?}");
    assert_eq!(user, before);
}

#[test]
fn change_password_and_rotate_keep_values() {
    let (mut user, _) = enabled();
    let slots_before = user.second_factor_status().clone();
    assert!(matches!(
        user.change_master_password_with_second_factor("wrong", "new password", &pinned()),
        Err(Error::WrongMasterPassword)
    ));
    let mut keys = user.change_master_password_with_second_factor(PASSWORD, "new password", &pinned()).unwrap();
    assert_values(&user, &mut keys);
    assert_eq!(*user.second_factor_status(), slots_before);
    assert!(user.clone().authenticate(&mut user.second_factor_keys(PASSWORD, &pinned()).unwrap()).is_err());
    assert!(user.clone().authenticate(&mut user.second_factor_keys("new password", &pinned()).unwrap()).is_ok());

    // Rotate: a new code; old slots are dropped, new ones required.
    let new_secret = other_secret();
    let before = user.clone();
    assert!(matches!(
        user.rotate_second_secret("new password", &pinned(), &new_secret, vec![], RecoveryCode::NotConfirmed),
        Err(Error::RecoveryCodeNotConfirmed)
    ));
    assert!(matches!(
        user.rotate_second_secret("new password", &new_secret, &pinned(), vec![wrap(&pinned(), 2)], RecoveryCode::NotConfirmed),
        Err(Error::SecondSecretMismatch)
    ));
    assert_eq!(user, before);
    let mut keys = user
        .rotate_second_secret("new password", &pinned(), &new_secret, vec![wrap(&new_secret, 3), wrap(&new_secret, 4)], RecoveryCode::NotConfirmed)
        .unwrap();
    assert_values(&user, &mut keys);
    let sf = user.second_factor_status().second_factor().unwrap();
    assert_eq!(sf.slots().len(), 2);
    assert!(sf.matches(&new_secret) && !sf.matches(&pinned()));
    assert!(matches!(user.second_factor_keys("new password", &pinned()), Err(Error::SecondSecretMismatch)));
}

#[test]
fn slot_management() {
    let (mut user, keys) = enabled();
    let first = user.second_factor_status().second_factor().unwrap().slots()[0].id().to_owned();
    assert!(matches!(user.add_second_factor_slot(&keys, wrap(&pinned(), 7)), Err(Error::SlotExists)));
    user.add_second_factor_slot(&keys, wrap(&pinned(), 9)).unwrap();
    user.relabel_second_factor_slot(&keys, &first, "Work CAC").unwrap();
    assert!(matches!(user.relabel_second_factor_slot(&keys, &first, "bad\nlabel"), Err(Error::InvalidSlot(_))));
    assert!(matches!(user.relabel_second_factor_slot(&keys, "nope", "x"), Err(Error::NoSuchSlot)));
    let sf = user.second_factor_status().second_factor().unwrap();
    assert_eq!(sf.slot(&first).unwrap().label(), "Work CAC");
    let second = sf.slots()[1].id().to_owned();

    // Slot changes need the unlocking keys but no re-key.
    let key_id = user.key_id().cloned();
    assert!(matches!(user.add_second_factor_slot(&robert(), wrap(&pinned(), 11)), Err(Error::NotAuthenticated)));
    user.remove_second_factor_slot(&keys, &first, RecoveryCode::NotConfirmed).unwrap();
    assert!(matches!(
        user.remove_second_factor_slot(&keys, &second, RecoveryCode::NotConfirmed),
        Err(Error::RecoveryCodeNotConfirmed)
    ));
    user.remove_second_factor_slot(&keys, &second, RecoveryCode::ConfirmedSaved).unwrap();
    assert!(user.second_factor_status().second_factor().unwrap().slots().is_empty());
    assert_eq!(user.key_id().cloned(), key_id);
    assert!(user.second_factor_status().is_enabled());

    // Slot validation.
    let fp = "ab".repeat(32);
    assert!(Slot::new(SlotKind::SmartCard, "x", "abcd", "alg", vec![1]).is_err());
    assert!(Slot::new(SlotKind::SmartCard, "x", &fp, "alg", vec![]).is_err());
    assert!(Slot::new(SlotKind::SmartCard, "x", &fp, "alg", vec![0; 16 * 1024 + 1]).is_err());
    assert!(Slot::new(SlotKind::SmartCard, "x", &fp, "", vec![1]).is_err());
    assert!(Slot::new(SlotKind::SmartCard, "a\u{7}", &fp, "alg", vec![1]).is_err());
    let s = Slot::new(SlotKind::Other("fido2".into()), "Key", &fp, "alg", vec![1]).unwrap();
    assert_eq!(s.fingerprint(), fp.to_uppercase());
    let mut plain = User::new(NAME).unwrap();
    let mut pk = robert();
    plain.authenticate(&mut pk).unwrap();
    assert!(matches!(plain.add_second_factor_slot(&pk, s), Err(Error::SecondFactorNotEnabled)));
}

// ------------------------------------------------------------------ formats

#[test]
fn json_round_trip_and_peek() {
    let (mut user, keys) = enabled();
    user.add_second_factor_slot(&keys, Slot::new(SlotKind::Other("fido2".into()), "Key", &"cd".repeat(32), "es256", vec![9; 40]).unwrap()).unwrap();
    user.preferences.mask_passwords = true;
    let out = write(&user, Format::Json, ExportMode::Redacted).unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    let member = &v["user"]["_ext_mpw"]["second_factor"];
    assert_eq!(member["version"], 1);
    assert_eq!(member["slots"][0]["kind"], "smart_card");
    assert_eq!(member["slots"][1]["kind"], "fido2");
    assert_eq!(v["user"]["_ext_mpw"]["maskPasswords"], true);
    assert_eq!(v["user"]["key_id"], PINNED_KEY_ID);
    for forbidden in ["subject", "certificate", "CN="] {
        assert!(!out.contains(forbidden));
    }

    let summary = peek(out.as_bytes()).unwrap();
    assert_eq!(summary.second_factor, *user.second_factor_status());
    let back = UserFile::parse(out.as_bytes()).unwrap().load_locked().unwrap();
    // (A loaded user also remembers the original `_ext_mpw`, so compare the parts.)
    assert_eq!(back.second_factor_status(), user.second_factor_status());
    assert_eq!(back.preferences, user.preferences);
    assert_eq!(back.key_id(), user.key_id());
    assert_eq!(without_date(&write(&back, Format::Json, ExportMode::Redacted).unwrap()), without_date(&out));

    // A revealed export carries the slots too, and stays a revealed export.
    let mut k = user.second_factor_keys(PASSWORD, &pinned()).unwrap();
    user.clone().authenticate(&mut k).unwrap();
    let revealed = write(&user, Format::Json, ExportMode::Revealed(&mut k)).unwrap();
    assert!(revealed.contains(PERSONAL_PW));
    let rv: Value = serde_json::from_str(&revealed).unwrap();
    assert_eq!(rv["user"]["_ext_mpw"]["second_factor"], *member);
    let reloaded = UserFile::parse(revealed.as_bytes()).unwrap().load(&mut k).unwrap();
    assert_eq!(reloaded.second_factor_status(), user.second_factor_status());
    assert_values(&reloaded, &mut k);
}

#[test]
fn unknown_or_damaged_members_fail_safe_and_are_kept() {
    let (user, keys) = enabled();
    let out = write(&user, Format::Json, ExportMode::Redacted).unwrap();
    let mut v: Value = serde_json::from_str(&out).unwrap();
    // A future version: kept verbatim, user still unlockable with the recovery code.
    v["user"]["_ext_mpw"]["second_factor"]["version"] = Value::from(2);
    v["user"]["_ext_mpw"]["second_factor"]["future"] = Value::from("x");
    let text = v.to_string();
    let mut future = UserFile::parse(text.as_bytes()).unwrap().load_locked().unwrap();
    assert_eq!(*future.second_factor_status(), SecondFactorStatus::Unreadable);
    assert!(peek(text.as_bytes()).unwrap().second_factor.is_enabled());
    let mut k = future.second_factor_keys(PASSWORD, &pinned()).unwrap();
    future.authenticate(&mut k).unwrap();
    assert_values(&future, &mut k);
    assert!(matches!(future.add_second_factor_slot(&k, wrap(&pinned(), 5)), Err(Error::SecondFactorUnreadable)));
    let again: Value = serde_json::from_str(&write(&future, Format::Json, ExportMode::Redacted).unwrap()).unwrap();
    assert_eq!(again["user"]["_ext_mpw"]["second_factor"], v["user"]["_ext_mpw"]["second_factor"]);
    let _ = keys;
    future.disable_second_factor(PASSWORD, &pinned()).unwrap();
    let off: Value = serde_json::from_str(&write(&future, Format::Json, ExportMode::Redacted).unwrap()).unwrap();
    assert!(off["user"]["_ext_mpw"].get("second_factor").is_none());
}

#[test]
fn hostile_slot_data_never_panics() {
    let (user, _) = enabled();
    let base: Value = serde_json::from_str(&write(&user, Format::Json, ExportMode::Redacted).unwrap()).unwrap();
    let slot = base["user"]["_ext_mpw"]["second_factor"]["slots"][0].clone();
    let mutate = |f: &dyn Fn(&mut Value)| {
        let mut v = base.clone();
        f(&mut v["user"]["_ext_mpw"]["second_factor"]);
        UserFile::parse(v.to_string().as_bytes()).unwrap().load_locked().unwrap().second_factor_status().clone()
    };
    let many: Vec<Value> = (0..=MAX_SLOTS)
        .map(|i| {
            let mut s = slot.clone();
            s["id"] = Value::from(format!("id{i}"));
            s
        })
        .collect();
    type Mutation = Box<dyn Fn(&mut Value)>;
    let cases: Vec<Mutation> = vec![
        Box::new(|m| m["slots"] = Value::from("nope")),
        Box::new(move |m| m["slots"] = Value::Array(many.clone())),
        Box::new(|m| m["slots"][0]["wrapped"] = Value::from("!!!not base64")),
        Box::new(|m| m["slots"][0]["wrapped"] = Value::from("A".repeat(100_000))),
        Box::new(|m| m["slots"][0]["wrapped"] = Value::from("")),
        Box::new(|m| m["slots"][0]["fingerprint"] = Value::from("abc")),
        Box::new(|m| m["slots"][0]["label"] = Value::from("a\u{0}b")),
        Box::new(|m| m["slots"][0]["id"] = Value::from(7)),
        Box::new(|m| m["slots"][0]["id"] = Value::from("../x")),
        Box::new(|m| m["check"] = Value::Null),
        Box::new(|m| m["version"] = Value::from(-1)),
        Box::new(|m| *m = Value::from(42)),
        Box::new(|m| {
            let s = m["slots"][0].clone();
            m["slots"].as_array_mut().unwrap().push(s);
        }),
    ];
    for (i, case) in cases.iter().enumerate() {
        assert_eq!(mutate(case.as_ref()), SecondFactorStatus::Unreadable, "case {i}");
    }
}

#[test]
fn flat_format_drops_the_slots_but_fails_safe() {
    let (user, _) = enabled();
    let flat = write(&user, Format::Flat, ExportMode::Redacted).unwrap();
    let file = UserFile::parse(flat.as_bytes()).unwrap();
    assert_eq!(file.summary().second_factor, SecondFactorStatus::Disabled);
    // The key ID in the header still demands the effective master password.
    assert!(matches!(file.load(&mut robert()), Err(Error::WrongMasterPassword)));
    let mut k = UserKeys::from_password_and_secret(NAME, PASSWORD, &pinned());
    let back = file.load(&mut k).unwrap();
    assert_eq!(back.site_password(&mut k, "personal.example").unwrap().as_str(), PERSONAL_PW);
}

// ------------------------------------------------------------------- merge

#[test]
fn merge_never_touches_the_second_factor() {
    // Destination with a second factor, source without (an old export).
    let (mut dest, mut dk) = enabled();
    let status = dest.second_factor_status().clone();
    let (mut src, mut sk) = rich_user();
    src.last_used = mpw_model::Timestamp::from_unix(i64::MAX / 4);
    src.add_site("new.example").unwrap().last_used = src.last_used;
    let summary = merge(&mut dest, &mut dk, &src, &mut sk).unwrap();
    assert_eq!(summary.added, ["new.example"]);
    assert_eq!(*dest.second_factor_status(), status);
    assert_eq!(dest.key_id().unwrap().as_str(), PINNED_KEY_ID);

    // Destination without, source with: the source's slots are not imported.
    let (mut plain, mut pk) = rich_user();
    let (mut src2, mut sk2) = enabled();
    src2.last_used = mpw_model::Timestamp::from_unix(i64::MAX / 4);
    src2.add_site("other.example").unwrap();
    merge(&mut plain, &mut pk, &src2, &mut sk2).unwrap();
    assert_eq!(*plain.second_factor_status(), SecondFactorStatus::Disabled);
    assert_eq!(plain.key_id().unwrap().as_str(), KEY_ID);
    assert_eq!(plain.site_password(&mut pk, "personal.example").unwrap().as_str(), PERSONAL_PW);
}
