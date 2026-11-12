mod common;

use common::*;
use mpw_model::{merge, AlgorithmVersion, Error, ResultType, Timestamp, User, UserKeys};

fn user_with(keys: &mut UserKeys, last_used: i64) -> User {
    let mut u = User::new(NAME).unwrap();
    u.authenticate(keys).unwrap();
    u.last_used = Timestamp::from_unix(last_used);
    u
}

fn site(u: &mut User, name: &str, last_used: i64) {
    u.add_site(name).unwrap().last_used = Timestamp::from_unix(last_used);
}

#[test]
fn same_key_merge_newer_wins_and_new_sites_are_added() {
    let (mut dk, mut sk) = (robert(), robert());
    let mut dest = user_with(&mut dk, 100);
    site(&mut dest, "kept.example", 50);
    site(&mut dest, "older-in-import.example", 50);
    site(&mut dest, "newer-in-import.example", 50);
    dest.site_mut("newer-in-import.example").unwrap().counter = 1;

    let mut src = user_with(&mut sk, 200);
    src.avatar = 7;
    src.default_type = ResultType::TemplateMaximum;
    site(&mut src, "older-in-import.example", 40);
    site(&mut src, "newer-in-import.example", 60);
    src.site_mut("newer-in-import.example").unwrap().counter = 9;
    site(&mut src, "new.example", 10);
    src.set_site_password(&mut sk, "new.example", ResultType::StatefulPersonal, PERSONAL_PW).unwrap();
    src.set_algorithm(&mut sk, AlgorithmVersion::V2).unwrap();

    let key_id = dest.key_id().cloned();
    let summary = merge(&mut dest, &mut dk, &src, &mut sk).unwrap();
    assert_eq!(summary.replaced, ["newer-in-import.example"]);
    assert_eq!(summary.added, ["new.example"]);
    assert!(summary.skipped.is_empty());
    assert!(summary.user_updated);
    assert_eq!(dest.key_id().cloned(), key_id);
    assert_eq!(dest.site("newer-in-import.example").unwrap().counter, 9);
    assert_eq!(dest.site("older-in-import.example").unwrap().last_used, Timestamp::from_unix(50));
    assert!(dest.site("kept.example").is_some());
    assert_eq!((dest.avatar, dest.default_type), (7, ResultType::TemplateMaximum));
    // Same key: algorithm taken (an ASCII name's key ID is version-independent).
    assert_eq!(dest.algorithm(), AlgorithmVersion::V2);
    assert!(dest.is_unlocked_by(&dk));
    assert_eq!(dest.site_password(&mut dk, "new.example").unwrap().as_str(), PERSONAL_PW);
}

#[test]
fn older_import_does_not_touch_user_settings() {
    let (mut dk, mut sk) = (robert(), robert());
    let mut dest = user_with(&mut dk, 300);
    let mut src = user_with(&mut sk, 200);
    src.avatar = 4;
    let before = dest.clone();
    let summary = merge(&mut dest, &mut dk, &src, &mut sk).unwrap();
    assert!(summary.is_empty());
    assert_eq!(dest, before);
}

#[test]
fn different_keys_reencrypt_and_never_change_the_key_id() {
    // Regressions: MPService.copy copied encrypted state between users with
    // different master keys, and the merge overwrote masterKeyID/algorithm.
    let (mut dk, mut sk) = (robert(), robert_other());
    let mut dest = user_with(&mut dk, 100);
    site(&mut dest, "replaced.example", 10);
    dest.set_site_password(&mut dk, "replaced.example", ResultType::StatefulPersonal, "old").unwrap();

    let mut src = user_with(&mut sk, 200);
    assert_eq!(src.key_id().unwrap().as_str(), OTHER_KEY_ID);
    src.avatar = 9;
    src.default_type = ResultType::TemplatePin;
    src.set_algorithm(&mut sk, AlgorithmVersion::V1).unwrap();
    site(&mut src, "replaced.example", 20);
    src.set_site_password(&mut sk, "replaced.example", ResultType::StatefulPersonal, "new").unwrap();
    site(&mut src, "personal.example", 20);
    src.set_site_password(&mut sk, "personal.example", ResultType::StatefulPersonal, PERSONAL_PW).unwrap();
    src.set_site_login_name(&mut sk, "personal.example", PERSONAL_LOGIN).unwrap();
    src.set_answer(&mut sk, "personal.example", "mother", "Smith").unwrap();
    src.set_user_login_name(&mut sk, "src-login").unwrap();

    let summary = merge(&mut dest, &mut dk, &src, &mut sk).unwrap();
    assert_eq!(summary.replaced, ["replaced.example"]);
    assert_eq!(summary.added, ["personal.example"]);
    assert!(summary.user_updated);
    assert_eq!(dest.key_id().unwrap().as_str(), KEY_ID);
    assert_eq!(dest.algorithm(), AlgorithmVersion::V3);
    assert_eq!(dest.default_type, ResultType::DEFAULT);
    assert_eq!(dest.avatar, 9);
    assert!(!dest.has_login_state());
    // The copied values decrypt with the destination's key.
    assert!(dest.is_unlocked_by(&dk));
    assert_eq!(dest.site_password(&mut dk, "replaced.example").unwrap().as_str(), "new");
    assert_eq!(dest.site_password(&mut dk, "personal.example").unwrap().as_str(), PERSONAL_PW);
    assert_eq!(dest.site_login(&mut dk, "personal.example").unwrap().as_str(), PERSONAL_LOGIN);
    assert_eq!(dest.site_answer(&mut dk, "personal.example", "mother").unwrap().as_str(), "Smith");
}

#[test]
fn undecryptable_state_skips_the_site_and_keeps_the_destination() {
    let (mut dk, mut sk) = (robert(), robert_other());
    let mut dest = user_with(&mut dk, 100);
    site(&mut dest, "broken.example", 10);
    dest.set_site_password(&mut dk, "broken.example", ResultType::StatefulPersonal, "mine").unwrap();

    // An import whose stored state was encrypted with a *third* key: our
    // source key cannot decrypt it.
    let text = format!(
        r#"{{"user":{{"full_name":"{NAME}","key_id":"{OTHER_KEY_ID}","last_used":"2020-01-01T00:00:00Z"}},
            "sites":{{"broken.example":{{"type":1056,"password":"{PERSONAL_STATE}","last_used":"2020-01-01T00:00:00Z"}},
                      "fresh.example":{{"type":17,"last_used":"2020-01-01T00:00:00Z"}}}}}}"#
    );
    let src = mpw_model::UserFile::parse(text.as_bytes()).unwrap().load(&mut sk).unwrap();
    let summary = merge(&mut dest, &mut dk, &src, &mut sk).unwrap();
    assert_eq!(summary.skipped, ["broken.example"]);
    assert_eq!(summary.added, ["fresh.example"]);
    assert_eq!(dest.site_password(&mut dk, "broken.example").unwrap().as_str(), "mine");
}

#[test]
fn merge_needs_both_users_unlocked() {
    let (mut dk, mut sk) = (robert(), robert());
    let mut dest = user_with(&mut dk, 1);
    let src = user_with(&mut sk, 2);
    let before = dest.clone();
    let mut fresh = robert();
    assert!(matches!(merge(&mut dest, &mut dk, &src, &mut fresh), Err(Error::NotAuthenticated)));
    assert!(matches!(merge(&mut dest, &mut fresh, &src, &mut sk), Err(Error::NotAuthenticated)));
    assert_eq!(dest, before);
}
