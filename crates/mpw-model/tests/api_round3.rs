//! Change of master password, storage mode, general results, stored-state
//! access, and keeping stored values across type switches.
mod common;

use common::*;
use mpw_model::{
    write, AlgorithmVersion, Error, ExportMode, Format, KeyPurpose, ResultRequest, ResultType, User, UserFile,
    UserKeys,
};
use serde_json::Value;

fn unlocked() -> (User, UserKeys) {
    let mut keys = robert();
    let mut user = User::new(NAME).unwrap();
    user.authenticate(&mut keys).unwrap();
    user.add_site(MPA).unwrap();
    (user, keys)
}

fn fixture_user(keys: &mut UserKeys) -> User {
    UserFile::parse(&fixture("c-redacted.mpjson")).unwrap().load(keys).unwrap()
}

// -------------------------------------------------------- change master password

#[test]
fn change_master_password_reencrypts_everything() {
    let mut old = robert();
    let mut user = fixture_user(&mut old);
    user.add_site("device.example").ok();
    user.set_site_password(&mut old, "device.example", ResultType::StatefulDevice, "dev-pw").unwrap();
    user.store_site_login(&mut old, "device.example", ResultType::StatefulDevice, "dev-login").unwrap();
    user.set_user_login_name(&mut old, "rob").unwrap();
    // A value kept while a template is selected.
    user.add_site("switched.example").unwrap();
    user.set_site_password(&mut old, "switched.example", ResultType::StatefulPersonal, "kept").unwrap();
    user.site_mut("switched.example").unwrap().result_type = ResultType::TemplateLong;
    let generated_before = user.site_password(&mut old, MPA).unwrap();

    let mut new = robert_other();
    user.change_master_password(&mut old, &mut new).unwrap();

    assert_eq!(user.key_id().unwrap().as_str(), OTHER_KEY_ID);
    assert!(user.is_unlocked_by(&new) && !user.is_unlocked_by(&old));
    assert_eq!(user.identicon, None, "key-bytes holder: identicon unknown");
    assert_eq!(user.site_password(&mut new, "personal.example").unwrap().as_str(), PERSONAL_PW);
    assert_eq!(user.site_login(&mut new, "personal.example").unwrap().as_str(), PERSONAL_LOGIN);
    assert_eq!(user.site_answer(&mut new, MPA, "mother").unwrap().as_str(), "Smith");
    assert_eq!(user.site_password(&mut new, "device.example").unwrap().as_str(), "dev-pw");
    assert_eq!(user.site_login(&mut new, "device.example").unwrap().as_str(), "dev-login");
    assert_eq!(user.user_login(&mut new).unwrap().as_str(), "rob");
    // Generated passwords change with the master password, as they must.
    assert_ne!(*user.site_password(&mut new, MPA).unwrap(), *generated_before);
    user.site_mut("switched.example").unwrap().result_type = ResultType::StatefulPersonal;
    assert_eq!(user.site_password(&mut new, "switched.example").unwrap().as_str(), "kept");

    // Settings and unknown members survive.
    assert!(user.preferences.mask_passwords);
    assert_eq!(user.avatar, 3);
    assert_eq!(user.site(MPA).unwrap().url.as_deref(), Some("https://masterpasswordapp.com"));
    let out = write(&user, Format::Json, ExportMode::Redacted).unwrap();
    for unknown in ["_ext_otherapp", "futurePref", "_ext_nested", "_ext_futureapp", "_ext_toplevel"] {
        assert!(out.contains(unknown), "{unknown} lost");
    }
    let back = UserFile::parse(out.as_bytes()).unwrap().load(&mut new).unwrap();
    assert_eq!(back.site_password(&mut new, "personal.example").unwrap().as_str(), PERSONAL_PW);
}

#[test]
fn change_master_password_with_a_password_holder_sets_the_identicon() {
    let (mut user, mut old) = unlocked();
    user.identicon = None;
    let mut new = UserKeys::from_password(NAME, PASSWORD); // same password: one scrypt
    user.change_master_password(&mut old, &mut new).unwrap();
    assert_eq!(user.key_id().unwrap().as_str(), KEY_ID);
    assert_eq!(user.identicon.as_ref().unwrap().encode(), "2:╚☻╯⛄");
}

#[test]
fn change_master_password_is_all_or_nothing() {
    // The live password of "broken.example" was encrypted with a different key
    // than the one that unlocks the user: it cannot be decrypted.
    let text = format!(
        r#"{{"export":{{"format":1}},"user":{{"full_name":"{NAME}","key_id":"{OTHER_KEY_ID}","last_used":"2020-01-01T00:00:00Z","_ext_x":1}},
            "sites":{{"a.example":{{"type":1056,"password":"PLACEHOLDER","last_used":"2020-01-01T00:00:00Z"}},
                      "broken.example":{{"type":1056,"password":"{PERSONAL_STATE}","last_used":"2020-01-01T00:00:00Z"}}}}}}"#
    );
    let mut old = robert_other();
    let mut user = UserFile::parse(text.as_bytes()).unwrap().load(&mut old).unwrap();
    user.set_site_password(&mut old, "a.example", ResultType::StatefulPersonal, "fine").unwrap();
    let before = user.clone();
    let mut new = robert();
    let err = user.change_master_password(&mut old, &mut new).unwrap_err();
    match &err {
        Error::ReencryptFailed { site, .. } => assert_eq!(site.as_deref(), Some("broken.example")),
        e => panic!("{e:?}"),
    }
    let shown = format!("{err} {err:?}");
    assert!(shown.contains("broken.example") && !shown.contains(PERSONAL_STATE), "{shown}");
    assert_eq!(user, before);
    assert!(user.is_unlocked_by(&old) && !user.is_unlocked_by(&new));
}

#[test]
fn change_master_password_checks_the_keys() {
    let (mut user, _) = unlocked();
    let before = user.clone();
    assert!(matches!(user.change_master_password(&mut robert(), &mut robert_other()), Err(Error::NotAuthenticated)));
    let mut old = robert();
    user.authenticate(&mut old).unwrap();
    assert!(matches!(
        user.change_master_password(&mut old, &mut keys("Someone Else", PASSWORD)),
        Err(Error::UserMismatch)
    ));
    assert_eq!(user, before);
}

// ------------------------------------------------------------------- storage

#[test]
fn storage_mode_keeps_device_private_values() {
    let (mut user, mut keys) = unlocked();
    user.set_site_password(&mut keys, MPA, ResultType::StatefulDevice, "device-pw").unwrap();
    user.add_site("q.example").unwrap();
    user.store_answer(&mut keys, "q.example", "pet", ResultType::StatefulDevice, "Rex").unwrap();
    user.store_user_login(&mut keys, ResultType::StatefulDevice, "dev-user").unwrap();
    for format in [Format::Json, Format::Flat] {
        let stored = write(&user, format, ExportMode::Storage).unwrap();
        let back = UserFile::parse(stored.as_bytes()).unwrap().load(&mut keys).unwrap();
        assert_eq!(back.site_password(&mut keys, MPA).unwrap().as_str(), "device-pw", "{format:?}");
        assert!(!stored.contains("device-pw"));
        if format == Format::Json {
            assert_eq!(back.site_answer(&mut keys, "q.example", "pet").unwrap().as_str(), "Rex");
            assert_eq!(back.user_login(&mut keys).unwrap().as_str(), "dev-user");
        }
        let exported = write(&user, format, ExportMode::Redacted).unwrap();
        let back = UserFile::parse(exported.as_bytes()).unwrap().load(&mut keys).unwrap();
        assert!(!back.site(MPA).unwrap().has_password_state(), "{format:?}");
    }
    // The flat format still refuses what it cannot carry.
    user.add_site(" leading.example").unwrap();
    assert!(matches!(write(&user, Format::Flat, ExportMode::Storage), Err(Error::NotRepresentable { .. })));
}

// ----------------------------------------------------------- general results

#[test]
fn site_result_defaults_match_the_specific_operations() {
    let mut keys = robert();
    let mut user = fixture_user(&mut keys);
    user.set_user_login_name(&mut keys, "rob").unwrap();
    let names: Vec<String> = user.sites().map(|s| s.name().to_owned()).collect();
    for name in &names {
        let r = |k: &mut UserKeys, req: ResultRequest<'_>| user.site_result(k, name, &req).map(|v| v.to_string());
        let s = |res: mpw_model::Result<mpw_model::Zeroizing<String>>| res.map(|v| v.to_string());
        assert_eq!(
            r(&mut keys, ResultRequest::password()).ok(),
            s(user.site_password(&mut keys, name)).ok(),
            "{name}"
        );
        assert_eq!(r(&mut keys, ResultRequest::login()).unwrap(), s(user.site_login(&mut keys, name)).unwrap());
        for kw in ["", "question", "mother", "unknown"] {
            assert_eq!(
                r(&mut keys, ResultRequest::answer(kw)).unwrap(),
                s(user.site_answer(&mut keys, name, kw)).unwrap()
            );
        }
    }
    assert_eq!(
        user.site_result(&mut keys, MPA, &ResultRequest::answer("question")).unwrap().as_str(),
        MPA_ANSWER_QUESTION
    );
}

#[test]
fn site_result_overrides_and_contexts() {
    let mut keys = robert();
    let user = fixture_user(&mut keys);
    let get = |k: &mut UserKeys, site: &str, req: ResultRequest<'_>| user.site_result(k, site, &req).unwrap().to_string();

    assert_eq!(get(&mut keys, MPA, ResultRequest::password().result_type(ResultType::TemplatePin)), "7662");
    assert_eq!(get(&mut keys, MPA, ResultRequest::password().counter(4_294_967_295)), "XambHoqo6[Peni");
    assert_eq!(get(&mut keys, MPA, ResultRequest::new(KeyPurpose::Recovery)), MPA_ANSWER);

    // A key context for passwords and logins, computed with the site's algorithm.
    for (site, alg) in [(MPA, AlgorithmVersion::V3), ("old.masterpasswordapp.com", AlgorithmVersion::V0)] {
        let with = get(&mut keys, site, ResultRequest::password().context("ctx"));
        let direct = keys
            .key(alg)
            .unwrap()
            .site_result(site, 1, KeyPurpose::Authentication, Some("ctx"), ResultType::TemplateLong, None)
            .unwrap();
        assert_eq!(with, *direct);
        assert_ne!(with, get(&mut keys, site, ResultRequest::password()));
        assert_eq!(get(&mut keys, site, ResultRequest::password().context("")), get(&mut keys, site, ResultRequest::password()));
    }
    let login_ctx = get(&mut keys, MPA, ResultRequest::login().context("ctx"));
    assert_ne!(login_ctx, MPA_LOGIN);

    // Stored values are decrypted regardless of context.
    assert_eq!(get(&mut keys, "personal.example", ResultRequest::password().context("x")), PERSONAL_PW);

    // Derived keys, with the site's algorithm and a size.
    let k256 = get(&mut keys, "old.masterpasswordapp.com", ResultRequest::password().derive_key(Some(256)));
    let direct = keys
        .key(AlgorithmVersion::V0)
        .unwrap()
        .site_result("old.masterpasswordapp.com", 1, KeyPurpose::Authentication, None, ResultType::DeriveKey, Some("256"))
        .unwrap();
    assert_eq!(k256, *direct);
    assert_eq!(k256.len(), 44);
    let default = get(&mut keys, MPA, ResultRequest::password().derive_key(None));
    assert_eq!(default.len(), 88);
    assert!(user.site_result(&mut keys, MPA, &ResultRequest::password().derive_key(Some(100))).is_err());
    assert!(matches!(
        user.site_result(&mut robert(), MPA, &ResultRequest::password()),
        Err(Error::NotAuthenticated)
    ));
}

#[test]
fn stored_states_are_readable_as_ciphertext() {
    let mut keys = robert();
    let mut user = fixture_user(&mut keys);
    let p = user.site("personal.example").unwrap();
    assert_eq!(p.password_state(), Some(PERSONAL_STATE));
    assert_eq!(p.login_state(), Some(PERSONAL_LOGIN_STATE));
    assert_eq!(user.site(MPA).unwrap().question("mother").unwrap().answer_state(), Some(MOTHER_STATE));
    assert_eq!(user.site(MPA).unwrap().password_state(), None);
    assert_eq!(user.login_state(), None);
    user.set_user_login_name(&mut keys, "rob").unwrap();
    assert!(user.login_state().is_some_and(|s| !s.contains("rob")));
}

// ------------------------------------------------- switching types keeps values

#[test]
fn switching_to_a_generated_login_keeps_the_stored_one() {
    let (mut user, mut keys) = unlocked();
    user.set_site_login_name(&mut keys, MPA, "stored-login").unwrap();
    user.site_mut(MPA).unwrap().set_generated_login(ResultType::TemplateName).unwrap();
    assert_eq!(user.site_login(&mut keys, MPA).unwrap().as_str(), MPA_LOGIN);
    assert!(user.site(MPA).unwrap().has_login_state());
    user.site_mut(MPA).unwrap().use_stored_login(ResultType::StatefulPersonal).unwrap();
    assert_eq!(user.site_login(&mut keys, MPA).unwrap().as_str(), "stored-login");
    assert!(user.site_mut(MPA).unwrap().use_stored_login(ResultType::TemplateName).is_err());

    // Same for the user-level login.
    user.site_mut(MPA).unwrap().use_default_login();
    user.set_user_login_name(&mut keys, "user-login").unwrap();
    user.set_generated_login(ResultType::TemplateName).unwrap();
    assert_eq!(user.site_login(&mut keys, MPA).unwrap().as_str(), MPA_LOGIN);
    user.use_stored_login(ResultType::StatefulPersonal).unwrap();
    assert_eq!(user.site_login(&mut keys, MPA).unwrap().as_str(), "user-login");
}

#[test]
fn switching_password_types_keeps_the_stored_password() {
    let (mut user, mut keys) = unlocked();
    user.set_site_password(&mut keys, MPA, ResultType::StatefulPersonal, "mine").unwrap();
    user.site_mut(MPA).unwrap().result_type = ResultType::TemplateLong;
    assert_eq!(user.site_password(&mut keys, MPA).unwrap().as_str(), MPA_V3_LONG);
    user.site_mut(MPA).unwrap().result_type = ResultType::StatefulPersonal;
    assert_eq!(user.site_password(&mut keys, MPA).unwrap().as_str(), "mine");
    // Like the reference, a value not in use is not written to files.
    user.site_mut(MPA).unwrap().result_type = ResultType::TemplateLong;
    let out = write(&user, Format::Json, ExportMode::Storage).unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    assert!(v["sites"][MPA].get("password").is_none());
}

#[test]
fn device_private_logins_and_answers() {
    let (mut user, mut keys) = unlocked();
    user.store_site_login(&mut keys, MPA, ResultType::StatefulDevice, "dev-login").unwrap();
    user.store_answer(&mut keys, MPA, "pet", ResultType::StatefulDevice, "Rex").unwrap();
    assert_eq!(user.site(MPA).unwrap().login_type(), Some(ResultType::StatefulDevice));
    assert_eq!(user.site_login(&mut keys, MPA).unwrap().as_str(), "dev-login");
    assert_eq!(user.site_answer(&mut keys, MPA, "pet").unwrap().as_str(), "Rex");
    for mode in [ExportMode::Redacted, ExportMode::Revealed(&mut keys)] {
        let out = write(&user, Format::Json, mode).unwrap();
        assert!(!out.contains("dev-login") && !out.contains("Rex"));
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v["sites"][MPA].get("login_name").is_none());
        assert!(v["sites"][MPA]["questions"]["pet"].get("answer").is_none());
    }
    assert!(matches!(
        user.store_site_login(&mut keys, MPA, ResultType::TemplateName, "x"),
        Err(Error::NotStateful(_))
    ));
    assert!(matches!(
        user.store_answer(&mut keys, MPA, "pet", ResultType::TemplatePhrase, "x"),
        Err(Error::NotStateful(_))
    ));
}
