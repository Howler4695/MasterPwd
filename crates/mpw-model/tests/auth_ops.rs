mod common;

use common::*;
use mpw_model::{
    sort_most_recent_first, AlgorithmVersion, Authentication, Error, MasterKey, ResultType, Timestamp, User,
    UserFile, UserKeys,
};

fn new_user() -> (User, UserKeys) {
    let mut keys = robert();
    let mut user = User::new(NAME).unwrap();
    assert_eq!(user.authenticate(&mut keys).unwrap(), Authentication::Adopted);
    user.add_site(MPA).unwrap();
    (user, keys)
}

// ------------------------------------------------------------- authentication

#[test]
fn new_user_adopts_the_key_id() {
    let (user, _) = new_user();
    assert_eq!(user.key_id().unwrap().as_str(), KEY_ID);
}

#[test]
fn authentication_with_the_password_sets_the_identicon() {
    // The only test that runs scrypt from a password.
    let mut keys = UserKeys::from_password(NAME, PASSWORD);
    let mut user = User::new(NAME).unwrap();
    user.authenticate(&mut keys).unwrap();
    assert_eq!(user.key_id().unwrap().as_str(), KEY_ID);
    assert_eq!(user.identicon.as_ref().unwrap().encode(), "2:╚☻╯⛄");
    // Keys for other versions of an ASCII name are reused, not re-derived.
    let v0 = keys.key_bytes(AlgorithmVersion::V0).unwrap();
    assert_eq!(*v0, *robert().key_bytes(AlgorithmVersion::V3).unwrap());
}

#[test]
fn non_ascii_names_derive_per_version() {
    // v0-v2 count the name's characters, v3 its bytes: the keys differ.
    let mut keys = UserKeys::from_password("⛄", PASSWORD);
    let v3 = keys.key(AlgorithmVersion::V3).unwrap().key_id();
    let v2 = keys.key(AlgorithmVersion::V2).unwrap().key_id();
    assert_eq!(v3.as_str(), "1717AA1F9BF5BA56CD0965CDA3D78E6D2E6A1EA8C067A8EA621F3DDAD4A87EB8");
    assert_eq!(v2.as_str(), "4D5851D0B093D65DE0CF13D94877270468C0B65A6E42CA50D393AC9B99C457B5");
}

#[test]
fn wrong_password_is_a_typed_error_and_changes_nothing() {
    let (mut user, _) = new_user();
    let before = user.clone();
    let mut wrong = robert_other();
    assert!(matches!(user.authenticate(&mut wrong), Err(Error::WrongMasterPassword)));
    assert_eq!(user, before);
    assert!(matches!(user.site_password(&mut wrong, MPA), Err(Error::NotAuthenticated)));
}

#[test]
fn failed_reauthentication_does_not_log_out() {
    // Regression: MPUser.login called logout() when a new attempt failed.
    let (mut user, mut keys) = new_user();
    let before = user.clone();
    assert!(user.authenticate(&mut robert_other()).is_err());
    assert_eq!(user, before);
    assert_eq!(user.site_password(&mut keys, MPA).unwrap().as_str(), MPA_V3_LONG);
}

#[test]
fn keys_must_belong_to_the_user() {
    let (mut user, _) = new_user();
    let mut stranger = keys("Someone Else", PASSWORD);
    assert!(matches!(user.authenticate(&mut stranger), Err(Error::UserMismatch)));
    assert!(matches!(user.site_password(&mut stranger, MPA), Err(Error::UserMismatch)));
}

#[test]
fn operations_need_authenticated_keys() {
    let (user, _) = new_user();
    let mut fresh = robert();
    assert!(matches!(user.site_password(&mut fresh, MPA), Err(Error::NotAuthenticated)));
    assert!(matches!(user.site_login(&mut fresh, MPA), Err(Error::NotAuthenticated)));
    assert!(matches!(user.site_answer(&mut fresh, MPA, ""), Err(Error::NotAuthenticated)));
    let mut user2 = user.clone();
    assert!(matches!(
        user2.set_site_password(&mut fresh, MPA, ResultType::StatefulPersonal, "x"),
        Err(Error::NotAuthenticated)
    ));
    assert_eq!(user2, user);
}

#[test]
fn keychain_keys_work_without_a_password() {
    let bytes = robert().key_bytes(AlgorithmVersion::V3).unwrap();
    let mut keys = UserKeys::from_key(NAME, MasterKey::from_bytes(*bytes, AlgorithmVersion::V3));
    assert!(!keys.has_password() && keys.identicon().is_none());
    let mut user = UserFile::parse(&fixture("c-redacted.mpjson")).unwrap().load(&mut keys).unwrap();
    // A site on another version of an ASCII name works too.
    assert!(user.site_password(&mut keys, "old.masterpasswordapp.com").is_ok());
    assert_eq!(user.authenticate(&mut keys).unwrap(), Authentication::Verified);
    // A non-ASCII name cannot produce other versions from one key.
    let mut snow = UserKeys::from_key("⛄", MasterKey::from_bytes([7; 64], AlgorithmVersion::V3));
    assert!(matches!(snow.key(AlgorithmVersion::V2), Err(Error::KeyUnavailable(AlgorithmVersion::V2))));
}

#[test]
fn reset_key_id_adopts_a_new_password() {
    let (mut user, _) = new_user();
    user.reset_key_id();
    let mut other = robert_other();
    assert_eq!(user.authenticate(&mut other).unwrap(), Authentication::Adopted);
    assert_eq!(user.key_id().unwrap().as_str(), OTHER_KEY_ID);
    assert!(matches!(user.authenticate(&mut robert()), Err(Error::WrongMasterPassword)));
}

#[test]
fn secrets_never_appear_in_debug_output() {
    let (mut user, mut keys) = new_user();
    user.set_site_password(&mut keys, MPA, ResultType::StatefulPersonal, PERSONAL_PW).unwrap();
    let state_debug = format!("{user:?}");
    assert!(state_debug.contains("<encrypted>"));
    let pw_keys = UserKeys::from_password(NAME, PASSWORD);
    let dbg = format!("{pw_keys:?} {keys:?}");
    assert!(!dbg.contains(PASSWORD) && !dbg.contains("banana"), "{dbg}");
}

// ----------------------------------------------------------------- operations

#[test]
fn site_results_use_the_sites_algorithm_counter_and_type() {
    let (mut user, mut keys) = new_user();
    assert_eq!(user.site_password(&mut keys, MPA).unwrap().as_str(), MPA_V3_LONG);
    user.set_site_algorithm(&mut keys, MPA, AlgorithmVersion::V0).unwrap();
    assert_eq!(user.site_password(&mut keys, MPA).unwrap().as_str(), MPA_V0_LONG);
    user.set_site_algorithm(&mut keys, MPA, AlgorithmVersion::V3).unwrap();
    user.site_mut(MPA).unwrap().result_type = ResultType::TemplatePin;
    assert_eq!(user.site_password(&mut keys, MPA).unwrap().as_str(), "7662");
    user.site_mut(MPA).unwrap().result_type = ResultType::TemplateLong;
    user.site_mut(MPA).unwrap().counter = 4_294_967_295;
    assert_eq!(user.site_password(&mut keys, MPA).unwrap().as_str(), "XambHoqo6[Peni");
    assert!(matches!(user.site_password(&mut keys, "nope"), Err(Error::NoSuchSite)));
}

#[test]
fn new_sites_take_the_users_defaults() {
    let (mut user, mut keys) = new_user();
    user.set_algorithm(&mut keys, AlgorithmVersion::V2).unwrap();
    user.default_type = ResultType::TemplateMaximum;
    let site = user.add_site("new.example").unwrap();
    assert_eq!((site.algorithm(), site.result_type, site.counter), (AlgorithmVersion::V2, ResultType::TemplateMaximum, 1));
    assert_eq!(site.login_type(), None);
    assert!(matches!(user.add_site("new.example"), Err(Error::SiteExists)));
    assert!(matches!(user.add_site(""), Err(Error::InvalidSiteName(_))));
    assert!(matches!(user.add_site("a\nb"), Err(Error::InvalidSiteName(_))));
}

#[test]
fn login_names_follow_the_original_defaulting_rules() {
    let (mut user, mut keys) = new_user();
    // No site login type: the user's template, applied to the site.
    assert_eq!(user.site_login(&mut keys, MPA).unwrap().as_str(), MPA_LOGIN);
    // The user stores a personal login: every inheriting site uses it.
    user.set_user_login_name(&mut keys, PERSONAL_LOGIN).unwrap();
    assert_eq!(user.user_login(&mut keys).unwrap().as_str(), PERSONAL_LOGIN);
    assert_eq!(user.site_login(&mut keys, MPA).unwrap().as_str(), PERSONAL_LOGIN);
    // A site's own login wins.
    user.add_site("other.example").unwrap();
    user.set_site_login_name(&mut keys, "other.example", "rob").unwrap();
    assert_eq!(user.site_login(&mut keys, "other.example").unwrap().as_str(), "rob");
    // A site generating its login from a template.
    user.site_mut(MPA).unwrap().set_generated_login(ResultType::TemplateName).unwrap();
    assert_eq!(user.site_login(&mut keys, MPA).unwrap().as_str(), MPA_LOGIN);
    // Back to inheriting.
    user.site_mut(MPA).unwrap().use_default_login();
    assert_eq!(user.site_login(&mut keys, MPA).unwrap().as_str(), PERSONAL_LOGIN);
    user.set_generated_login(ResultType::TemplateName).unwrap();
    assert_eq!(user.site_login(&mut keys, MPA).unwrap().as_str(), MPA_LOGIN);
}

#[test]
fn answers_use_keyword_context_and_question_type() {
    let (mut user, mut keys) = new_user();
    assert_eq!(user.site_answer(&mut keys, MPA, "").unwrap().as_str(), MPA_ANSWER);
    assert_eq!(user.site_answer(&mut keys, MPA, "question").unwrap().as_str(), MPA_ANSWER_QUESTION);
    user.site_mut(MPA).unwrap().add_question("question").unwrap();
    assert_eq!(user.site_answer(&mut keys, MPA, "question").unwrap().as_str(), MPA_ANSWER_QUESTION);
    user.set_answer(&mut keys, MPA, "mother", "Smith").unwrap();
    assert_eq!(user.site_answer(&mut keys, MPA, "mother").unwrap().as_str(), "Smith");
    let q = user.site(MPA).unwrap().question("mother").unwrap();
    assert_eq!(q.result_type, ResultType::StatefulPersonal);
    assert!(q.has_answer_state());
}

#[test]
fn stored_passwords() {
    let (mut user, mut keys) = new_user();
    user.set_site_password(&mut keys, MPA, ResultType::StatefulPersonal, "pässword").unwrap();
    assert_eq!(user.site_password(&mut keys, MPA).unwrap().as_str(), "pässword");
    user.set_site_password(&mut keys, MPA, ResultType::StatefulDevice, "device").unwrap();
    assert_eq!(user.site_password(&mut keys, MPA).unwrap().as_str(), "device");
    assert!(matches!(
        user.set_site_password(&mut keys, MPA, ResultType::TemplateLong, "x"),
        Err(Error::NotStateful(_))
    ));
    user.add_site("empty.example").unwrap().result_type = ResultType::StatefulPersonal;
    assert!(matches!(user.site_password(&mut keys, "empty.example"), Err(Error::NoStoredValue(_))));
    // Back to a template: the generated password again.
    user.site_mut(MPA).unwrap().result_type = ResultType::TemplateLong;
    assert_eq!(user.site_password(&mut keys, MPA).unwrap().as_str(), MPA_V3_LONG);
}

#[test]
fn site_algorithm_change_reencrypts_state() {
    let (mut user, mut keys) = new_user();
    user.set_site_password(&mut keys, MPA, ResultType::StatefulPersonal, "keep me").unwrap();
    user.set_answer(&mut keys, MPA, "pet", "Rex").unwrap();
    user.set_site_algorithm(&mut keys, MPA, AlgorithmVersion::V1).unwrap();
    assert_eq!(user.site(MPA).unwrap().algorithm(), AlgorithmVersion::V1);
    assert_eq!(user.site_password(&mut keys, MPA).unwrap().as_str(), "keep me");
    assert_eq!(user.site_answer(&mut keys, MPA, "pet").unwrap().as_str(), "Rex");
}

#[test]
fn user_algorithm_change_keeps_the_user_unlocked() {
    let (mut user, mut keys) = new_user();
    user.set_user_login_name(&mut keys, "rob").unwrap();
    user.set_algorithm(&mut keys, AlgorithmVersion::V2).unwrap();
    assert_eq!(user.algorithm(), AlgorithmVersion::V2);
    assert!(user.is_unlocked_by(&keys));
    assert_eq!(user.user_login(&mut keys).unwrap().as_str(), "rob");
}

#[test]
fn use_site_bumps_uses_and_last_used() {
    let (mut user, _) = new_user();
    user.last_used = Timestamp::from_unix(10);
    user.site_mut(MPA).unwrap().last_used = Timestamp::from_unix(10);
    user.site_mut(MPA).unwrap().uses = u32::MAX - 1;
    user.use_site(MPA).unwrap();
    user.use_site(MPA).unwrap();
    let site = user.site(MPA).unwrap();
    assert_eq!(site.uses, u32::MAX);
    assert!(site.last_used > Timestamp::from_unix(10) && user.last_used == site.last_used);
    assert!(matches!(user.use_site("nope"), Err(Error::NoSuchSite)));
}

#[test]
fn rename_keeps_stored_values() {
    let (mut user, mut keys) = new_user();
    user.set_site_password(&mut keys, MPA, ResultType::StatefulPersonal, "kept").unwrap();
    user.add_site("taken.example").unwrap();
    assert!(matches!(user.rename_site(MPA, "taken.example"), Err(Error::SiteExists)));
    user.rename_site(MPA, "renamed.example").unwrap();
    assert!(user.site(MPA).is_none());
    assert_eq!(user.site_password(&mut keys, "renamed.example").unwrap().as_str(), "kept");
}

// ------------------------------------------------------------------- ordering

#[test]
fn ordering_is_total_and_consistent() {
    // Regression: MPUser had == by name but < by last-used.
    let mk = |name: &str, t: i64| {
        let mut u = User::new(name).unwrap();
        u.last_used = Timestamp::from_unix(t);
        u
    };
    let mut users = vec![mk("b", 5), mk("a", 5), mk("c", 9), mk("d", 1)];
    sort_most_recent_first(&mut users);
    let names: Vec<_> = users.iter().map(User::full_name).collect();
    assert_eq!(names, ["c", "a", "b", "d"]);
    users.sort_by(User::cmp_by_name);
    let names: Vec<_> = users.iter().map(User::full_name).collect();
    assert_eq!(names, ["a", "b", "c", "d"]);
    // Equality is structural: same name but different data is not equal, and
    // the name order says "same identity", not "equal".
    let (x, y) = (mk("a", 1), mk("a", 2));
    assert_ne!(x, y);
    assert_eq!(x.cmp_by_name(&y), std::cmp::Ordering::Equal);
}
