mod common;

use common::*;
use mpw_model::{
    encode_name, export_to, read_user_file, Error, ExportMode, Format, ResultType, User, UserKeys, UserStore,
};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn files(dir: &Path) -> Vec<String> {
    let mut v: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn unlocked(name: &str) -> (User, UserKeys) {
    let mut keys = keys(name, PASSWORD);
    let mut user = User::new(name).unwrap();
    user.authenticate(&mut keys).unwrap();
    user.add_site(MPA).unwrap();
    (user, keys)
}

#[test]
fn save_list_load_with_private_permissions() {
    let tmp = TempDir::new("basic");
    let dir = tmp.path().join("nested/Users");
    let store = UserStore::open(&dir).unwrap();
    assert_eq!(mode(&dir), 0o700);

    let (mut user, mut keys) = unlocked(NAME);
    user.set_site_password(&mut keys, MPA, ResultType::StatefulDevice, "device pw").unwrap();
    let path = store.create(&user).unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(path, store.path_for(NAME));
    assert!(matches!(store.create(&user), Err(Error::UserExists)));

    let listing = store.list().unwrap();
    assert_eq!(listing.users.len(), 1);
    assert!(listing.unreadable.is_empty());
    assert_eq!(listing.users[0].summary.full_name, NAME);

    let mut keys2 = robert();
    let loaded = store.load(NAME, &mut keys2).unwrap();
    assert_eq!(loaded, user);
    // Device-private passwords stay in this device's store.
    assert_eq!(loaded.site_password(&mut keys2, MPA).unwrap().as_str(), "device pw");
    assert!(matches!(store.load(NAME, &mut robert_other()), Err(Error::WrongMasterPassword)));
    assert_eq!(store.load_locked(NAME).unwrap(), user);
    assert!(matches!(store.load("Nobody", &mut robert()), Err(Error::UserNotFound)));
}

#[test]
fn failed_save_leaves_the_previous_file_intact() {
    // Regression: MPMarshal wrote with createFile (non-atomic) and "replace"
    // deleted the existing file before writing the new one.
    let tmp = TempDir::new("atomic");
    let store = UserStore::open(tmp.path()).unwrap();
    let (mut user, _) = unlocked(NAME);
    let path = store.save(&user).unwrap();
    let original = fs::read(&path).unwrap();

    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o500)).unwrap();
    if fs::File::create(tmp.path().join("probe")).is_ok() {
        eprintln!("running with privileges that ignore permissions; skipping");
        return;
    }
    user.add_site("second.example").unwrap();
    assert!(matches!(store.save(&user), Err(Error::Io(_))));
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(files(tmp.path()), [path.file_name().unwrap().to_str().unwrap()]);

    // A successful replace swaps the content and leaves no temporary files.
    store.save(&user).unwrap();
    assert_eq!(files(tmp.path()).len(), 1);
    assert!(store.load_locked(NAME).unwrap().site("second.example").is_some());
}

#[test]
fn file_names_are_safe_distinct_and_never_hidden() {
    // Regression: only "/" was replaced, so "..", ".hidden", control characters,
    // long names and case variants misbehaved or collided.
    let tmp = TempDir::new("names");
    let store = UserStore::open(tmp.path()).unwrap();
    let long = "Ä".repeat(600);
    let names = ["..", ".hidden", "a/b", "../escape", "Bob", "bob", "BOB", "e\u{301}", "\u{e9}", long.as_str(), "x~y"];
    for n in names {
        let (user, _) = unlocked_any(n);
        let path = store.save(&user).unwrap();
        assert_eq!(path.parent().unwrap(), tmp.path(), "{n:?}");
        let file = path.file_name().unwrap().to_str().unwrap();
        assert!(!file.starts_with('.') && file.len() <= 255, "{file}");
    }
    let listing = store.list().unwrap();
    let mut listed: Vec<_> = listing.users.iter().map(|u| u.summary.full_name.clone()).collect();
    listed.sort();
    let mut expected: Vec<_> = names.iter().map(|s| s.to_string()).collect();
    expected.sort();
    assert_eq!(listed, expected);
    // No two names share a file, even on a case-insensitive file system.
    let lower: std::collections::HashSet<_> = files(tmp.path()).iter().map(|f| f.to_lowercase()).collect();
    assert_eq!(lower.len(), names.len());
    assert!(!tmp.path().parent().unwrap().join("escape.mpjson").exists());
    assert!(matches!(User::new("line\nbreak"), Err(Error::InvalidFullName(_))));
    assert!(matches!(User::new("nul\0"), Err(Error::InvalidFullName(_))));
}

fn unlocked_any(name: &str) -> (User, ()) {
    // These users are never unlocked; storage does not need keys.
    (User::new(name).unwrap(), ())
}

#[test]
fn hashed_name_collisions_are_detected() {
    let tmp = TempDir::new("collide");
    let store = UserStore::open(tmp.path()).unwrap();
    let long = "Ä".repeat(600);
    let user = User::new(&long).unwrap();
    let path = store.path_for(&long);
    assert!(path.file_name().unwrap().to_str().unwrap().contains('~'));
    // Plant another user's file at that path.
    let intruder = User::new("Intruder").unwrap();
    let data = mpw_model::write(&intruder, Format::Json, ExportMode::Redacted).unwrap();
    fs::write(&path, data.as_bytes()).unwrap();
    assert!(matches!(store.save(&user), Err(Error::NameCollision(_))));
    assert_eq!(read_user_file(&path).unwrap().summary().full_name, "Intruder");
}

#[test]
fn the_embedded_full_name_is_authoritative() {
    let tmp = TempDir::new("embedded");
    let store = UserStore::open(tmp.path()).unwrap();
    let (user, _) = unlocked(NAME);
    let path = store.save(&user).unwrap();
    fs::rename(&path, tmp.path().join("Mallory.mpjson")).unwrap();
    let listing = store.list().unwrap();
    assert_eq!(listing.users.len(), 1);
    assert_eq!(listing.users[0].summary.full_name, NAME);
    assert!(store.load_locked("Mallory").is_err());
    assert_eq!(store.load_locked(NAME).unwrap(), user);
}

#[test]
fn symlinks_are_never_followed() {
    let tmp = TempDir::new("symlink");
    let outside = TempDir::new("outside");
    let store = UserStore::open(tmp.path()).unwrap();
    let (user, _) = unlocked(NAME);

    // A symlink to a user file outside the store is not listed or loaded.
    let target = outside.path().join("victim.mpjson");
    fs::write(&target, fixture("c-redacted.mpjson")).unwrap();
    symlink(&target, tmp.path().join("link.mpjson")).unwrap();
    assert!(store.list().unwrap().users.is_empty());
    assert!(matches!(store.load_locked(NAME), Err(Error::UserNotFound)));

    // Saving over a symlink at the canonical path is refused; the target is untouched.
    symlink(&target, store.path_for(NAME)).unwrap();
    assert!(matches!(store.save(&user), Err(Error::UnsafePath(_))));
    assert_eq!(fs::read(&target).unwrap(), fixture("c-redacted.mpjson"));
    assert!(matches!(read_user_file(&store.path_for(NAME)), Err(Error::UnsafePath(_))));
}

#[test]
fn legacy_files_are_listed_and_migrated() {
    let tmp = TempDir::new("legacy");
    let store = UserStore::open(tmp.path()).unwrap();
    fs::write(tmp.path().join("Robert Lee Mitchell.mpsites"), fixture("flat1-redacted.mpsites")).unwrap();
    fs::write(tmp.path().join("notes.txt"), "not a user").unwrap();
    fs::write(tmp.path().join("broken.mpjson"), "{").unwrap();
    let listing = store.list().unwrap();
    assert_eq!(listing.users.len(), 1);
    assert_eq!(listing.unreadable.len(), 1);
    let mut keys = robert();
    let user = store.load(NAME, &mut keys).unwrap();
    assert_eq!(user.site_password(&mut keys, "personal.example").unwrap().as_str(), PERSONAL_PW);
    store.save(&user).unwrap();
    let mut expected = vec!["broken.mpjson".to_owned(), "notes.txt".into(), format!("{}.mpjson", encode_name(NAME))];
    expected.sort();
    assert_eq!(files(tmp.path()), expected);
    assert_eq!(store.list().unwrap().users.len(), 1);
}

#[test]
fn delete_removes_every_file_of_the_user() {
    let tmp = TempDir::new("delete");
    let store = UserStore::open(tmp.path()).unwrap();
    let (user, _) = unlocked(NAME);
    store.save(&user).unwrap();
    fs::write(tmp.path().join("old copy.mpsites"), fixture("flat1-redacted.mpsites")).unwrap();
    store.delete(NAME).unwrap();
    assert!(files(tmp.path()).is_empty());
    assert!(matches!(store.delete(NAME), Err(Error::UserNotFound)));
}

#[test]
fn import_new_replace_and_merge() {
    let tmp = TempDir::new("import");
    let store = UserStore::open(tmp.path()).unwrap();

    // Import as a new user.
    let mut keys = robert();
    let imported = read_user_file(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/c-redacted.mpjson"))
        .unwrap()
        .load(&mut keys)
        .unwrap();
    store.create(&imported).unwrap();

    // Merge a second file (different master password) into it.
    let mut other = robert_other();
    let mut second = User::new(NAME).unwrap();
    second.authenticate(&mut other).unwrap();
    second.add_site("from-other.example").unwrap();
    second.set_site_password(&mut other, "from-other.example", ResultType::StatefulPersonal, "x1").unwrap();
    let mut existing_keys = robert();
    let (merged, summary) = store.merge_into(&second, &mut other, &mut existing_keys).unwrap();
    assert_eq!(summary.added, ["from-other.example"]);
    assert_eq!(merged.key_id().unwrap().as_str(), KEY_ID);
    let reloaded = store.load(NAME, &mut existing_keys).unwrap();
    assert_eq!(reloaded.site_password(&mut existing_keys, "from-other.example").unwrap().as_str(), "x1");

    // Replace it wholesale.
    store.save(&second).unwrap();
    assert!(matches!(store.load(NAME, &mut robert()), Err(Error::WrongMasterPassword)));
    assert_eq!(store.load(NAME, &mut robert_other()).unwrap(), second);
}

#[test]
fn export_to_any_path() {
    let tmp = TempDir::new("export");
    let (mut user, mut keys) = unlocked(NAME);
    user.set_site_password(&mut keys, MPA, ResultType::StatefulPersonal, "exported").unwrap();
    let redacted = tmp.path().join("robert.mpsites");
    let revealed = tmp.path().join("robert.mpjson");
    export_to(&redacted, &user, Format::Flat, ExportMode::Redacted).unwrap();
    export_to(&revealed, &user, Format::Json, ExportMode::Revealed(&mut keys)).unwrap();
    assert_eq!((mode(&redacted), mode(&revealed)), (0o600, 0o600));
    assert!(!fs::read_to_string(&redacted).unwrap().contains("exported"));
    assert!(fs::read_to_string(&revealed).unwrap().contains("exported"));
    let back = read_user_file(&revealed).unwrap().load(&mut keys).unwrap();
    assert_eq!(back.site_password(&mut keys, MPA).unwrap().as_str(), "exported");
    assert_eq!(Format::from_path(&redacted), Some(Format::Flat));
}

#[test]
fn oversized_files_are_not_read() {
    let tmp = TempDir::new("big");
    let path = tmp.path().join("big.mpjson");
    let f = fs::File::create(&path).unwrap();
    f.set_len(mpw_model::limits::MAX_FILE_SIZE as u64 + 1).unwrap();
    assert!(matches!(read_user_file(&path), Err(Error::Parse(_))));
    let store = UserStore::open(tmp.path()).unwrap();
    assert_eq!(store.list().unwrap().unreadable.len(), 1);
}

#[test]
fn default_dir_comes_from_home() {
    let dir = UserStore::default_dir().unwrap();
    assert!(dir.ends_with("Library/Application Support/MasterPwd/Users"));
}
