//! Users with the opt-in second factor: the CLI's recovery-code path.

use mpw_model::{
    AlgorithmVersion, ExportMode, Format, KeyPurpose, MasterKey, RecoveryCode, ResultType,
    SecondSecret, Slot, SlotKind, User, UserKeys,
};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const MPW: &str = env!("CARGO_BIN_EXE_mpw");
const NAME: &str = "Robert Lee Mitchell";
const PASSWORD: &str = "banana colored duckling";
const SITE: &str = "masterpasswordapp.com";
/// The recovery code of the pinned secret 00 01 .. 13 (mpw-model's vector).
const CODE: &str = "000G4-0R40M-30E20-9185G-R38E1-W8124-GKQ4P";

fn pinned() -> SecondSecret {
    SecondSecret::from_bytes(&(0u8..20).collect::<Vec<_>>()).unwrap()
}

/// Generated password of SITE for an effective master password.
fn expected(effective: &str) -> String {
    MasterKey::derive(NAME, effective, AlgorithmVersion::V3)
        .unwrap()
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
}

struct Home(PathBuf);

impl Home {
    /// A HOME with a second-factor user in `~/.mpw.d`, written by mpw-model.
    fn with_second_factor_user() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "sf-home-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir.join(".mpw.d"))
            .unwrap();
        let home = Self(dir);

        let mut keys = UserKeys::from_password(NAME, PASSWORD);
        let mut user = User::new(NAME).unwrap();
        user.authenticate(&mut keys).unwrap();
        user.add_site(SITE).unwrap();
        user.add_site("personal.example").unwrap();
        user.set_site_password(
            &mut keys,
            "personal.example",
            ResultType::StatefulPersonal,
            "my personal pw",
        )
        .unwrap();
        let wrapped = pinned().as_bytes().iter().map(|b| b ^ 7).collect();
        let slot = Slot::new(
            SlotKind::SmartCard,
            "Card 7",
            &"07".repeat(32),
            "test-xor",
            wrapped,
        )
        .unwrap();
        user.enable_second_factor(PASSWORD, &pinned(), vec![slot], RecoveryCode::NotConfirmed)
            .unwrap();
        mpw_model::export_to(&home.json(), &user, Format::Json, ExportMode::Storage).unwrap();
        fs::set_permissions(home.json(), fs::Permissions::from_mode(0o600)).unwrap();
        home
    }

    fn json(&self) -> PathBuf {
        self.0.join(".mpw.d").join(format!("{NAME}.mpjson"))
    }

    /// `mpw <args>` with `stdin`; `code` (if any) is supplied on fd 3 (`-k 3`).
    fn run(&self, args: &[&str], stdin: &str, code: Option<&str>) -> Output {
        let mut cmd = match code {
            Some(code) => {
                let mut c = Command::new("/bin/sh");
                // "$0" is mpw, "$1" the code, the rest are mpw's arguments.
                c.arg("-c")
                    .arg("code=$1; shift; exec \"$0\" -k 3 \"$@\" 3<<END\n$code\nEND\n")
                    .arg(MPW)
                    .arg(code);
                c
            }
            None => Command::new(MPW),
        };
        for var in ["MPW_FULLNAME", "MPW_ALGORITHM", "MPW_FORMAT", "MPW_ASKPASS"] {
            cmd.env_remove(var);
        }
        cmd.env("HOME", &self.0)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[track_caller]
fn ok(o: &Output, expected: &str) {
    assert!(
        o.status.success(),
        "status {:?}, stderr: {}",
        o.status,
        stderr(o)
    );
    assert_eq!(stdout(o), format!("{expected}\n"), "stderr: {}", stderr(o));
}

#[track_caller]
fn fails(o: &Output, code: i32, message: &str) {
    assert_eq!(o.status.code(), Some(code), "stderr: {}", stderr(o));
    assert!(
        stderr(o).contains(message),
        "expected {message:?} in: {}",
        stderr(o)
    );
    assert!(o.stdout.is_empty());
}

/// The `"second_factor": {...}` member, verbatim.
fn member(json: &str) -> String {
    let start = json
        .find("\"second_factor\"")
        .expect("second_factor member");
    let open = start + json[start..].find('{').unwrap();
    let mut depth = 0;
    for (i, c) in json[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return json[start..=open + i].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced member")
}

fn pw(line: &str) -> String {
    format!("{line}\n")
}

#[test]
fn code_on_the_dedicated_fd() {
    let home = Home::with_second_factor_user();
    let before = member(&fs::read_to_string(home.json()).unwrap());
    let o = home.run(&["-u", NAME, SITE], &pw(PASSWORD), Some(CODE));
    ok(&o, &expected(&format!("{PASSWORD} {CODE}")));
    assert!(
        stderr(&o).contains("This user has a second factor"),
        "{}",
        stderr(&o)
    );
    assert!(!stderr(&o).contains(CODE), "the code is never echoed");
    // Normalised: lower case, no dashes, surrounding whitespace.
    let sloppy = format!("  {}  ", CODE.replace('-', "").to_lowercase());
    ok(
        &home.run(
            &["-u", NAME, "personal.example"],
            &pw(PASSWORD),
            Some(&sloppy),
        ),
        "my personal pw",
    );
    // Slots survive the CLI's saves byte for byte.
    assert_eq!(member(&fs::read_to_string(home.json()).unwrap()), before);
}

#[test]
fn combined_form_still_works() {
    let home = Home::with_second_factor_user();
    let o = home.run(
        &["-u", NAME, SITE],
        &pw(&format!("{PASSWORD} {CODE}")),
        None,
    );
    ok(&o, &expected(&format!("{PASSWORD} {CODE}")));
    // The trailing code is normalised like a separately given one.
    let lower = format!("{PASSWORD} {}", CODE.to_lowercase());
    ok(
        &home.run(&["-u", NAME, SITE], &pw(&lower), None),
        &expected(&format!("{PASSWORD} {CODE}")),
    );
}

#[test]
fn code_errors_are_distinct_and_change_nothing() {
    let home = Home::with_second_factor_user();
    let before = fs::read(home.json()).unwrap();
    let mistyped = CODE.replacen('Q', "R", 1);
    let foreign = SecondSecret::from_bytes(&[0xA5; 20])
        .unwrap()
        .recovery_code()
        .to_string();

    // Missing: not a terminal, no -k, no code in the password.
    fails(
        &home.run(&["-u", NAME, SITE], &pw(PASSWORD), None),
        66,
        "the recovery code is needed",
    );
    fails(
        &home.run(&["-u", NAME, SITE], &pw(PASSWORD), Some("\n")),
        66,
        "the recovery code is needed",
    );
    // Mistyped (checksum), on the fd and in the combined form.
    fails(
        &home.run(&["-u", NAME, SITE], &pw(PASSWORD), Some(&mistyped)),
        67,
        "mistyped",
    );
    fails(
        &home.run(
            &["-u", NAME, SITE],
            &pw(&format!("{PASSWORD} {mistyped}")),
            None,
        ),
        67,
        "mistyped",
    );
    fails(
        &home.run(&["-u", NAME, SITE], &pw(PASSWORD), Some("ABCDE")),
        67,
        "should have 35",
    );
    // Valid but another user's code.
    fails(
        &home.run(&["-u", NAME, SITE], &pw(PASSWORD), Some(&foreign)),
        77,
        "does not belong to this user",
    );
    fails(
        &home.run(
            &["-u", NAME, SITE],
            &pw(&format!("{PASSWORD} {foreign}")),
            None,
        ),
        77,
        "does not belong to this user",
    );
    // Right code, wrong password: a wrong master password, explained.
    let o = home.run(&["-u", NAME, SITE], &pw("not the password"), Some(CODE));
    fails(&o, 65, "Incorrect master password");
    assert!(
        stderr(&o).contains("recovery code was accepted"),
        "{}",
        stderr(&o)
    );
    assert!(stderr(&o).contains("-k fd"), "{}", stderr(&o));

    assert_eq!(fs::read(home.json()).unwrap(), before);
    for e in fs::read_dir(home.0.join(".mpw.d")).unwrap() {
        let name = e.unwrap().file_name().into_string().unwrap();
        assert_eq!(name, format!("{NAME}.mpjson"), "nothing else was written");
    }
}

#[test]
fn capital_u_keeps_the_second_factor() {
    let home = Home::with_second_factor_user();
    let before = member(&fs::read_to_string(home.json()).unwrap());
    let new = "a new password";

    // New typed password on stdin, then the old one at the "Old master password" prompt.
    let o = home.run(
        &["-U", NAME, "personal.example"],
        &format!("{new}\n{PASSWORD}\n"),
        Some(CODE),
    );
    ok(&o, "my personal pw");
    assert!(
        stderr(&o).contains("the second factor is unchanged"),
        "{}",
        stderr(&o)
    );
    assert_eq!(
        member(&fs::read_to_string(home.json()).unwrap()),
        before,
        "same secret, same slots"
    );

    ok(
        &home.run(&["-u", NAME, SITE], &pw(new), Some(CODE)),
        &expected(&format!("{new} {CODE}")),
    );
    ok(
        &home.run(&["-u", NAME, "personal.example"], &pw(new), Some(CODE)),
        "my personal pw",
    );
    fails(
        &home.run(&["-u", NAME, SITE], &pw(PASSWORD), Some(CODE)),
        65,
        "Incorrect master password",
    );

    // A wrong old password changes nothing.
    let file = fs::read(home.json()).unwrap();
    let o = home.run(&["-U", NAME, SITE], "third\nnot it\n", Some(CODE));
    assert_eq!(o.status.code(), Some(65), "{}", stderr(&o));
    assert_eq!(fs::read(home.json()).unwrap(), file);
}

#[test]
fn flat_save_is_refused() {
    let home = Home::with_second_factor_user();
    let before = fs::read(home.json()).unwrap();
    let flat = home.0.join(".mpw.d").join(format!("{NAME}.mpsites"));

    // -F flat next to the second-factor JSON user: refused, nothing derived or written.
    let o = home.run(&["-u", NAME, "-F", "flat", SITE], &pw(PASSWORD), Some(CODE));
    fails(&o, 64, "flat format cannot store");
    assert!(stderr(&o).contains("-F json"), "{}", stderr(&o));
    assert!(!flat.exists());
    assert_eq!(fs::read(home.json()).unwrap(), before);

    // The user itself read through -F flat (a JSON file under a flat name) is
    // not written back as flat either.
    fs::rename(home.json(), &flat).unwrap();
    let o = home.run(&["-u", NAME, "-F", "flat", SITE], &pw(PASSWORD), Some(CODE));
    fails(&o, 64, "flat format cannot store");
    assert_eq!(fs::read(&flat).unwrap(), before);

    // -f flat (not fixed) reads it and saves JSON: fine, slots kept.
    let o = home.run(&["-u", NAME, "-f", "flat", SITE], &pw(PASSWORD), Some(CODE));
    ok(&o, &expected(&format!("{PASSWORD} {CODE}")));
    assert_eq!(
        member(&fs::read_to_string(home.json()).unwrap()),
        member(&String::from_utf8(before).unwrap())
    );
}

#[test]
fn unreadable_second_factor_is_kept_and_unlocks_with_the_code() {
    let home = Home::with_second_factor_user();
    // A newer version of the member: unreadable here, must survive untouched.
    let text = fs::read_to_string(home.json()).unwrap();
    let text = text.replacen("\"version\": 1", "\"version\": 99", 1);
    fs::write(home.json(), &text).unwrap();
    let before = member(&text);
    assert!(before.contains("99"));

    let o = home.run(&["-u", NAME, SITE], &pw(PASSWORD), Some(CODE));
    ok(&o, &expected(&format!("{PASSWORD} {CODE}")));
    assert!(
        stderr(&o).contains("newer version or damaged"),
        "{}",
        stderr(&o)
    );
    assert_eq!(member(&fs::read_to_string(home.json()).unwrap()), before);
    // Without a pre-check, a foreign code shows up as a wrong master password.
    let foreign = SecondSecret::from_bytes(&[0xA5; 20])
        .unwrap()
        .recovery_code()
        .to_string();
    fails(
        &home.run(&["-u", NAME, SITE], &pw(PASSWORD), Some(&foreign)),
        65,
        "Incorrect master password",
    );
}

#[test]
fn stateless_mode_takes_the_combined_form() {
    let home = Home::with_second_factor_user();
    let before = fs::read(home.json()).unwrap();
    let o = home.run(
        &["-u", NAME, "-F", "none", SITE],
        &pw(&format!("{PASSWORD} {CODE}")),
        None,
    );
    ok(&o, &expected(&format!("{PASSWORD} {CODE}")));
    assert_eq!(fs::read(home.json()).unwrap(), before);
}
