//! User-file persistence (`~/.mpw.d`), with `HOME` pointed at a temp dir.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const MPW: &str = env!("CARGO_BIN_EXE_mpw");
const NAME: &str = "Robert Lee Mitchell";
const PASSWORD: &str = "banana colored duckling";
const OTHER_PASSWORD: &str = "⛄";
const SITE: &str = "masterpasswordapp.com";
const KEY_ID: &str = "98EEF4D1DF46D849574A82A03C3177056B15DFFCA29BB3899DE4628453675302";

struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "persist-home-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn mpw_d(&self) -> PathBuf {
        self.0.join(".mpw.d")
    }

    fn file(&self, name: &str) -> PathBuf {
        self.mpw_d().join(name)
    }

    /// Run `mpw <args>` with `stdin`.
    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut cmd = Command::new(MPW);
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

    /// `mpw -u NAME <args>` with the right master password on stdin.
    fn mpw(&self, args: &[&str]) -> Output {
        let mut all = vec!["-u", NAME];
        all.extend_from_slice(args);
        self.run(&all, &format!("{PASSWORD}\n"))
    }

    /// Every path under HOME, relative.
    fn tree(&self) -> Vec<String> {
        fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
            for e in fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                out.push(p.strip_prefix(base).unwrap().display().to_string());
                if fs::symlink_metadata(&p).unwrap().is_dir() {
                    walk(base, &p, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.0, &self.0, &mut out);
        out.sort();
        out
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

fn json_path(home: &Home) -> PathBuf {
    home.file(&format!("{NAME}.mpjson"))
}

#[test]
fn first_run_creates_the_file_second_run_verifies() {
    let home = Home::new();
    ok(&home.mpw(&[SITE]), "Jejr5[RepuSosp");
    let path = json_path(&home);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains(KEY_ID), "{text}");
    assert!(text.contains("\"redacted\": true"), "{text}");
    assert!(
        !text.contains("Jejr5[RepuSosp"),
        "redacted files hold no generated passwords"
    );

    // Second run: verified against the stored key ID; uses are counted.
    ok(&home.mpw(&[SITE]), "Jejr5[RepuSosp");
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"uses\": 2"), "{text}");
}

#[test]
fn wrong_password_leaves_the_file_byte_identical() {
    let home = Home::new();
    ok(
        &home.mpw(&["-t", "P", "-P", "my personal pw", "personal.example"]),
        "my personal pw",
    );
    let path = json_path(&home);
    let before = fs::read(&path).unwrap();
    let mtime = fs::metadata(&path).unwrap().modified().unwrap();
    let tree = home.tree();

    for args in [
        vec!["-u", NAME, SITE],
        vec!["-u", NAME, "-t", "x", "-c", "9", SITE],
    ] {
        let o = home.run(&args, &format!("{OTHER_PASSWORD}\n"));
        assert_eq!(o.status.code(), Some(65), "{}", stderr(&o));
        assert!(o.stdout.is_empty());
        assert!(stderr(&o).contains("Incorrect master password according to configuration"));
    }
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), mtime);
    assert_eq!(home.tree(), tree, "no temp files left behind");
}

#[test]
fn saved_type_counter_and_state_are_reused() {
    let home = Home::new();
    // v3_type_pin with counter 4 / a personal password / an algorithm.
    let pin4 = stdout(&home.mpw(&["-t", "i", "-c", "4", "pin.example"]));
    ok(&home.mpw(&["pin.example"]), pin4.trim_end());
    assert_ne!(pin4, stdout(&home.mpw(&["-c", "1", "pin.example"])));
    // -c 1 was persisted too.
    let pin1 = stdout(&home.mpw(&["pin.example"]));
    assert_ne!(pin4, pin1);

    ok(
        &home.mpw(&["-t", "P", "-P", "my personal pw", "personal.example"]),
        "my personal pw",
    );
    // No -P, nothing on stdin after the master password: the stored value is used.
    let o = home.mpw(&["personal.example"]);
    ok(&o, "my personal pw");
    assert!(!stderr(&o).contains("Your personal password"));

    ok(&home.mpw(&["-a", "0", SITE]), "Feji5@ReduWosh");
    ok(&home.mpw(&[SITE]), "Feji5@ReduWosh");
    ok(&home.mpw(&["-a", "3", SITE]), "Jejr5[RepuSosp");

    // Logins and answers: types persisted per site / question.
    ok(&home.mpw(&["-p", "i", SITE]), "wohzaqage");
    ok(
        &home.mpw(&["-p", "r", "-C", "question", SITE]),
        "xogx tem cegyiva jab",
    );
    ok(&home.mpw(&["-p", "r", SITE]), "xin diyjiqoja hubu");
    let text = fs::read_to_string(json_path(&home)).unwrap();
    assert!(text.contains("\"question\""), "{text}");

    // A personal login name, prompted on stdin (not a terminal).
    let o = home.run(
        &["-u", NAME, "-p", "i", "-t", "P", SITE],
        &format!("{PASSWORD}\nrobert@example.com\n"),
    );
    ok(&o, "robert@example.com");
    ok(&home.mpw(&["-p", "i", SITE]), "robert@example.com");

    // A derived key is not persisted as the site's type.
    ok(
        &home.mpw(&["-t", "K", "-P", "256", SITE]),
        "TCFYP7cKH8FQ8WYwILAlSfqAcz14K0yPGYV3sBvuyQA=",
    );
    ok(&home.mpw(&[SITE]), "Jejr5[RepuSosp");
}

#[test]
fn revealed_only_on_explicit_request() {
    let home = Home::new();
    ok(
        &home.mpw(&["-t", "P", "-P", "my personal pw", "personal.example"]),
        "my personal pw",
    );
    let path = json_path(&home);
    assert!(!fs::read_to_string(&path)
        .unwrap()
        .contains("my personal pw"));

    // -R 1 is redacted, too.
    ok(&home.mpw(&["-R", "1", SITE]), "Jejr5[RepuSosp");
    assert!(!fs::read_to_string(&path)
        .unwrap()
        .contains("Jejr5[RepuSosp"));

    // -R 0: clear text, with a warning.
    let o = home.mpw(&["-R", "0", SITE]);
    ok(&o, "Jejr5[RepuSosp");
    assert!(stderr(&o).contains("clear text (-R 0)"), "{}", stderr(&o));
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"redacted\": false"), "{text}");
    assert!(
        text.contains("my personal pw") && text.contains("Jejr5[RepuSosp"),
        "{text}"
    );

    // A revealed file is read fine, and saved redacted again unless -R 0.
    let o = home.mpw(&["personal.example"]);
    ok(&o, "my personal pw");
    assert!(
        stderr(&o).contains("was not redacted; saving it redacted"),
        "{}",
        stderr(&o)
    );
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"redacted\": true"));
    assert!(!text.contains("my personal pw") && !text.contains("Jejr5[RepuSosp"));
}

#[test]
fn file_and_directory_modes() {
    let home = Home::new();
    ok(&home.mpw(&[SITE]), "Jejr5[RepuSosp");
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&home.mpw_d()), 0o700);
    assert_eq!(mode(&json_path(&home)), 0o600);
    ok(&home.mpw(&["-F", "flat", SITE]), "Jejr5[RepuSosp");
    assert_eq!(mode(&home.file(&format!("{NAME}.mpsites"))), 0o600);

    // An existing, looser directory is used but warned about.
    fs::set_permissions(home.mpw_d(), fs::Permissions::from_mode(0o777)).unwrap();
    let o = home.mpw(&[SITE]);
    ok(&o, "Jejr5[RepuSosp");
    assert!(
        stderr(&o).contains("writable by other users"),
        "{}",
        stderr(&o)
    );
    assert_eq!(mode(&json_path(&home)), 0o600);
}

#[test]
fn hostile_full_names_stay_inside_mpw_d() {
    let home = Home::new();
    for (name, file) in [
        ("../../evil", "_._.._evil"),
        ("/etc/passwd", "_etc_passwd"),
        (".hidden", "_hidden"),
        ("..", "_."),
        ("a/b", "a_b"),
    ] {
        let o = home.run(&["-u", name, SITE], &format!("{PASSWORD}\n"));
        assert!(o.status.success(), "{name:?}: {}", stderr(&o));
        let expected = home.file(&format!("{file}.mpjson"));
        let created = fs::read_dir(home.mpw_d())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        assert!(created.iter().all(|f| !f.starts_with('.')), "{created:?}");
        assert!(expected.is_file(), "{name:?}: {created:?}");
    }
    // Nothing outside ~/.mpw.d.
    assert!(
        home.tree()
            .iter()
            .all(|p| p == ".mpw.d" || p.starts_with(".mpw.d/")),
        "{:?}",
        home.tree()
    );

    // "a_b" maps to the same file as "a/b": refused, file untouched.
    let ab = home.file("a_b.mpjson");
    let before = fs::read(&ab).unwrap();
    let o = home.run(&["-u", "a_b", SITE], &format!("{PASSWORD}\n"));
    assert_eq!(o.status.code(), Some(65));
    assert!(
        stderr(&o).contains("belongs to a different full name"),
        "{}",
        stderr(&o)
    );
    assert_eq!(fs::read(&ab).unwrap(), before);

    // Control characters cannot name a file.
    let o = home.run(&["-u", "tab\there", SITE], &format!("{PASSWORD}\n"));
    assert_eq!(o.status.code(), Some(65));
    assert!(o.stdout.is_empty());
}

#[test]
fn symlinks_are_never_followed() {
    let home = Home::new();
    let outside = home.0.join("outside.txt");
    fs::write(&outside, "do not touch").unwrap();

    // A symlinked user file is neither read nor replaced.
    fs::create_dir(home.mpw_d()).unwrap();
    std::os::unix::fs::symlink(&outside, json_path(&home)).unwrap();
    let o = home.mpw(&[SITE]);
    assert_eq!(o.status.code(), Some(65), "{}", stderr(&o));
    assert!(stderr(&o).contains("symlink"));
    assert_eq!(fs::read_to_string(&outside).unwrap(), "do not touch");
    assert!(fs::symlink_metadata(json_path(&home))
        .unwrap()
        .file_type()
        .is_symlink());

    // Same when only the flat file is a symlink and JSON would be written.
    let home = Home::new();
    let outside = home.0.join("outside.txt");
    fs::write(&outside, "do not touch").unwrap();
    fs::create_dir(home.mpw_d()).unwrap();
    std::os::unix::fs::symlink(&outside, home.file(&format!("{NAME}.mpsites"))).unwrap();
    let o = home.mpw(&["-F", "flat", SITE]);
    assert_ne!(o.status.code(), Some(0));
    assert_eq!(fs::read_to_string(&outside).unwrap(), "do not touch");

    // A symlinked ~/.mpw.d is refused.
    let home = Home::new();
    let elsewhere = home.0.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, home.mpw_d()).unwrap();
    let o = home.mpw(&[SITE]);
    assert_eq!(o.status.code(), Some(73), "{}", stderr(&o));
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
}

#[test]
fn format_fallback_and_fixed() {
    let home = Home::new();
    // -F flat: reads and writes only the flat file.
    ok(
        &home.mpw(&["-F", "flat", "-c", "4", "-t", "i", "pin.example"]),
        "2783",
    );
    let flat = home.file(&format!("{NAME}.mpsites"));
    assert!(flat.is_file());
    assert!(!json_path(&home).exists());

    // Default (-f json semantics): JSON not found, falls back to the flat file,
    // takes its settings, writes the default (JSON) format.
    ok(&home.mpw(&["pin.example"]), "2783");
    assert!(json_path(&home).is_file());

    // MPW_FORMAT=flat behaves like -f flat: reads flat first, writes JSON.
    let mut cmd = Command::new(MPW);
    let o = cmd
        .env("HOME", &home.0)
        .env("MPW_FORMAT", "flat")
        .env_remove("MPW_FULLNAME")
        .env_remove("MPW_ALGORITHM")
        .args(["-u", NAME, "-m", "0", "pin.example"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.take().unwrap().write_all(PASSWORD.as_bytes())?;
            c.wait_with_output()
        })
        .unwrap();
    ok(&o, "2783");

    // -F none: no files at all.
    let home = Home::new();
    ok(&home.mpw(&["-F", "none", SITE]), "Jejr5[RepuSosp");
    assert!(home.tree().is_empty(), "{:?}", home.tree());
    // ... but -f none (not fixed) still uses the default file.
    ok(&home.mpw(&["-f", "none", SITE]), "Jejr5[RepuSosp");
    assert!(json_path(&home).is_file());
}

#[test]
fn update_master_password_with_capital_u() {
    let home = Home::new();
    ok(
        &home.mpw(&["-t", "P", "-P", "my personal pw", "personal.example"]),
        "my personal pw",
    );
    ok(&home.mpw(&["-t", "x", SITE]), "W6@692^B1#&@gVdSdLZ@");

    // -U with a new password: confirm the old one (on stdin), then re-keyed.
    let o = home.run(
        &["-U", NAME, "personal.example"],
        &format!("{OTHER_PASSWORD}\n{PASSWORD}\n"),
    );
    ok(&o, "my personal pw");
    assert!(stderr(&o).contains("first confirm the old master password"));

    // The old password is now wrong; the new one works and the settings survived.
    let o = home.mpw(&[SITE]);
    assert_eq!(o.status.code(), Some(65));
    let new = |args: &[&str]| {
        let mut all = vec!["-u", NAME];
        all.extend_from_slice(args);
        home.run(&all, &format!("{OTHER_PASSWORD}\n"))
    };
    ok(&new(&["personal.example"]), "my personal pw");
    let max = stdout(&new(&[SITE]));
    assert_eq!(max.trim_end().len(), 20, "still the maximum type: {max}");

    // -U with a wrong old password changes nothing.
    let before = fs::read(json_path(&home)).unwrap();
    let o = home.run(&["-U", NAME, SITE], "third password\nnot it\n");
    assert_eq!(o.status.code(), Some(65));
    assert_eq!(fs::read(json_path(&home)).unwrap(), before);
}

/// The flat file the reference CLI writes for the same operations, built by
/// hand from `mpw_marshal_write_flat` (dates taken from our file, since they
/// are "now").  Cf. `crates/mpw-model/tests/fixtures/flat1-redacted.mpsites`.
#[test]
fn flat_file_matches_the_reference_layout() {
    let home = Home::new();
    let flat = ["-F", "flat"];
    let run = |args: &[&str]| {
        let mut all = flat.to_vec();
        all.extend_from_slice(args);
        home.mpw(&all)
    };
    ok(&run(&[SITE]), "Jejr5[RepuSosp");
    ok(
        &run(&["-t", "P", "-P", "my personal pw", "personal.example"]),
        "my personal pw",
    );
    ok(&run(&["-t", "i", "-c", "4", "pin.example"]), "2783");
    ok(&run(&["-t", "i", "-c", "4", "pin.example"]), "2783");

    let text = fs::read_to_string(home.file(&format!("{NAME}.mpsites"))).unwrap();
    let date = text
        .lines()
        .find_map(|l| l.strip_prefix("# Date: "))
        .expect("date line")
        .to_owned();
    let site_date = |site: &str| {
        text.lines()
            .find(|l| !l.starts_with('#') && l.contains(site))
            .and_then(|l| l.split_whitespace().next())
            .unwrap()
            .to_owned()
    };
    // `%s  %8ld  %8s  %25s\t%25s\t%s`
    let line = |site: &str, uses: u32, kind: &str, login: &str, pw: &str| {
        format!(
            "{}  {uses:>8}  {kind:>8}  {login:>25}\t{site:>25}\t{pw}\n",
            site_date(site)
        )
    };
    let expected = format!(
        "# Master Password site export\n\
         #     Export of site names and stored passwords (unless device-private) encrypted with the master key.\n\
         # \n\
         ##\n\
         # Format: 1\n\
         # Date: {date}\n\
         # User Name: {NAME}\n\
         # Full Name: {NAME}\n\
         # Avatar: 0\n\
         # Identicon: 2:╚☻╯⛄\n\
         # Key ID: {KEY_ID}\n\
         # Algorithm: 3\n\
         # Default Type: 17\n\
         # Passwords: PROTECTED\n\
         ##\n\
         #\n\
         #               Last     Times  Password                      Login\t                     Site\tSite\n\
         #               used      used      type                       name\t                     name\tpassword\n\
         {}{}{}",
        line(SITE, 1, "17:3:1", "", ""),
        line("personal.example", 1, "1056:3:1", "", "S3thn+F0DS7pzWY1CqfxEw=="),
        line("pin.example", 2, "21:3:4", "", ""),
    );
    assert_eq!(text, expected);

    // The model's own fixture parses back to the same shape of header.
    let fixture = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../mpw-model/tests/fixtures/flat1-redacted.mpsites"),
    )
    .unwrap();
    let header = |t: &str| {
        t.lines()
            .filter(|l| {
                l.starts_with('#') && !l.starts_with("# Date") && !l.starts_with("# Avatar")
            })
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(header(&text), header(&fixture));
}
