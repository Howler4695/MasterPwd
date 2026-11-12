//! End-to-end tests of the `mpw` binary against known vectors
//! (`mpw-core/tests/mpw_tests.xml`).  The master password is always fed via
//! stdin or a file descriptor, never via arguments.  Every invocation gets a
//! fresh, empty `HOME`, so these behave as first runs (see `persistence.rs`
//! for the user-file tests).

use std::io::Write;
use std::process::{Command, Output, Stdio};

const MPW: &str = env!("CARGO_BIN_EXE_mpw");
const NAME: &str = "Robert Lee Mitchell";
const PASSWORD: &str = "banana colored duckling";
const SITE: &str = "masterpasswordapp.com";

/// A fresh, empty home directory under cargo's per-target temp dir.
fn fresh_home() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "cli-home-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn command() -> Command {
    let mut cmd = Command::new(MPW);
    for var in ["MPW_FULLNAME", "MPW_ALGORITHM", "MPW_FORMAT", "MPW_ASKPASS"] {
        cmd.env_remove(var);
    }
    cmd.env("HOME", fresh_home());
    cmd
}

fn run_with_stdin(mut cmd: Command, stdin: &str) -> Output {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn mpw");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// `mpw -u NAME <args> SITE` with the password on stdin.
fn mpw(args: &[&str]) -> Output {
    let mut cmd = command();
    cmd.arg("-u").arg(NAME).args(args).arg(SITE);
    run_with_stdin(cmd, &format!("{PASSWORD}\n"))
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8(o.stderr.clone()).unwrap()
}

#[track_caller]
fn assert_result(o: &Output, expected: &str) {
    assert!(
        o.status.success(),
        "status {:?}, stderr: {}",
        o.status,
        stderr(o)
    );
    assert_eq!(stdout(o), format!("{expected}\n"), "stderr: {}", stderr(o));
}

#[test]
fn default_long_password_from_stdin() {
    let o = mpw(&[]);
    assert_result(&o, "Jejr5[RepuSosp");
    // Prompt, summary and identicon go to stderr (no colour: not a terminal).
    let err = stderr(&o);
    assert!(err.contains("Your master password:"), "{err}");
    assert!(
        err.contains("Robert Lee Mitchell's password for masterpasswordapp.com:\n[ ╚☻╯⛄ ]: "),
        "{err}"
    );
    assert!(!err.contains(PASSWORD), "password must never be echoed");
}

#[test]
fn types_counters_and_versions() {
    let cases: &[(&[&str], &str)] = &[
        (&["-t", "x"], "W6@692^B1#&@gVdSdLZ@"),
        (&["-tmedium"], "Jej2$Quv"),
        (&["-t", "b"], "WAo2xIg6"),
        (&["-t", "s"], "Jej2"),
        (&["-t", "i"], "7662"),
        (&["-t", "n"], "jejraquvo"),
        (&["-t", "p"], "jejr quv cabsibu tam"),
        (&["-c", "4294967295"], "XambHoqo6[Peni"),
        (&["-c", "0xFFFFFFFF"], "XambHoqo6[Peni"),
        (&["-a", "0"], "Feji5@ReduWosh"),
        (&["-a0", "-tx"], "w1!3bA3icmRAc)SS@lwl"),
        (&["-a", "0", "-c", "4294967295"], "QateDojh1@Hecn"),
        (&["-p", "i"], "wohzaqage"),
        (&["-p", "rec"], "xin diyjiqoja hubu"),
        (&["-p", "r", "-C", "question"], "xogx tem cegyiva jab"),
        (
            &["-a", "0", "-p", "r", "-C", "question"],
            "movm bex gevrica jaf",
        ),
    ];
    for (args, expected) in cases {
        let o = mpw(args);
        assert!(o.status.success(), "{args:?}: {}", stderr(&o));
        assert_eq!(stdout(&o), format!("{expected}\n"), "{args:?}");
    }
}

#[test]
fn environment_variables() {
    let mut cmd = command();
    cmd.env("MPW_FULLNAME", NAME)
        .env("MPW_ALGORITHM", "0")
        .arg(SITE);
    assert_result(
        &run_with_stdin(cmd, &format!("{PASSWORD}\n")),
        "Feji5@ReduWosh",
    );

    // -a beats MPW_ALGORITHM, -u beats MPW_FULLNAME.
    let mut cmd = command();
    cmd.env("MPW_FULLNAME", "Someone Else")
        .env("MPW_ALGORITHM", "0")
        .args(["-u", NAME, "-a", "3", SITE]);
    assert_result(
        &run_with_stdin(cmd, &format!("{PASSWORD}\n")),
        "Jejr5[RepuSosp",
    );
}

#[test]
fn everything_prompted_on_stdin() {
    let o = run_with_stdin(command(), &format!("{NAME}\n{PASSWORD}\n{SITE}\n"));
    assert_result(&o, "Jejr5[RepuSosp");
    let err = stderr(&o);
    assert!(
        err.contains("Your full name:") && err.contains("Site name:"),
        "{err}"
    );
}

#[test]
fn unicode_inputs() {
    // v3_mb_fullName / v3_mb_siteName / v3_mb_masterPassword
    let mut cmd = command();
    cmd.args(["-u", "⛄", SITE]);
    assert_result(
        &run_with_stdin(cmd, &format!("{PASSWORD}\n")),
        "NopaDajh8=Fene",
    );

    let mut cmd = command();
    cmd.args(["-u", NAME, "⛄"]);
    assert_result(
        &run_with_stdin(cmd, &format!("{PASSWORD}\n")),
        "LiheCuwhSerz6)",
    );

    let mut cmd = command();
    cmd.args(["-u", NAME, SITE]);
    assert_result(&run_with_stdin(cmd, "⛄\n"), "QesuHirv5-Xepl");
}

#[test]
fn password_from_fd_zero_is_used_verbatim() {
    let mut cmd = command();
    cmd.args(["-u", NAME, "-m", "0", SITE]);
    assert_result(&run_with_stdin(cmd, PASSWORD), "Jejr5[RepuSosp");

    // Like the reference, -m uses the exact bytes: a trailing newline is part
    // of the password (so the result differs).
    let mut cmd = command();
    cmd.args(["-u", NAME, "-m", "0", SITE]);
    let o = run_with_stdin(cmd, &format!("{PASSWORD}\n"));
    assert!(o.status.success());
    assert_ne!(stdout(&o), "Jejr5[RepuSosp\n");
}

#[test]
fn password_from_another_fd() {
    // fd 3 is the pipe, stdin is /dev/null.
    let o = Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"printf %s "$3" | "$0" -u "$1" -m 3 "$2" 3<&0 </dev/null"#)
        .args([MPW, NAME, SITE, PASSWORD])
        .env_remove("MPW_FULLNAME")
        .env_remove("MPW_ALGORITHM")
        .env_remove("MPW_FORMAT")
        .env("HOME", fresh_home())
        .output()
        .unwrap();
    assert_result(&o, "Jejr5[RepuSosp");
    assert!(
        !stderr(&o).contains("Your master password"),
        "no prompt needed"
    );
}

#[test]
fn personal_password_state_and_derived_key() {
    let o = mpw(&["-t", "P", "-P", "hunter2"]);
    assert_result(&o, "hunter2");
    assert!(
        stderr(&o).contains("(state) q7EPkUsq6BtkK0/cX/pqzA== => "),
        "{}",
        stderr(&o)
    );

    let o = mpw(&["-t", "K", "-P", "256"]);
    assert_result(&o, "TCFYP7cKH8FQ8WYwILAlSfqAcz14K0yPGYV3sBvuyQA=");

    // Without -P (and nothing stored) the value is asked for; here stdin has
    // nothing left after the master password.
    let o = mpw(&["-t", "P"]);
    assert_eq!(o.status.code(), Some(65));
    assert!(
        stderr(&o).contains("Missing personal password."),
        "{}",
        stderr(&o)
    );
    assert!(o.stdout.is_empty());

    // ... and read from stdin (not a terminal) after the master password.
    let mut cmd = command();
    cmd.args(["-u", NAME, "-t", "P", SITE]);
    let o = run_with_stdin(cmd, &format!("{PASSWORD}\nhunter2\n"));
    assert_result(&o, "hunter2");
    let err = stderr(&o);
    assert!(err.contains("Your personal password: "), "{err}");
    assert!(
        err.contains("(state) q7EPkUsq6BtkK0/cX/pqzA== => "),
        "{err}"
    );
    assert!(
        !err.contains("visible to other users"),
        "no -P, no warning: {err}"
    );

    // `-P -` asks for the value, too (no warning).
    let mut cmd = command();
    cmd.args(["-u", NAME, "-t", "P", "-P", "-", SITE]);
    let o = run_with_stdin(cmd, &format!("{PASSWORD}\nhunter2\n"));
    assert_result(&o, "hunter2");
    assert!(
        !stderr(&o).contains("visible to other users"),
        "{}",
        stderr(&o)
    );

    // -P still works, with a warning.
    let o = mpw(&["-t", "P", "-P", "hunter2"]);
    assert!(
        stderr(&o).contains("visible to other users (ps)"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn quiet_mode_prints_only_the_result() {
    let mut cmd = command();
    cmd.args(["-q", "-u", NAME, "-m", "0", SITE]);
    let o = run_with_stdin(cmd, PASSWORD);
    assert_result(&o, "Jejr5[RepuSosp");
    assert_eq!(stderr(&o), "");
}

#[test]
fn verbose_mode_does_not_leak_secrets() {
    let o = mpw(&["-v", "-t", "P", "-P", "hunter2"]);
    assert_result(&o, "hunter2");
    let err = stderr(&o);
    assert!(err.contains("resultParam      : (given)"), "{err}");
    assert!(!err.contains(PASSWORD));
    assert!(!err.contains("hunter2"), "{err}");
}

#[test]
fn master_password_argument_is_refused() {
    let o = command()
        .args(["-u", NAME, "-M", PASSWORD, SITE])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(64));
    assert!(o.stdout.is_empty());
    assert!(!stderr(&o).contains(PASSWORD));
}

#[test]
fn usage_errors() {
    let cases: &[(&[&str], i32)] = &[
        (&["-c", "abc"], 64),
        (&["-c", "-1"], 64),
        (&["-c", "4294967296"], 64),
        (&["-a", "4"], 64),
        (&["-a", "x"], 64),
        (&["-t", "nope"], 64),
        (&["-p", "nope"], 65),
        (&["-F", "xml"], 65),
        (&["-Z"], 64),
        (&["extra-site"], 64),
    ];
    for (args, code) in cases {
        let o = mpw(args);
        assert_eq!(o.status.code(), Some(*code), "{args:?}: {}", stderr(&o));
        assert!(o.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn missing_input_is_a_data_error() {
    let mut cmd = command();
    cmd.args(["-u", NAME, SITE]);
    let o = run_with_stdin(cmd, "");
    assert_eq!(o.status.code(), Some(65));
    assert!(stderr(&o).contains("Missing master password."));

    let o = run_with_stdin(command(), "");
    assert_eq!(o.status.code(), Some(65));
    assert!(stderr(&o).contains("Missing full name."));
}

#[test]
fn help() {
    let o = command().arg("-h").stdin(Stdio::null()).output().unwrap();
    assert!(o.status.success());
    assert!(o.stdout.is_empty());
    assert!(stderr(&o).contains("USAGE"));
}
