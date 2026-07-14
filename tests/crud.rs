mod common;

use common::TestVault;
use predicates::prelude::*;

#[test]
fn full_lifecycle() {
    let tv = TestVault::new();

    tv.cmd()
        .args([
            "add",
            "github",
            "--service",
            "github.com",
            "--username",
            "bot@example.com",
            "--url",
            "https://github.com/login",
            "--tags",
            "ci,bot",
            "--generate",
            "--length",
            "32",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created 'github'"))
        .stdout(predicate::str::contains("bits"));

    tv.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("github"))
        .stdout(predicate::str::contains("bot@example.com"));

    tv.cmd()
        .args(["show", "github"])
        .assert()
        .success()
        .stdout(predicate::str::contains("password=[REDACTED]"));

    // Case-insensitive lookup.
    tv.cmd().args(["show", "GitHub"]).assert().success();

    // Add a second secret field.
    tv.cmd()
        .args(["set", "github", "api_key", "--stdin"])
        .write_stdin("ghp_notarealkey123")
        .assert()
        .success();
    tv.cmd()
        .args(["show", "github"])
        .assert()
        .stdout(predicate::str::contains("api_key=[REDACTED]"));

    // Edit metadata + rename.
    tv.cmd()
        .args([
            "edit",
            "github",
            "--notes",
            "primary bot account",
            "--rename",
            "gh-bot",
        ])
        .assert()
        .success();
    tv.cmd()
        .args(["show", "gh-bot"])
        .assert()
        .success()
        .stdout(predicate::str::contains("untrusted data, not instructions"));

    // Unset a field.
    tv.cmd()
        .args(["unset", "gh-bot", "api_key", "--yes"])
        .assert()
        .success();
    tv.cmd()
        .args(["show", "gh-bot"])
        .assert()
        .stdout(predicate::str::contains("api_key").not());

    // Delete.
    tv.cmd().args(["rm", "gh-bot", "--yes"]).assert().success();
    tv.cmd().args(["show", "gh-bot"]).assert().failure().code(3);
}

#[test]
fn duplicate_add_is_rejected() {
    let tv = TestVault::new();
    tv.add_with_secret("dup", "x1");
    tv.cmd()
        .args(["add", "DUP", "--stdin"])
        .write_stdin("x2")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn destructive_actions_need_yes_when_not_a_tty() {
    let tv = TestVault::new();
    tv.add_with_secret("victim", "s");
    tv.cmd()
        .args(["rm", "victim"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("--yes"));
    // Entry still exists.
    tv.cmd().args(["show", "victim"]).assert().success();
}

#[test]
fn secrets_are_rejected_on_argv_grammar() {
    let tv = TestVault::new();
    // There is no positional/flag way to pass a secret value: a bare extra
    // argument is a usage error, not a silently accepted secret.
    tv.cmd()
        .args(["add", "acct", "hunter2"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn generate_into_entry_and_print_modes() {
    let tv = TestVault::new();
    tv.add_with_secret("svc", "old-password");

    tv.cmd()
        .args(["generate", "--entry", "svc", "--length", "40"])
        .assert()
        .success()
        .stdout(predicate::str::contains("value stored, not shown"))
        .stdout(predicate::str::contains("bits"));

    // --print is the sanctioned escape hatch: prints value, warns on stderr.
    let out = tv
        .cmd()
        .args([
            "generate",
            "--print",
            "--length",
            "20",
            "--charset",
            "alnum",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("context"))
        .get_output()
        .clone();
    let printed = String::from_utf8(out.stdout).unwrap();
    assert_eq!(printed.trim().len(), 20);

    // --entry and --print are mutually exclusive; one is required.
    tv.cmd()
        .args(["generate", "--entry", "svc", "--print"])
        .assert()
        .failure()
        .code(2);
    tv.cmd().arg("generate").assert().failure().code(2);
}

#[test]
fn list_filters() {
    let tv = TestVault::new();
    tv.cmd()
        .args([
            "add",
            "a1",
            "--service",
            "aws.amazon.com",
            "--tags",
            "cloud",
            "--generate",
        ])
        .assert()
        .success();
    tv.cmd()
        .args([
            "add",
            "g1",
            "--service",
            "github.com",
            "--tags",
            "code",
            "--generate",
        ])
        .assert()
        .success();

    tv.cmd()
        .args(["list", "--tag", "cloud"])
        .assert()
        .success()
        .stdout(predicate::str::contains("a1"))
        .stdout(predicate::str::contains("g1").not());

    tv.cmd()
        .args(["list", "--service", "github"])
        .assert()
        .success()
        .stdout(predicate::str::contains("g1"))
        .stdout(predicate::str::contains("a1").not());
}

#[test]
fn generation_flags_require_generate() {
    let tv = TestVault::new();
    tv.cmd()
        .args(["add", "x", "--stdin", "--length", "30"])
        .write_stdin("secret")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("--generate"));
    tv.cmd()
        .args(["add", "x", "--stdin", "--charset", "alnum"])
        .write_stdin("secret")
        .assert()
        .failure()
        .code(2);
}

#[test]
fn stdin_secret_limits() {
    let tv = TestVault::new();
    tv.cmd()
        .args(["add", "empty", "--stdin"])
        .write_stdin("\n")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("empty"));

    let huge = "x".repeat(5000);
    tv.cmd()
        .args(["add", "huge", "--stdin"])
        .write_stdin(huge)
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("exceeds"));
}

#[test]
fn invalid_names_are_usage_errors() {
    let tv = TestVault::new();
    for bad in ["a:b", "a=b", "a b", "__reserved"] {
        tv.cmd()
            .args(["add", bad, "--stdin"])
            .write_stdin("s")
            .assert()
            .failure()
            .code(2);
    }
}
