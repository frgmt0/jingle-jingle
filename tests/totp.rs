mod common;

use common::TestVault;
use predicates::prelude::*;

const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn setup() -> TestVault {
    let tv = TestVault::new();
    tv.add_with_secret("gh", "password-value");
    tv.cmd()
        .args(["set", "gh", "totp", "--stdin"])
        .write_stdin(SEED)
        .assert()
        .success();
    tv
}

#[test]
fn prints_current_code_never_the_seed() {
    let tv = setup();
    let out = tv
        .cmd()
        .args(["totp", "gh"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let code = stdout.split_whitespace().next().unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert!(stdout.contains("remaining"));
    assert!(!stdout.contains(SEED));
}

#[test]
fn json_mode() {
    let tv = setup();
    let out = tv
        .cmd()
        .args(["totp", "gh", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["code"].as_str().unwrap().len(), 6);
    let expires = v["expires_in"].as_u64().unwrap();
    assert!((1..=30).contains(&expires));
}

#[test]
fn accepts_otpauth_uri_on_stdin() {
    let tv = TestVault::new();
    tv.add_with_secret("svc", "pw");
    tv.cmd()
        .args(["set", "svc", "totp", "--stdin"])
        .write_stdin(format!(
            "otpauth://totp/Example:bot@example.com?secret={SEED}&issuer=Example"
        ))
        .assert()
        .success();
    tv.cmd().args(["totp", "svc"]).assert().success();
}

#[test]
fn rejects_invalid_seed_and_generate() {
    let tv = TestVault::new();
    tv.add_with_secret("svc", "pw");
    tv.cmd()
        .args(["set", "svc", "totp", "--stdin"])
        .write_stdin("this is not base32!!")
        .assert()
        .failure()
        .code(2);
    tv.cmd()
        .args(["set", "svc", "totp", "--generate"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("--stdin"));
}

#[test]
fn entry_without_totp_is_exit_3() {
    let tv = TestVault::new();
    tv.add_with_secret("nototp", "pw");
    tv.cmd()
        .args(["totp", "nototp"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("totp"));
}

#[test]
fn locked_entry_refuses_totp() {
    let tv = setup();
    tv.cmd().args(["lock", "gh"]).assert().success();
    tv.cmd().args(["totp", "gh"]).assert().failure().code(5);
    tv.cmd()
        .args(["totp", "gh", "--confirm-locked", "gh"])
        .assert()
        .success();
}
