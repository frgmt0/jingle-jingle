mod common;

use common::TestVault;
use predicates::prelude::*;

#[test]
fn corrupt_vault_is_a_clean_exit_4() {
    let tv = TestVault::new();
    tv.add_with_secret("e", "secret");

    let mut raw = std::fs::read(tv.vault_path()).unwrap();
    let mid = raw.len() / 2;
    raw[mid] ^= 0xFF;
    std::fs::write(tv.vault_path(), &raw).unwrap();

    tv.cmd()
        .args(["show", "e"])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("integrity"));
}

#[test]
fn truncated_vault_is_exit_4() {
    let tv = TestVault::new();
    tv.add_with_secret("e", "secret");
    let raw = std::fs::read(tv.vault_path()).unwrap();
    std::fs::write(tv.vault_path(), &raw[..10]).unwrap();
    tv.cmd().args(["list"]).assert().failure().code(4);
}

#[test]
fn wrong_magic_is_exit_4() {
    let tv = TestVault::new();
    std::fs::write(tv.vault_path(), b"not a vault at all, definitely").unwrap();
    tv.cmd().args(["list"]).assert().failure().code(4);
}

#[test]
fn wrong_keyfile_is_exit_4() {
    let tv = TestVault::new();
    tv.add_with_secret("e", "secret");
    // Replace the keyfile with fresh random bytes.
    let other = TestVault::new();
    std::fs::copy(other.keyfile_path(), tv.keyfile_path()).unwrap();
    tv.cmd().args(["list"]).assert().failure().code(4).stderr(
        predicate::str::contains("wrong keyfile").or(predicate::str::contains("integrity")),
    );
}

#[test]
fn tamper_events_are_audited() {
    let tv = TestVault::new();
    tv.add_with_secret("e", "secret");
    let mut raw = std::fs::read(tv.vault_path()).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    std::fs::write(tv.vault_path(), &raw).unwrap();
    tv.cmd().args(["list"]).assert().failure().code(4);

    let audit = std::fs::read_to_string(tv.audit_path()).unwrap();
    assert!(audit.contains("\"outcome\":\"tamper\""));
}

#[test]
fn backup_survives_a_corrupted_primary() {
    let tv = TestVault::new();
    tv.add_with_secret("first", "s1");
    tv.add_with_secret("second", "s2"); // second save: .bak now holds gen-1
    std::fs::write(tv.vault_path(), b"garbage").unwrap();

    // Recovery: point --vault at the backup.
    tv.cmd()
        .args(["list", "--vault"])
        .arg(tv.backup_path())
        .assert()
        .success()
        .stdout(predicate::str::contains("first"));
}

#[test]
fn edited_audit_log_is_flagged() {
    let tv = TestVault::new();
    tv.add_with_secret("e", "s");
    tv.cmd().args(["lock", "e"]).assert().success();
    tv.cmd().args(["unlock", "e", "--yes"]).assert().success();

    // Remove a middle line from the log.
    let content = std::fs::read_to_string(tv.audit_path()).unwrap();
    let mut lines: Vec<&str> = content.lines().collect();
    assert!(lines.len() >= 3);
    lines.remove(1);
    std::fs::write(tv.audit_path(), format!("{}\n", lines.join("\n"))).unwrap();

    tv.cmd()
        .args(["audit"])
        .assert()
        .success()
        .stdout(predicate::str::contains("BROKEN"))
        .stderr(predicate::str::contains("edited or truncated"));

    let out = tv
        .cmd()
        .args(["audit", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["chain_ok"], serde_json::Value::Bool(false));
}
