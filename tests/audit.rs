mod common;

use common::TestVault;
use predicates::prelude::*;

#[cfg(unix)]
fn true_cmd() -> Vec<&'static str> {
    vec!["sh", "-c", "true"]
}

#[cfg(windows)]
fn true_cmd() -> Vec<&'static str> {
    vec!["cmd", "/C", "exit 0"]
}

#[test]
fn every_egress_and_refusal_is_recorded() {
    let tv = TestVault::new();
    tv.add_with_secret("gh", "s");

    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "gh=S", "--"]);
    cmd.args(true_cmd());
    cmd.assert().success();

    tv.cmd().args(["lock", "gh"]).assert().success();
    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "gh=S", "--"]);
    cmd.args(true_cmd());
    cmd.assert().failure().code(5);

    let audit = std::fs::read_to_string(tv.audit_path()).unwrap();
    assert!(audit.contains("\"cmd\":\"init\""));
    assert!(audit.contains("\"cmd\":\"exec\""));
    assert!(audit.contains("\"outcome\":\"ok\""));
    assert!(audit.contains("\"outcome\":\"refused_locked\""));
    assert!(audit.contains("\"cmd\":\"lock\""));

    // Chain verifies end to end.
    tv.cmd()
        .args(["audit"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hash chain: OK"));
}

#[test]
fn failed_lookups_are_recorded() {
    let tv = TestVault::new();
    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "ghost=S", "--"]);
    cmd.args(true_cmd());
    cmd.assert().failure().code(3);

    let audit = std::fs::read_to_string(tv.audit_path()).unwrap();
    assert!(audit.contains("\"entry\":\"ghost\""));
    assert!(audit.contains("\"outcome\":\"not_found\""));
}

#[test]
fn burst_tripwire_warns_on_bulk_access() {
    let tv = TestVault::new();
    for i in 0..6 {
        tv.add_with_secret(&format!("acct{i}"), "s");
    }

    // Access 5 distinct entries: quiet.
    for i in 0..5 {
        let mut cmd = tv.cmd();
        cmd.args(["exec", "-s", &format!("acct{i}=S"), "--"]);
        cmd.args(true_cmd());
        cmd.assert()
            .success()
            .stderr(predicate::str::contains("WARNING").not());
    }
    // The 6th distinct entry within the window trips the wire.
    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "acct5=S", "--"]);
    cmd.args(true_cmd());
    cmd.assert()
        .success()
        .stderr(predicate::str::contains("distinct entries"));

    let audit = std::fs::read_to_string(tv.audit_path()).unwrap();
    assert!(audit.contains("burst_warning"));
}

#[test]
fn audit_json_reports_records() {
    let tv = TestVault::new();
    tv.add_with_secret("e", "s");
    let out = tv
        .cmd()
        .args(["audit", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["chain_ok"], serde_json::Value::Bool(true));
    assert!(!v["records"].as_array().unwrap().is_empty());
}
