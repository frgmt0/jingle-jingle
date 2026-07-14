mod common;

use common::TestVault;
use predicates::prelude::*;

#[test]
fn export_import_roundtrip() {
    let tv = TestVault::new();
    tv.add_with_secret("keep", "kept-secret");
    tv.add_with_secret("temp", "temp-secret");

    let backup = tv.dir.path().join("backup.jingle");
    tv.cmd()
        .args(["export", "--output"])
        .arg(&backup)
        .assert()
        .success()
        .stdout(predicate::str::contains("encrypted"));

    // The export is ciphertext: no plaintext inside.
    let raw = std::fs::read(&backup).unwrap();
    assert!(!raw.windows(11).any(|w| w == b"kept-secret"));

    tv.cmd().args(["rm", "temp", "--yes"]).assert().success();
    tv.cmd()
        .args(["import"])
        .arg(&backup)
        .assert()
        .success()
        .stdout(predicate::str::contains("1 added"))
        .stdout(predicate::str::contains("1 skipped"));

    tv.cmd().args(["show", "temp"]).assert().success();

    // Re-import without --overwrite skips; with it, replaces.
    tv.cmd()
        .args(["import", "--overwrite"])
        .arg(&backup)
        .assert()
        .success()
        .stdout(predicate::str::contains("2 replaced"));
}

#[test]
fn import_with_wrong_key_fails() {
    let tv = TestVault::new();
    tv.add_with_secret("a", "s");
    let backup = tv.dir.path().join("backup.jingle");
    tv.cmd()
        .args(["export", "--output"])
        .arg(&backup)
        .assert()
        .success();

    let other = TestVault::new();
    other
        .cmd()
        .args(["import"])
        .arg(&backup)
        .assert()
        .failure()
        .code(4);
}

#[test]
fn there_is_no_plaintext_export_flag() {
    let tv = TestVault::new();
    tv.add_with_secret("a", "s");
    // Any hypothetical "--plaintext"/"--include-secrets" flag must not exist.
    for flag in ["--plaintext", "--include-secrets", "--reveal", "--decrypt"] {
        tv.cmd()
            .args(["export", flag, "--output", "x.out"])
            .assert()
            .failure()
            .code(2);
    }
}
