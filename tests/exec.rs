mod common;

use common::TestVault;
use predicates::prelude::*;

#[test]
fn injects_secret_into_child_env() {
    let tv = TestVault::new();
    tv.add_with_secret("github", "sup3r-s3cret-value");
    let outfile = tv.dir.path().join("dump.txt");
    let shell = TestVault::dump_env_command("GH_PASS", &outfile.display().to_string());

    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "github=GH_PASS", "--"]);
    cmd.args(&shell);
    cmd.assert().success();

    let dumped = std::fs::read_to_string(&outfile).unwrap();
    assert_eq!(dumped.trim(), "sup3r-s3cret-value");
}

#[test]
fn maps_specific_fields() {
    let tv = TestVault::new();
    tv.add_with_secret("acct", "the-password");
    tv.cmd()
        .args(["set", "acct", "api_key", "--stdin"])
        .write_stdin("the-api-key")
        .assert()
        .success();

    let outfile = tv.dir.path().join("dump.txt");
    let shell = TestVault::dump_env_command("K", &outfile.display().to_string());
    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "acct:api_key=K", "--"]);
    cmd.args(&shell);
    cmd.assert().success();
    assert_eq!(
        std::fs::read_to_string(&outfile).unwrap().trim(),
        "the-api-key"
    );
}

#[cfg(unix)]
#[test]
fn scrubs_jingle_env_from_child() {
    let tv = TestVault::new();
    tv.add_with_secret("e", "s");
    let outfile = tv.dir.path().join("dump.txt");
    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "e=SECRET", "--", "sh", "-c"]);
    cmd.arg(format!(
        "printf %s \"[$JINGLE_KEYFILE][$JINGLE_DATA_DIR]\" > \"{}\"",
        outfile.display()
    ));
    cmd.assert().success();
    assert_eq!(std::fs::read_to_string(&outfile).unwrap(), "[][]");
}

#[cfg(unix)]
#[test]
fn propagates_child_exit_code() {
    let tv = TestVault::new();
    tv.add_with_secret("e", "s");
    tv.cmd()
        .args(["exec", "-s", "e=S", "--", "sh", "-c", "exit 7"])
        .assert()
        .code(7);
}

#[test]
fn refuses_env_collision_without_allow_overwrite() {
    let tv = TestVault::new();
    tv.add_with_secret("e", "s");
    let outfile = tv.dir.path().join("dump.txt");
    let shell = TestVault::dump_env_command("COLLIDE", &outfile.display().to_string());

    let mut cmd = tv.cmd();
    cmd.env("COLLIDE", "pre-existing");
    cmd.args(["exec", "-s", "e=COLLIDE", "--"]);
    cmd.args(&shell);
    cmd.assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("--allow-overwrite"));

    let mut cmd = tv.cmd();
    cmd.env("COLLIDE", "pre-existing");
    cmd.args(["exec", "--allow-overwrite", "-s", "e=COLLIDE", "--"]);
    cmd.args(&shell);
    cmd.assert().success();
    assert_eq!(std::fs::read_to_string(&outfile).unwrap().trim(), "s");
}

#[test]
fn locked_entries_refuse_and_confirm() {
    let tv = TestVault::new();
    tv.add_with_secret("prod", "prod-secret");
    tv.cmd().args(["lock", "prod"]).assert().success();

    let outfile = tv.dir.path().join("dump.txt");
    let shell = TestVault::dump_env_command("P", &outfile.display().to_string());

    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "prod=P", "--"]);
    cmd.args(&shell);
    cmd.assert()
        .failure()
        .code(5)
        .stderr(predicate::str::contains("locked"));
    assert!(!outfile.exists(), "child must not run on refusal");

    // Confirmation must repeat the exact name; a different name doesn't count.
    let mut cmd = tv.cmd();
    cmd.args(["exec", "--confirm-locked", "other", "-s", "prod=P", "--"]);
    cmd.args(&shell);
    cmd.assert().failure().code(5);

    let mut cmd = tv.cmd();
    cmd.args(["exec", "--confirm-locked", "prod", "-s", "prod=P", "--"]);
    cmd.args(&shell);
    cmd.assert().success();
    assert_eq!(
        std::fs::read_to_string(&outfile).unwrap().trim(),
        "prod-secret"
    );
}

#[test]
fn unknown_entry_or_field_is_exit_3() {
    let tv = TestVault::new();
    tv.add_with_secret("known", "s");
    let shell = TestVault::dump_env_command("X", "unused.txt");

    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "missing=X", "--"]);
    cmd.args(&shell);
    cmd.assert().failure().code(3);

    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "known:no_such_field=X", "--"]);
    cmd.args(&shell);
    cmd.assert().failure().code(3);
}

#[test]
fn bad_mapping_specs_are_usage_errors() {
    let tv = TestVault::new();
    tv.add_with_secret("e", "s");
    for bad in ["no-equals", "e=lower_case", "e=1STARTS_DIGIT", "=X", "e="] {
        let mut cmd = tv.cmd();
        cmd.args(["exec", "-s", bad, "--", "true"]);
        cmd.assert().failure().code(2);
    }
    // Duplicate env var target.
    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "e=SAME", "-s", "e=SAME", "--", "true"]);
    cmd.assert().failure().code(2);
}
