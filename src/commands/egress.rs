//! Secret egress: `exec` (env injection), `copy` (clipboard), `totp`.
//! Every access — granted or refused — is written to the audit log.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::process::Command;

use serde_json::json;
use sha2::{Digest, Sha256};

use crate::commands::Ctx;
use crate::model::Entry;
use crate::{Error, Result, output, redact, totp as totp_mod};

/// Env var used to hand the expected-value hash to the detached
/// `__clear-clipboard` helper. An env var (not argv) because /proc/pid/cmdline
/// is world-readable on Linux while environ is same-user only.
pub const CLEAR_HASH_ENV: &str = "JINGLE_CLEAR_HASH";

struct Mapping {
    entry: String,
    field: String,
    env_var: String,
}

fn parse_mapping(spec: &str) -> Result<Mapping> {
    let (reference, env_var) = spec.split_once('=').ok_or_else(|| {
        Error::Usage(format!(
            "invalid --secret '{}': expected REF=ENVVAR (e.g. github=GH_PASS or github:api_key=GH_KEY)",
            redact::sanitize(spec)
        ))
    })?;
    let (entry, field) = match reference.split_once(':') {
        Some((e, f)) => (e, f),
        None => (reference, "password"),
    };
    if entry.is_empty() || field.is_empty() {
        return Err(Error::Usage(format!(
            "invalid --secret '{}': empty entry or field",
            redact::sanitize(spec)
        )));
    }
    let valid_env = !env_var.is_empty()
        && !env_var.as_bytes()[0].is_ascii_digit()
        && env_var
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if !valid_env {
        return Err(Error::Usage(format!(
            "invalid environment variable name '{}': use [A-Z_][A-Z0-9_]*",
            redact::sanitize(env_var)
        )));
    }
    Ok(Mapping {
        entry: entry.to_owned(),
        field: field.to_owned(),
        env_var: env_var.to_owned(),
    })
}

/// Locked-entry gate. `--confirm-locked` must repeat the exact (case-sensitive)
/// entry name: deliberate friction that an injected "run it again with the
/// bypass flag" instruction has to reproduce precisely, and which always
/// leaves an audit trail (the refusal is recorded by the caller).
fn check_locked(entry: &Entry, confirm_locked: &[String]) -> Result<()> {
    if entry.locked && !confirm_locked.iter().any(|n| n == &entry.name) {
        return Err(Error::Locked(redact::sanitize(&entry.name)));
    }
    Ok(())
}

fn warn_burst(fired: Option<usize>) {
    if let Some(n) = fired {
        eprintln!(
            "jingle: WARNING: secrets from {n} distinct entries were accessed within the last 60s — \
if you did not intend a bulk access, inspect `jingle audit` (possible prompt-injection/exfiltration)"
        );
    }
}

/// Audit a refused/failed egress attempt, then return the error.
fn audited_failure(ctx: &Ctx, entry: Option<&str>, field: Option<&str>, err: Error) -> Error {
    let _ = ctx
        .audit()
        .append(ctx.cmd_label, entry, field, err.audit_outcome(), None);
    err
}

pub fn exec(
    ctx: &Ctx,
    specs: &[String],
    confirm_locked: &[String],
    no_inherit_env: bool,
    allow_overwrite: bool,
    command: &[OsString],
) -> Result<i32> {
    let mappings: Vec<Mapping> = specs
        .iter()
        .map(|s| parse_mapping(s))
        .collect::<Result<_>>()?;

    {
        let mut seen = std::collections::BTreeSet::new();
        for m in &mappings {
            if !seen.insert(&m.env_var) {
                return Err(Error::Usage(format!(
                    "environment variable {} is mapped more than once",
                    m.env_var
                )));
            }
        }
    }

    let vault = ctx.load_vault()?;

    // Resolve and authorize every mapping BEFORE building the child env, so a
    // refusal never launches a partially injected process.
    let mut resolved: Vec<(&Mapping, &Entry)> = Vec::with_capacity(mappings.len());
    for m in &mappings {
        let entry = vault
            .find(&m.entry)
            .map_err(|e| audited_failure(ctx, Some(&m.entry), Some(&m.field), e))?;
        check_locked(entry, confirm_locked)
            .map_err(|e| audited_failure(ctx, Some(&m.entry), Some(&m.field), e))?;
        entry
            .secret(&m.field)
            .map_err(|e| audited_failure(ctx, Some(&m.entry), Some(&m.field), e))?;
        resolved.push((m, entry));
    }

    // Child env: parent env minus every JINGLE_* variable (so the child can't
    // discover the keyfile/vault location), or a minimal env with
    // --no-inherit-env; then the requested mappings.
    let mut env: BTreeMap<OsString, OsString> = BTreeMap::new();
    if no_inherit_env {
        for keep in ["PATH", "HOME", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT"] {
            if let Some(v) = std::env::var_os(keep) {
                env.insert(keep.into(), v);
            }
        }
    } else {
        for (k, v) in std::env::vars_os() {
            let name = k.to_string_lossy();
            if name.starts_with("JINGLE_") {
                continue;
            }
            env.insert(k, v);
        }
    }

    for (m, entry) in &resolved {
        let var: OsString = m.env_var.clone().into();
        if env.contains_key(&var) && !allow_overwrite {
            return Err(Error::Usage(format!(
                "environment variable {} already exists; pass --allow-overwrite to replace it",
                m.env_var
            )));
        }
        env.insert(var, entry.secret(&m.field)?.expose().into());
    }

    // Record each grant. Done before spawn: the access decision is made.
    for (m, entry) in &resolved {
        let fired = ctx
            .audit()
            .record_egress("exec", &entry.name, Some(&m.field), entry.locked)?;
        warn_burst(fired);
    }

    let program = &command[0];
    let status = Command::new(program)
        .args(&command[1..])
        .env_clear()
        .envs(&env)
        .status()
        .map_err(|e| Error::Other(format!("failed to run {}: {e}", program.to_string_lossy())))?;

    Ok(exit_code_of(status))
}

#[cfg(unix)]
fn exit_code_of(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}

#[cfg(not(unix))]
fn exit_code_of(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

pub fn copy(
    ctx: &Ctx,
    name: &str,
    field: &str,
    clear_after: u64,
    confirm_locked: &[String],
) -> Result<()> {
    let vault = ctx.load_vault()?;
    let entry = vault
        .find(name)
        .map_err(|e| audited_failure(ctx, Some(name), Some(field), e))?;
    check_locked(entry, confirm_locked)
        .map_err(|e| audited_failure(ctx, Some(name), Some(field), e))?;
    let secret = entry
        .secret(field)
        .map_err(|e| audited_failure(ctx, Some(name), Some(field), e))?;

    let mut clipboard = arboard::Clipboard::new().map_err(|e| Error::Clipboard(e.to_string()))?;
    clipboard
        .set_text(secret.expose().to_owned())
        .map_err(|e| Error::Clipboard(e.to_string()))?;

    let fired = ctx
        .audit()
        .record_egress("copy", &entry.name, Some(field), entry.locked)?;
    warn_burst(fired);

    let mut cleared_note = String::from("auto-clear disabled");
    if clear_after > 0 {
        match spawn_clear_helper(secret.expose(), clear_after) {
            Ok(()) => cleared_note = format!("clears in {clear_after}s"),
            Err(e) => {
                eprintln!("jingle: warning: could not schedule clipboard auto-clear: {e}");
                cleared_note = "auto-clear FAILED to schedule".into();
            }
        }
    }

    let display_name = redact::sanitize(&entry.name);
    output::ok(
        ctx.json,
        ctx.quiet,
        &format!("Copied {field} of '{display_name}' to the clipboard ({cleared_note})"),
        json!({
            "name": display_name,
            "field": field,
            "clear_after": if clear_after > 0 { Some(clear_after) } else { None },
        }),
    );
    Ok(())
}

/// Re-launch ourselves detached; the helper clears the clipboard only if it
/// still holds the value we set (compared by SHA-256 carried in the env).
fn spawn_clear_helper(secret: &str, after: u64) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let hash: String = Sha256::digest(secret.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut cmd = Command::new(exe);
    cmd.arg("__clear-clipboard")
        .arg("--after")
        .arg(after.to_string())
        .env(CLEAR_HASH_ENV, hash)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NO_WINDOW
        cmd.creation_flags(0x0000_0008 | 0x0800_0000);
    }
    cmd.spawn()?;
    Ok(())
}

/// The hidden helper: sleep, then clear the clipboard iff it still holds the
/// value whose hash we were given.
pub fn clear_clipboard(after: u64) -> Result<()> {
    let expected = std::env::var(CLEAR_HASH_ENV)
        .map_err(|_| Error::Usage("missing clear-hash environment".into()))?;
    std::thread::sleep(std::time::Duration::from_secs(after));
    let mut clipboard = arboard::Clipboard::new().map_err(|e| Error::Clipboard(e.to_string()))?;
    let current = clipboard.get_text().unwrap_or_default();
    let current_hash: String = Sha256::digest(current.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if current_hash == expected {
        clipboard
            .clear()
            .map_err(|e| Error::Clipboard(e.to_string()))?;
        // On X11 the clipboard lives in the setting process; give the owner
        // change a moment to propagate before exiting.
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Ok(())
}

pub fn totp(ctx: &Ctx, name: &str, confirm_locked: &[String]) -> Result<()> {
    let vault = ctx.load_vault()?;
    let entry = vault
        .find(name)
        .map_err(|e| audited_failure(ctx, Some(name), Some("totp"), e))?;
    check_locked(entry, confirm_locked)
        .map_err(|e| audited_failure(ctx, Some(name), Some("totp"), e))?;
    let seed = entry
        .secret("totp")
        .map_err(|e| audited_failure(ctx, Some(name), Some("totp"), e))?;

    let (code, remaining) = totp_mod::code_now(seed)?;

    let fired = ctx
        .audit()
        .record_egress("totp", &entry.name, Some("totp"), entry.locked)?;
    warn_burst(fired);

    // Sanctioned egress: the code is dead in <=30 seconds; the seed never prints.
    if ctx.json {
        println!("{}", json!({ "code": code, "expires_in": remaining }));
    } else {
        println!("{code} ({remaining}s remaining)");
    }
    Ok(())
}
