//! Entry CRUD: add, set, unset, generate, list, show, rm, edit, lock/unlock.

use serde_json::json;

use crate::cli::SecretSource;
use crate::commands::{Ctx, confirm, obtain_secret};
use crate::model::{Entry, validate_entry_name, validate_field_name};
use crate::{Error, Result, genpass, output, redact, totp};

#[allow(clippy::too_many_arguments)]
pub fn add(
    ctx: &Ctx,
    name: String,
    service: Option<String>,
    username: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
    field: String,
    source: &SecretSource,
) -> Result<()> {
    validate_entry_name(&name)?;
    validate_field_name(&field)?;

    let mut vault = ctx.load_vault()?;
    if vault.contains(&name) {
        return Err(Error::AlreadyExists(redact::sanitize(&name)));
    }

    let (value, bits) = obtain_secret_for_field(&field, source)?;

    let mut entry = Entry::new(name.clone());
    entry.service = service.unwrap_or_else(|| name.clone());
    entry.username = username;
    entry.url = url;
    entry.notes = notes;
    entry.tags = tags.into_iter().filter(|t| !t.is_empty()).collect();
    entry.secrets.insert(field.clone(), value);
    vault.add(entry)?;
    vault.save()?;

    let strength = bits
        .map(|b| format!(", {} bits", b.round() as u64))
        .unwrap_or_default();
    output::ok(
        ctx.json,
        ctx.quiet,
        &format!(
            "Created '{}' ({field} set{strength})",
            redact::sanitize(&name)
        ),
        json!({
            "name": redact::sanitize(&name),
            "field": field,
            "entropy_bits": bits.map(|b| b.round() as u64),
        }),
    );
    Ok(())
}

pub fn set(ctx: &Ctx, name: &str, field: &str, source: &SecretSource) -> Result<()> {
    validate_field_name(field)?;
    let mut vault = ctx.load_vault()?;
    let (value, bits) = obtain_secret_for_field(field, source)?;
    let entry = vault.find_mut(name)?;
    let existed = entry.secrets.insert(field.to_owned(), value).is_some();
    entry.touch();
    let display_name = redact::sanitize(&entry.name);
    vault.save()?;

    let verb = if existed { "Replaced" } else { "Set" };
    let strength = bits
        .map(|b| format!(", {} bits", b.round() as u64))
        .unwrap_or_default();
    output::ok(
        ctx.json,
        ctx.quiet,
        &format!("{verb} {field} on '{display_name}'{strength}"),
        json!({
            "name": display_name,
            "field": field,
            "replaced": existed,
            "entropy_bits": bits.map(|b| b.round() as u64),
        }),
    );
    Ok(())
}

/// Shared source handling with TOTP-specific validation: seeds must be valid
/// base32/otpauth and cannot be "generated" (they come from the service).
fn obtain_secret_for_field(
    field: &str,
    source: &SecretSource,
) -> Result<(crate::model::SecretString, Option<f64>)> {
    if field.eq_ignore_ascii_case("totp") {
        if source.generate {
            return Err(Error::Usage(
                "--generate cannot create a TOTP seed; pipe the service's base32 seed or otpauth:// URI via --stdin".into(),
            ));
        }
        let (raw, _) = obtain_secret(source)?;
        let seed = totp::normalize_seed(raw.expose())?;
        return Ok((seed, None));
    }
    obtain_secret(source)
}

pub fn unset(ctx: &Ctx, name: &str, field: &str, yes: bool) -> Result<()> {
    let mut vault = ctx.load_vault()?;
    let entry = vault.find_mut(name)?;
    if !entry.secrets.contains_key(field) {
        return Err(Error::FieldNotFound {
            entry: redact::sanitize(&entry.name),
            field: redact::sanitize(field),
        });
    }
    let display_name = redact::sanitize(&entry.name);
    confirm(
        &format!("Remove secret field '{field}' from '{display_name}'?"),
        yes,
    )?;
    let entry = vault.find_mut(name)?;
    entry.secrets.remove(field);
    entry.touch();
    vault.save()?;

    output::ok(
        ctx.json,
        ctx.quiet,
        &format!("Removed {field} from '{display_name}'"),
        json!({ "name": display_name, "field": field }),
    );
    Ok(())
}

pub fn generate(
    ctx: &Ctx,
    entry: Option<&str>,
    field: &str,
    print: bool,
    length: usize,
    charset: genpass::Charset,
) -> Result<()> {
    let value = genpass::generate(length, charset)?;
    let bits = genpass::entropy_bits(length, charset).round() as u64;

    if print {
        // The single sanctioned way to print a generated value. The warning
        // goes to stderr so piped stdout stays clean.
        eprintln!(
            "warning: this value is now in your context/transcript; prefer `jingle generate --entry NAME` which stores without showing"
        );
        let _ = ctx.audit().append("generate-print", None, None, "ok", None);
        println!("{}", value.expose());
        return Ok(());
    }

    let name = entry.expect("clap group guarantees --entry when --print is absent");
    validate_field_name(field)?;
    let mut vault = ctx.load_vault()?;
    let e = vault.find_mut(name)?;
    if field.eq_ignore_ascii_case("totp") {
        return Err(Error::Usage(
            "cannot generate a TOTP seed; use `jingle set NAME totp --stdin`".into(),
        ));
    }
    let existed = e.secrets.insert(field.to_owned(), value).is_some();
    e.touch();
    let display_name = redact::sanitize(&e.name);
    vault.save()?;

    let verb = if existed { "Replaced" } else { "Set" };
    output::ok(
        ctx.json,
        ctx.quiet,
        &format!("{verb} {field} on '{display_name}' ({bits} bits); value stored, not shown"),
        json!({
            "name": display_name,
            "field": field,
            "replaced": existed,
            "entropy_bits": bits,
        }),
    );
    Ok(())
}

pub fn list(ctx: &Ctx, tag: Option<&str>, service: Option<&str>) -> Result<()> {
    let vault = ctx.load_vault()?;
    let mut views: Vec<_> = vault
        .payload
        .entries
        .iter()
        .filter(|e| tag.is_none_or(|t| e.tags.iter().any(|et| et.eq_ignore_ascii_case(t))))
        .filter(|e| service.is_none_or(|s| e.service.to_lowercase().contains(&s.to_lowercase())))
        .map(Entry::view)
        .collect();
    views.sort_by(|a, b| a.name.cmp(&b.name));
    output::entry_list(ctx.json, &views);
    Ok(())
}

pub fn show(ctx: &Ctx, name: &str) -> Result<()> {
    let vault = ctx.load_vault()?;
    let entry = vault.find(name)?;
    output::entry_detail(ctx.json, &entry.view());
    Ok(())
}

pub fn rm(ctx: &Ctx, name: &str, yes: bool) -> Result<()> {
    let mut vault = ctx.load_vault()?;
    let display_name = redact::sanitize(&vault.find(name)?.name);
    confirm(
        &format!("Delete entry '{display_name}' and all its secrets?"),
        yes,
    )?;
    vault.remove(name)?;
    vault.save()?;
    output::ok(
        ctx.json,
        ctx.quiet,
        &format!("Deleted '{display_name}'"),
        json!({ "name": display_name }),
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn edit(
    ctx: &Ctx,
    name: &str,
    service: Option<String>,
    username: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    tags: Option<Vec<String>>,
    rename: Option<String>,
) -> Result<()> {
    if service.is_none()
        && username.is_none()
        && url.is_none()
        && notes.is_none()
        && tags.is_none()
        && rename.is_none()
    {
        return Err(Error::Usage(
            "nothing to edit: pass at least one of --service/--username/--url/--notes/--tags/--rename".into(),
        ));
    }

    let mut vault = ctx.load_vault()?;
    if let Some(new_name) = &rename {
        validate_entry_name(new_name)?;
        if !new_name.eq_ignore_ascii_case(name) && vault.contains(new_name) {
            return Err(Error::AlreadyExists(redact::sanitize(new_name)));
        }
    }
    let entry = vault.find_mut(name)?;
    if let Some(s) = service {
        entry.service = s;
    }
    if let Some(u) = username {
        entry.username = if u.is_empty() { None } else { Some(u) };
    }
    if let Some(u) = url {
        entry.url = if u.is_empty() { None } else { Some(u) };
    }
    if let Some(n) = notes {
        entry.notes = if n.is_empty() { None } else { Some(n) };
    }
    if let Some(t) = tags {
        entry.tags = t.into_iter().filter(|t| !t.is_empty()).collect();
    }
    if let Some(new_name) = rename {
        entry.name = new_name;
    }
    entry.touch();
    let display_name = redact::sanitize(&entry.name);
    vault.save()?;

    output::ok(
        ctx.json,
        ctx.quiet,
        &format!("Updated '{display_name}'"),
        json!({ "name": display_name }),
    );
    Ok(())
}

pub fn set_locked(ctx: &Ctx, name: &str, locked: bool, yes: bool) -> Result<()> {
    let mut vault = ctx.load_vault()?;
    let display_name = redact::sanitize(&vault.find(name)?.name);
    if !locked {
        confirm(
            &format!(
                "Unlock '{display_name}' (secret egress will no longer require --confirm-locked)?"
            ),
            yes,
        )?;
    }
    let entry = vault.find_mut(name)?;
    entry.locked = locked;
    entry.touch();
    vault.save()?;
    ctx.audit().append(
        if locked { "lock" } else { "unlock" },
        Some(name),
        None,
        "ok",
        Some(locked),
    )?;

    let msg = if locked {
        format!(
            "Locked '{display_name}': exec/copy/totp now require --confirm-locked {display_name}"
        )
    } else {
        format!("Unlocked '{display_name}'")
    };
    output::ok(
        ctx.json,
        ctx.quiet,
        &msg,
        json!({ "name": display_name, "locked": locked }),
    );
    Ok(())
}
