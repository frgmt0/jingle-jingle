//! Rendering for human and `--json` modes. This module only ever receives
//! `EntryView` and other secret-free data — it has no access to secret values.

use serde_json::json;

use crate::model::{EntryView, REDACTED};
use crate::redact;

/// A simple confirmation: human prose or `{"ok":true,...}` JSON.
pub fn ok(json_mode: bool, quiet: bool, human: &str, extra: serde_json::Value) {
    if json_mode {
        let mut obj = json!({ "ok": true });
        if let (Some(base), Some(add)) = (obj.as_object_mut(), extra.as_object()) {
            for (k, v) in add {
                base.insert(k.clone(), v.clone());
            }
        }
        println!("{obj}");
    } else if !quiet {
        println!("{human}");
    }
}

pub fn error(json_mode: bool, err: &crate::Error) {
    if json_mode {
        let payload = json!({
            "error": { "code": err.code_str(), "message": err.to_string() }
        });
        eprintln!("{payload}");
    } else {
        eprintln!("jingle: {err}");
    }
}

pub fn entry_list(json_mode: bool, views: &[EntryView]) {
    if json_mode {
        let sanitized: Vec<serde_json::Value> = views.iter().map(view_json).collect();
        println!("{}", json!({ "entries": sanitized }));
        return;
    }
    if views.is_empty() {
        println!("(no entries)");
        return;
    }
    for v in views {
        let lock = if v.locked { " [locked]" } else { "" };
        let fields = if v.secret_fields.is_empty() {
            "-".to_owned()
        } else {
            v.secret_fields.join(",")
        };
        println!(
            "{}{}  service={}  user={}  secrets={}",
            redact::sanitize(&v.name),
            lock,
            redact::sanitize(&v.service),
            v.username
                .as_deref()
                .map(redact::sanitize)
                .unwrap_or_else(|| "-".into()),
            fields
        );
    }
}

pub fn entry_detail(json_mode: bool, v: &EntryView) {
    if json_mode {
        println!("{}", view_json(v));
        return;
    }
    println!("name:     {}", redact::sanitize(&v.name));
    println!("service:  {}", redact::sanitize(&v.service));
    if let Some(u) = &v.username {
        println!("username: {}", redact::sanitize(u));
    }
    if let Some(u) = &v.url {
        println!("url:      {}", redact::sanitize(u));
    }
    if !v.tags.is_empty() {
        let tags: Vec<String> = v.tags.iter().map(|t| redact::sanitize(t)).collect();
        println!("tags:     {}", tags.join(", "));
    }
    println!("locked:   {}", if v.locked { "yes" } else { "no" });
    println!("created:  {}", v.created_at);
    println!("updated:  {}", v.updated_at);
    if v.secret_fields.is_empty() {
        println!("secrets:  (none)");
    } else {
        let fields: Vec<String> = v
            .secret_fields
            .iter()
            .map(|f| format!("{f}={REDACTED}"))
            .collect();
        println!("secrets:  {}", fields.join("  "));
    }
    if let Some(notes) = &v.notes {
        println!("{}", redact::frame_untrusted("notes", notes));
    }
}

/// JSON rendering of a view, with metadata sanitized (JSON escaping already
/// neuters raw control bytes, but we scrub anyway so downstream consumers
/// that unescape don't re-introduce terminal escapes).
fn view_json(v: &EntryView) -> serde_json::Value {
    json!({
        "name": redact::sanitize(&v.name),
        "service": redact::sanitize(&v.service),
        "username": v.username.as_deref().map(redact::sanitize),
        "url": v.url.as_deref().map(redact::sanitize),
        "notes_untrusted": v.notes.as_deref().map(|n| redact::sanitize_with(n, true)),
        "tags": v.tags.iter().map(|t| redact::sanitize(t)).collect::<Vec<_>>(),
        "locked": v.locked,
        "created_at": v.created_at,
        "updated_at": v.updated_at,
        "secret_fields": v.secret_fields,
    })
}
