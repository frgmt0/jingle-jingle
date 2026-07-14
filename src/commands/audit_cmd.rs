//! `jingle audit` — display recent records and verify the hash chain.

use serde_json::json;

use crate::commands::Ctx;
use crate::{Result, redact};

pub fn run(ctx: &Ctx, limit: usize) -> Result<()> {
    let log = ctx.audit();
    let records = log.read_records()?;
    let breaks = log.verify()?;
    let chain_ok = breaks.is_empty();

    let start = records.len().saturating_sub(limit);
    let recent = &records[start..];

    if ctx.json {
        let recs: Vec<serde_json::Value> = recent
            .iter()
            .map(|(_, r)| {
                json!({
                    "ts": r.ts,
                    "cmd": r.cmd,
                    "entry": r.entry.as_deref().map(redact::sanitize),
                    "field": r.field,
                    "outcome": r.outcome,
                    "locked": r.locked,
                })
            })
            .collect();
        println!(
            "{}",
            json!({
                "chain_ok": chain_ok,
                "breaks_at": breaks,
                "total_records": records.len(),
                "records": recs,
            })
        );
        return Ok(());
    }

    if records.is_empty() {
        println!("(audit log is empty)");
        return Ok(());
    }
    for (_, r) in recent {
        let entry = r.entry.as_deref().map(redact::sanitize);
        let mut line = format!("{}  {:<14} {:<16}", r.ts, r.cmd, r.outcome);
        if let Some(e) = entry {
            line.push_str(&format!(" entry={e}"));
        }
        if let Some(f) = &r.field {
            line.push_str(&format!(" field={f}"));
        }
        if r.locked == Some(true) {
            line.push_str(" [locked]");
        }
        println!("{line}");
    }
    println!(
        "-- {} records total; hash chain: {}",
        records.len(),
        if chain_ok { "OK" } else { "BROKEN" }
    );
    if !chain_ok {
        eprintln!(
            "jingle: WARNING: audit chain broken at record(s) {breaks:?} — the log has been edited or truncated"
        );
    }
    Ok(())
}
