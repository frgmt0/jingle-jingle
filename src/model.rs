//! Data model: `Entry`, the zeroizing `SecretString`, and the type-enforced
//! redaction boundary `EntryView`.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

pub const REDACTED: &str = "[REDACTED]";

/// A secret value. Zeroized on drop; `Debug`/`Display` print `[REDACTED]` so
/// panics, logs, and format strings cannot leak it. The raw value is reachable
/// only through the deliberately named [`SecretString::expose`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        SecretString(value)
    }

    /// Access the raw secret. Call sites of this method are the complete set
    /// of places secret material can escape the model layer.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

// Serde support exists solely so the vault payload (which is always encrypted
// before touching disk) can round-trip. `EntryView`, the only type handed to
// output code, has no secret-value fields at all.
impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = SecretString;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(SecretString(v.to_owned()))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(SecretString(v))
            }
        }
        deserializer.deserialize_string(V)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Random 16-hex-char identifier, stable across renames.
    pub id: String,
    /// Unique handle used to address the entry (case-insensitive).
    pub name: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    /// Free text, often sourced from the web: treated as UNTRUSTED on display.
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Locked entries refuse secret egress without --confirm-locked.
    #[serde(default)]
    pub locked: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// All secret material lives here; everything above is metadata.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretString>,
}

impl Entry {
    pub fn new(name: String) -> Self {
        let now = OffsetDateTime::now_utc();
        Entry {
            id: new_id(),
            name,
            service: String::new(),
            username: None,
            url: None,
            notes: None,
            tags: Vec::new(),
            locked: false,
            created_at: now,
            updated_at: now,
            secrets: BTreeMap::new(),
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = OffsetDateTime::now_utc();
    }

    pub fn secret(&self, field: &str) -> Result<&SecretString> {
        self.secrets.get(field).ok_or_else(|| Error::FieldNotFound {
            entry: self.name.clone(),
            field: field.to_owned(),
        })
    }

    pub fn view(&self) -> EntryView {
        EntryView {
            name: self.name.clone(),
            service: self.service.clone(),
            username: self.username.clone(),
            url: self.url.clone(),
            notes: self.notes.clone(),
            tags: self.tags.clone(),
            locked: self.locked,
            created_at: format_ts(self.created_at),
            updated_at: format_ts(self.updated_at),
            secret_fields: self.secrets.keys().cloned().collect(),
        }
    }
}

/// The redaction boundary. Output code only ever receives this type; it has
/// no secret-value fields, so `list`/`show`/`--json` cannot leak by accident.
#[derive(Clone, Serialize)]
pub struct EntryView {
    pub name: String,
    pub service: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub locked: bool,
    pub created_at: String,
    pub updated_at: String,
    /// Names of the secret fields present on the entry — never their values.
    pub secret_fields: Vec<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct VaultPayload {
    pub schema: u32,
    pub entries: Vec<Entry>,
}

pub fn format_ts(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339).unwrap_or_else(|_| "?".into())
}

pub fn new_id() -> String {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("OS randomness unavailable");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Entry names are handles that appear in CLI args and env-mapping specs, so
/// they must not contain `:` or `=` (used as separators) or whitespace.
pub fn validate_entry_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 128 {
        return Err(Error::Usage("entry name must be 1..=128 characters".into()));
    }
    if name.starts_with("__") {
        return Err(Error::Usage(
            "entry names starting with '__' are reserved".into(),
        ));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | '/' | '+'));
    if !ok {
        return Err(Error::Usage(format!(
            "invalid entry name '{}': allowed characters are A-Z a-z 0-9 . _ - @ / +",
            crate::redact::sanitize(name)
        )));
    }
    Ok(())
}

/// Secret field names ("password", "totp", "api_key", custom...).
pub fn validate_field_name(field: &str) -> Result<()> {
    if field.is_empty() || field.len() > 64 {
        return Err(Error::Usage("field name must be 1..=64 characters".into()));
    }
    let ok = field
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !ok {
        return Err(Error::Usage(format!(
            "invalid field name '{}': allowed characters are A-Z a-z 0-9 . _ -",
            crate::redact::sanitize(field)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_string_debug_and_display_are_redacted() {
        let s = SecretString::new("hunter2".into());
        assert_eq!(format!("{s:?}"), REDACTED);
        assert_eq!(format!("{s}"), REDACTED);
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn view_carries_field_names_not_values() {
        let mut e = Entry::new("gh".into());
        e.secrets
            .insert("password".into(), SecretString::new("supersecret".into()));
        let v = e.view();
        assert_eq!(v.secret_fields, vec!["password".to_string()]);
        let json = serde_json::to_string(&v).unwrap();
        assert!(!json.contains("supersecret"));
    }

    #[test]
    fn name_validation() {
        assert!(validate_entry_name("github.com/bot").is_ok());
        assert!(validate_entry_name("a:b").is_err());
        assert!(validate_entry_name("a=b").is_err());
        assert!(validate_entry_name("a b").is_err());
        assert!(validate_entry_name("").is_err());
        assert!(validate_entry_name("__x").is_err());
        assert!(validate_field_name("api_key").is_ok());
        assert!(validate_field_name("api key").is_err());
    }
}
