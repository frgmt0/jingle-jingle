//! Path resolution: CLI flags > environment variables > XDG defaults.

use std::path::PathBuf;

use crate::{Error, Result};

pub const ENV_KEYFILE: &str = "JINGLE_KEYFILE";
pub const ENV_DATA_DIR: &str = "JINGLE_DATA_DIR";

#[derive(Debug, Clone)]
pub struct Paths {
    pub keyfile: PathBuf,
    pub vault: PathBuf,
    pub audit: PathBuf,
}

/// Resolve the keyfile, vault, and audit-log paths.
///
/// Precedence: explicit CLI flag, then `JINGLE_KEYFILE` / `JINGLE_DATA_DIR`
/// environment variables, then platform defaults (`~/.config/jingle/key`,
/// `~/.local/share/jingle/vault.jingle` on Linux). The audit log always lives
/// next to the vault so a relocated vault keeps its trail.
pub fn resolve(vault_flag: Option<PathBuf>, keyfile_flag: Option<PathBuf>) -> Result<Paths> {
    let dirs = directories::ProjectDirs::from("", "", "jingle");

    let keyfile = match keyfile_flag {
        Some(p) => p,
        None => match std::env::var_os(ENV_KEYFILE) {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => dirs
                .as_ref()
                .map(|d| d.config_dir().join("key"))
                .ok_or_else(|| Error::Other("cannot determine a config directory".into()))?,
        },
    };

    let vault = match vault_flag {
        Some(p) => p,
        None => {
            let data_dir = match std::env::var_os(ENV_DATA_DIR) {
                Some(p) if !p.is_empty() => PathBuf::from(p),
                _ => dirs
                    .as_ref()
                    .map(|d| d.data_dir().to_path_buf())
                    .ok_or_else(|| Error::Other("cannot determine a data directory".into()))?,
            };
            data_dir.join("vault.jingle")
        }
    };

    let audit = vault.with_file_name("audit.jsonl");

    Ok(Paths {
        keyfile,
        vault,
        audit,
    })
}
