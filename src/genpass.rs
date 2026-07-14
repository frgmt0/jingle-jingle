//! Password generation with unbiased (rejection-sampled) character selection.

use crate::model::SecretString;
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    /// Letters, digits, and shell-safe symbols.
    Full,
    /// Letters and digits.
    Alnum,
    /// Digits only (PINs).
    Digits,
}

impl Charset {
    /// Symbols chosen to avoid quote/backslash/backtick so generated values
    /// survive careless shell interpolation in agent scripts.
    pub fn alphabet(self) -> &'static [u8] {
        match self {
            Charset::Full => {
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}:,.?~"
            }
            Charset::Alnum => {
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            }
            Charset::Digits => b"0123456789",
        }
    }
}

pub const MIN_LENGTH: usize = 4;
pub const MAX_LENGTH: usize = 1024;

pub fn generate(length: usize, charset: Charset) -> Result<SecretString> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return Err(Error::Usage(format!(
            "length must be between {MIN_LENGTH} and {MAX_LENGTH}"
        )));
    }
    let alphabet = charset.alphabet();
    debug_assert!(alphabet.len() <= 256);
    // Rejection sampling: accept bytes below the largest multiple of
    // alphabet.len() to avoid modulo bias.
    let limit = 256 - (256 % alphabet.len());
    let mut out = String::with_capacity(length);
    let mut buf = [0u8; 64];
    while out.len() < length {
        getrandom::fill(&mut buf)
            .map_err(|e| Error::Other(format!("failed to gather OS randomness: {e}")))?;
        for &b in &buf {
            if (b as usize) < limit {
                out.push(alphabet[b as usize % alphabet.len()] as char);
                if out.len() == length {
                    break;
                }
            }
        }
    }
    Ok(SecretString::new(out))
}

pub fn entropy_bits(length: usize, charset: Charset) -> f64 {
    length as f64 * (charset.alphabet().len() as f64).log2()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn respects_length_and_charset() {
        for cs in [Charset::Full, Charset::Alnum, Charset::Digits] {
            let p = generate(32, cs).unwrap();
            assert_eq!(p.expose().len(), 32);
            let alphabet: HashSet<char> = cs.alphabet().iter().map(|&b| b as char).collect();
            assert!(p.expose().chars().all(|c| alphabet.contains(&c)));
        }
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(generate(0, Charset::Full).is_err());
        assert!(generate(3, Charset::Full).is_err());
        assert!(generate(MAX_LENGTH + 1, Charset::Full).is_err());
    }

    #[test]
    fn outputs_differ() {
        let a = generate(24, Charset::Full).unwrap();
        let b = generate(24, Charset::Full).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn entropy_estimates() {
        let n = Charset::Full.alphabet().len() as f64;
        assert!((entropy_bits(24, Charset::Full) - 24.0 * n.log2()).abs() < 1e-9);
        assert_eq!(entropy_bits(10, Charset::Digits).round(), 33.0);
    }

    #[test]
    fn no_shell_hostile_characters_in_full() {
        let p = generate(512, Charset::Full).unwrap();
        for bad in ['\'', '"', '\\', '`', ' ', ';'] {
            assert!(!p.expose().contains(bad), "found {bad:?}");
        }
    }
}
