//! RFC 6238 TOTP (SHA-1, 30-second period, 6 digits) with base32 and
//! otpauth:// seed parsing. Hand-rolled on hmac+sha1 to keep the dependency
//! tree small and the code trivially auditable.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::model::SecretString;
use crate::{Error, Result};

pub const PERIOD: u64 = 30;
pub const DIGITS: u32 = 6;

/// Accepts a raw base32 seed (case-insensitive, spaces/dashes/padding
/// tolerated) or a full `otpauth://totp/...?secret=...` URI, and returns the
/// canonical base32 seed (uppercase, unpadded). The seed is a long-lived
/// secret: callers must never print it.
pub fn normalize_seed(input: &str) -> Result<SecretString> {
    let trimmed = input.trim();
    let raw = if trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        extract_uri_secret(trimmed)?
    } else {
        trimmed.to_owned()
    };
    let cleaned: String = raw
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '='))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() {
        return Err(Error::Usage("TOTP seed is empty".into()));
    }
    decode_seed(&cleaned)?; // validate
    Ok(SecretString::new(cleaned))
}

fn extract_uri_secret(uri: &str) -> Result<String> {
    let query = uri
        .split_once('?')
        .map(|(_, q)| q)
        .ok_or_else(|| Error::Usage("otpauth URI has no query string".into()))?;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k.eq_ignore_ascii_case("secret") {
            if v.is_empty() {
                return Err(Error::Usage("otpauth URI has an empty secret".into()));
            }
            return Ok(v.to_owned());
        }
    }
    Err(Error::Usage("otpauth URI has no secret parameter".into()))
}

fn decode_seed(b32: &str) -> Result<Zeroizing<Vec<u8>>> {
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, b32)
        .map(Zeroizing::new)
        .filter(|b| !b.is_empty())
        .ok_or_else(|| Error::Usage("TOTP seed is not valid base32".into()))
}

/// HOTP (RFC 4226) dynamic truncation.
fn hotp(key: &[u8], counter: u64, digits: u32) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let bin = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let code = bin % 10u32.pow(digits);
    format!("{code:0width$}", width = digits as usize)
}

fn code_at(seed: &[u8], unix_time: u64, digits: u32) -> String {
    hotp(seed, unix_time / PERIOD, digits)
}

/// Current code and the seconds until it expires.
pub fn code_now(seed_b32: &SecretString) -> Result<(String, u64)> {
    let seed = decode_seed(seed_b32.expose())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Other("system clock is before the Unix epoch".into()))?
        .as_secs();
    let remaining = PERIOD - (now % PERIOD);
    Ok((code_at(&seed, now, DIGITS), remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4226 appendix D test vectors (seed "12345678901234567890", 6 digits).
    #[test]
    fn hotp_rfc4226_vectors() {
        let key = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(hotp(key, counter as u64, 6), *want);
        }
    }

    /// RFC 6238 appendix B SHA-1 test vectors (8 digits).
    #[test]
    fn totp_rfc6238_vectors() {
        let key = b"12345678901234567890";
        let cases: &[(u64, &str)] = &[
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];
        for &(t, want) in cases {
            assert_eq!(code_at(key, t, 8), want);
        }
    }

    #[test]
    fn normalize_accepts_variants() {
        // "12345678901234567890" in base32
        let canonical = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        for input in [
            canonical,
            "gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
            "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
            "gezd-gnbv-gy3t-qojq-gezd-gnbv-gy3t-qojq",
            "otpauth://totp/Example:bot?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example",
        ] {
            assert_eq!(normalize_seed(input).unwrap().expose(), canonical);
        }
    }

    #[test]
    fn normalize_rejects_garbage() {
        assert!(normalize_seed("").is_err());
        assert!(normalize_seed("not!base32").is_err());
        assert!(normalize_seed("otpauth://totp/x").is_err());
        assert!(normalize_seed("otpauth://totp/x?issuer=y").is_err());
    }

    #[test]
    fn code_now_shape() {
        let seed = normalize_seed("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        let (code, remaining) = code_now(&seed).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!((1..=30).contains(&remaining));
    }
}
