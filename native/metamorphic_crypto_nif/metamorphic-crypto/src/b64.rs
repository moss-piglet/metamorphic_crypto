//! Base64 utilities (standard alphabet, with padding).
//!
//! Matches JavaScript `btoa` / `atob` encoding.

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::CryptoError;

/// Encode bytes to standard base64 with padding.
#[inline]
pub fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decode a standard base64 string to bytes.
#[inline]
pub fn decode(s: &str) -> Result<Vec<u8>, CryptoError> {
    STANDARD.decode(s).map_err(CryptoError::Base64)
}

/// Extract the salt portion from a key_hash string (`{salt_b64}$argon2id`).
pub fn parse_salt_from_key_hash(key_hash: &str) -> Result<&str, CryptoError> {
    let (salt, rest) = key_hash
        .split_once('$')
        .ok_or(CryptoError::InvalidKeyHash)?;
    if rest.contains('$') {
        return Err(CryptoError::InvalidKeyHash);
    }
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = b"hello world";
        let encoded = encode(data);
        assert_eq!(decode(&encoded).unwrap(), data);
    }

    #[test]
    fn matches_js_btoa() {
        // JS: btoa("hello") === "aGVsbG8="
        assert_eq!(encode(b"hello"), "aGVsbG8=");
        assert_eq!(decode("aGVsbG8=").unwrap(), b"hello");
    }

    #[test]
    fn parse_salt_valid() {
        let salt = parse_salt_from_key_hash("c2FsdA==$argon2id").unwrap();
        assert_eq!(salt, "c2FsdA==");
    }

    #[test]
    fn parse_salt_invalid() {
        assert!(parse_salt_from_key_hash("noseparator").is_err());
        assert!(parse_salt_from_key_hash("a$b$c").is_err());
    }
}
