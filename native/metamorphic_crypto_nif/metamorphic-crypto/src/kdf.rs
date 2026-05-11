//! Argon2id key derivation.
//!
//! Derives a 32-byte session key from a password and 16-byte salt using Argon2id
//! with libsodium's `OPSLIMIT_INTERACTIVE` / `MEMLIMIT_INTERACTIVE` parameters.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::CryptoError;
use crate::b64;

/// `crypto_pwhash_OPSLIMIT_INTERACTIVE` (time cost).
const T_COST: u32 = 2;
/// `crypto_pwhash_MEMLIMIT_INTERACTIVE` in KiB (64 MiB).
const M_COST_KIB: u32 = 65_536;
/// Output length (`crypto_secretbox_KEYBYTES`).
const KEY_LEN: usize = 32;
/// Required salt length (`crypto_pwhash_SALTBYTES`).
const SALT_LEN: usize = 16;

/// Derive a 32-byte session key from `password` and a base64-encoded 16-byte `salt`.
///
/// Returns the derived key as base64. The intermediate key material is zeroized on drop.
pub fn derive_session_key(password: &str, salt_b64: &str) -> Result<String, CryptoError> {
    let salt = b64::decode(salt_b64)?;
    if salt.len() != SALT_LEN {
        return Err(CryptoError::InvalidLength {
            expected: SALT_LEN,
            got: salt.len(),
        });
    }

    let params = Params::new(M_COST_KIB, T_COST, 1, Some(KEY_LEN))
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    let encoded = b64::encode(&key);
    key.zeroize();
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_salt() -> String {
        b64::encode(&[0u8; 16])
    }

    #[test]
    fn deterministic() {
        let a = derive_session_key("pw", &zero_salt()).unwrap();
        let b = derive_session_key("pw", &zero_salt()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn output_is_32_bytes() {
        let key = derive_session_key("pw", &zero_salt()).unwrap();
        assert_eq!(b64::decode(&key).unwrap().len(), 32);
    }

    #[test]
    fn different_passwords_differ() {
        let salt = zero_salt();
        let a = derive_session_key("alpha", &salt).unwrap();
        let b = derive_session_key("beta", &salt).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_salts_differ() {
        let s1 = b64::encode(&[1u8; 16]);
        let s2 = b64::encode(&[2u8; 16]);
        let a = derive_session_key("pw", &s1).unwrap();
        let b = derive_session_key("pw", &s2).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn bad_salt_length() {
        let short = b64::encode(&[0u8; 8]);
        assert!(derive_session_key("pw", &short).is_err());
    }
}
