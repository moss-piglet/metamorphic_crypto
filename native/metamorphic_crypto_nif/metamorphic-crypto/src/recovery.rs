//! Recovery key generation and encoding.
//!
//! A recovery key is a human-readable string derived from 32 random bytes, encoded
//! with a custom base32 alphabet (no I/O/0/1) as 13 hyphen-separated groups.

use zeroize::Zeroize;

use crate::CryptoError;
use crate::b64;
use crate::secretbox::{decrypt_secretbox_to_string, encrypt_secretbox_string};

/// Custom base32 alphabet (32 chars, excludes I/O/0/1 to avoid confusion).
const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// A recovery key with its derived 32-byte secret.
#[derive(Debug, Clone)]
pub struct RecoveryKey {
    /// Human-readable key (13 hyphen-separated groups, 64 chars total).
    pub recovery_key: String,
    /// Base64-encoded 32-byte secret derived from the key (for encrypt/hash).
    pub recovery_secret_b64: String,
}

/// Generate a new recovery key from 32 OS-random bytes.
///
/// Returns the human-readable key and the derived secret (base64). The secret is
/// obtained by roundtripping through `recovery_key_to_secret` to ensure canonical form.
pub fn generate_recovery_key() -> Result<RecoveryKey, CryptoError> {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).expect("OS CSPRNG unavailable");

    // Encode each byte as two base32 chars
    let mut encoded = String::with_capacity(64);
    for &byte in &secret {
        encoded.push(ALPHABET[(byte % 32) as usize] as char);
        encoded.push(ALPHABET[((byte >> 3) % 32) as usize] as char);
    }
    secret.zeroize();

    // Format: 12 groups of 5 + 1 group of 4 = 64 chars
    let groups: Vec<&str> = (0..64)
        .step_by(5)
        .map(|i| &encoded[i..encoded.len().min(i + 5)])
        .collect();
    let recovery_key = groups.join("-");

    // Derive canonical secret by roundtripping
    let recovery_secret_b64 = recovery_key_to_secret(&recovery_key)?;

    Ok(RecoveryKey {
        recovery_key,
        recovery_secret_b64,
    })
}

/// Re-derive the 32-byte secret (base64) from a human-readable recovery key.
///
/// Case-insensitive. Strips hyphens.
pub fn recovery_key_to_secret(recovery_key: &str) -> Result<String, CryptoError> {
    let stripped: String = recovery_key.replace('-', "").to_uppercase();
    if stripped.len() != 64 {
        return Err(CryptoError::InvalidRecoveryKey);
    }

    let chars = stripped.as_bytes();
    let mut bytes = Vec::with_capacity(32);

    for pair in chars.chunks_exact(2) {
        let idx1 = alphabet_index(pair[0])?;
        let idx2 = alphabet_index(pair[1])?;
        bytes.push((idx1 & 0x1f) | ((idx2 & 0x1f) << 3));
    }

    Ok(b64::encode(&bytes))
}

/// Encrypt a private key (base64 string) with the recovery secret for backup.
pub fn encrypt_private_key_for_recovery(
    pk_b64: &str,
    secret_b64: &str,
) -> Result<String, CryptoError> {
    encrypt_secretbox_string(pk_b64, secret_b64)
}

/// Decrypt a private key using the recovery secret.
pub fn decrypt_private_key_with_recovery(
    ct_b64: &str,
    secret_b64: &str,
) -> Result<String, CryptoError> {
    decrypt_secretbox_to_string(ct_b64, secret_b64)
}

/// Find a character's index in our base32 alphabet.
fn alphabet_index(ch: u8) -> Result<u8, CryptoError> {
    ALPHABET
        .iter()
        .position(|&c| c == ch)
        .map(|i| i as u8)
        .ok_or(CryptoError::InvalidRecoveryKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;

    #[test]
    fn format_13_groups() {
        let rk = generate_recovery_key().unwrap();
        let groups: Vec<&str> = rk.recovery_key.split('-').collect();
        assert_eq!(groups.len(), 13);
        for (i, g) in groups.iter().enumerate() {
            if i < 12 {
                assert_eq!(g.len(), 5);
            } else {
                assert_eq!(g.len(), 4);
            }
        }
    }

    #[test]
    fn roundtrip() {
        let rk = generate_recovery_key().unwrap();
        let secret = recovery_key_to_secret(&rk.recovery_key).unwrap();
        assert_eq!(secret, rk.recovery_secret_b64);
        assert_eq!(b64::decode(&secret).unwrap().len(), 32);
    }

    #[test]
    fn case_insensitive() {
        let rk = generate_recovery_key().unwrap();
        let lower = recovery_key_to_secret(&rk.recovery_key.to_lowercase()).unwrap();
        assert_eq!(lower, rk.recovery_secret_b64);
    }

    #[test]
    fn encrypt_decrypt_private_key() {
        let kp = generate_keypair();
        let rk = generate_recovery_key().unwrap();
        let ct =
            encrypt_private_key_for_recovery(&kp.private_key, &rk.recovery_secret_b64).unwrap();
        let pt = decrypt_private_key_with_recovery(&ct, &rk.recovery_secret_b64).unwrap();
        assert_eq!(pt, kp.private_key);
    }

    #[test]
    fn only_valid_chars() {
        let rk = generate_recovery_key().unwrap();
        for ch in rk.recovery_key.replace('-', "").bytes() {
            assert!(ALPHABET.contains(&ch), "invalid char: {}", ch as char);
        }
    }

    #[test]
    fn invalid_char_rejected() {
        // 'I' and 'O' are not in the alphabet
        assert!(
            recovery_key_to_secret(
                "IIIII-OOOOO-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF-GGGGG-HHHHH-JJJJJ-KKKKK-LLLL"
            )
            .is_err()
        );
    }
}
