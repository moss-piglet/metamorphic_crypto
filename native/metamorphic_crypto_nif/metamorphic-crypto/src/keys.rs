//! Key generation and private-key encrypt/decrypt helpers.

use crypto_box::SecretKey;
use zeroize::Zeroize;

use crate::CryptoError;
use crate::b64;
use crate::secretbox::{decrypt_secretbox_to_string, encrypt_secretbox_string};

/// Secretbox key length (32 bytes).
const KEY_LEN: usize = 32;
/// Argon2id salt length (16 bytes).
const SALT_LEN: usize = 16;

/// An X25519 keypair (base64-encoded).
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// X25519 public key (base64, 32 bytes decoded).
    pub public_key: String,
    /// X25519 secret key (base64, 32 bytes decoded).
    pub private_key: String,
}

/// Fill `buf` with OS-random bytes.
#[inline]
fn random_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

/// Generate a random 32-byte symmetric key (base64-encoded).
///
/// Used for per-context keys (habit_key, group_key, reflection_key, etc.).
pub fn generate_key() -> String {
    let mut key = [0u8; KEY_LEN];
    random_bytes(&mut key);
    let encoded = b64::encode(&key);
    key.zeroize();
    encoded
}

/// Generate a random X25519 keypair (base64-encoded).
pub fn generate_keypair() -> KeyPair {
    let mut sk_bytes = [0u8; KEY_LEN];
    random_bytes(&mut sk_bytes);
    let sk = SecretKey::from_slice(&sk_bytes).expect("valid 32-byte key");
    let pk = sk.public_key();

    let kp = KeyPair {
        public_key: b64::encode(pk.as_bytes()),
        private_key: b64::encode(&sk_bytes),
    };
    sk_bytes.zeroize();
    kp
}

/// Generate a random 16-byte Argon2id salt (base64-encoded).
pub fn generate_salt() -> String {
    let mut salt = [0u8; SALT_LEN];
    random_bytes(&mut salt);
    b64::encode(&salt)
}

/// Encrypt a base64-encoded private key with a session key.
///
/// **Invariant**: the private key is stored as a base64 *string* (not raw bytes).
/// This function encrypts that string via secretbox, matching the JS implementation.
pub fn encrypt_private_key(
    private_key_b64: &str,
    session_key_b64: &str,
) -> Result<String, CryptoError> {
    encrypt_secretbox_string(private_key_b64, session_key_b64)
}

/// Decrypt an encrypted private key with a session key, returning the base64 private key.
pub fn decrypt_private_key(ct_b64: &str, session_key_b64: &str) -> Result<String, CryptoError> {
    decrypt_secretbox_to_string(ct_b64, session_key_b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_32_bytes() {
        let key = generate_key();
        assert_eq!(b64::decode(&key).unwrap().len(), 32);
    }

    #[test]
    fn keys_are_unique() {
        assert_ne!(generate_key(), generate_key());
    }

    #[test]
    fn keypair_sizes() {
        let kp = generate_keypair();
        assert_eq!(b64::decode(&kp.public_key).unwrap().len(), 32);
        assert_eq!(b64::decode(&kp.private_key).unwrap().len(), 32);
    }

    #[test]
    fn salt_is_16_bytes() {
        assert_eq!(b64::decode(&generate_salt()).unwrap().len(), 16);
    }

    #[test]
    fn private_key_encrypt_decrypt() {
        let kp = generate_keypair();
        let session_key = generate_key();
        let ct = encrypt_private_key(&kp.private_key, &session_key).unwrap();
        let pt = decrypt_private_key(&ct, &session_key).unwrap();
        assert_eq!(pt, kp.private_key);
    }

    #[test]
    fn private_key_wrong_session_key() {
        let kp = generate_keypair();
        let k1 = generate_key();
        let k2 = generate_key();
        let ct = encrypt_private_key(&kp.private_key, &k1).unwrap();
        assert!(decrypt_private_key(&ct, &k2).is_err());
    }
}
