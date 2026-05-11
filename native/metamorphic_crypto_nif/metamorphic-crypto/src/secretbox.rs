//! XSalsa20-Poly1305 authenticated encryption (NaCl `secretbox`).
//!
//! Ciphertext layout: `nonce (24 B) || ciphertext (plaintext.len() + 16 B MAC)`.
//! This is the same layout produced by the JS `crypto_secretbox_easy` + prepended nonce.

use crypto_secretbox::aead::Aead;
use crypto_secretbox::aead::generic_array::GenericArray;
use crypto_secretbox::{KeyInit, XSalsa20Poly1305};

use crate::CryptoError;
use crate::b64;

/// XSalsa20-Poly1305 key size (32 bytes).
const KEY_LEN: usize = 32;
/// XSalsa20-Poly1305 nonce size (24 bytes).
const NONCE_LEN: usize = 24;
/// Poly1305 MAC size (16 bytes).
const MAC_LEN: usize = 16;

/// Fill `buf` with OS-random bytes.
#[inline]
fn random_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

/// Encrypt `plaintext` with `key_b64`, returning base64-encoded `nonce || ciphertext`.
pub fn encrypt_secretbox(plaintext: &[u8], key_b64: &str) -> Result<String, CryptoError> {
    let key_bytes = b64::decode(key_b64)?;
    if key_bytes.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: key_bytes.len(),
        });
    }

    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&key_bytes));

    let mut nonce_buf = [0u8; NONCE_LEN];
    random_bytes(&mut nonce_buf);
    let nonce = GenericArray::from_slice(&nonce_buf);

    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Decryption)?;

    let mut combined = Vec::with_capacity(NONCE_LEN + ct.len());
    combined.extend_from_slice(&nonce_buf);
    combined.extend_from_slice(&ct);

    Ok(b64::encode(&combined))
}

/// Decrypt base64-encoded `nonce || ciphertext` with `key_b64`, returning plaintext bytes.
pub fn decrypt_secretbox(ciphertext_b64: &str, key_b64: &str) -> Result<Vec<u8>, CryptoError> {
    let combined = b64::decode(ciphertext_b64)?;
    let key_bytes = b64::decode(key_b64)?;

    if key_bytes.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: key_bytes.len(),
        });
    }
    if combined.len() < NONCE_LEN + MAC_LEN {
        return Err(CryptoError::TooShort);
    }

    let (nonce_slice, ct) = combined.split_at(NONCE_LEN);
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&key_bytes));
    let nonce = GenericArray::from_slice(nonce_slice);

    cipher
        .decrypt(nonce, ct)
        .map_err(|_| CryptoError::Decryption)
}

/// Encrypt a UTF-8 string, returning base64 ciphertext.
pub fn encrypt_secretbox_string(plaintext: &str, key_b64: &str) -> Result<String, CryptoError> {
    encrypt_secretbox(plaintext.as_bytes(), key_b64)
}

/// Decrypt base64 ciphertext to a UTF-8 string.
pub fn decrypt_secretbox_to_string(ct_b64: &str, key_b64: &str) -> Result<String, CryptoError> {
    let bytes = decrypt_secretbox(ct_b64, key_b64)?;
    String::from_utf8(bytes).map_err(CryptoError::Utf8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_key;

    #[test]
    fn roundtrip_bytes() {
        let key = generate_key();
        let pt = b"hello, metamorphic!";
        let ct = encrypt_secretbox(pt, &key).unwrap();
        assert_eq!(decrypt_secretbox(&ct, &key).unwrap(), pt);
    }

    #[test]
    fn roundtrip_string() {
        let key = generate_key();
        let pt = "Exercise 3x/week 🏋️";
        let ct = encrypt_secretbox_string(pt, &key).unwrap();
        assert_eq!(decrypt_secretbox_to_string(&ct, &key).unwrap(), pt);
    }

    #[test]
    fn wrong_key() {
        let k1 = generate_key();
        let k2 = generate_key();
        let ct = encrypt_secretbox(b"secret", &k1).unwrap();
        assert!(decrypt_secretbox(&ct, &k2).is_err());
    }

    #[test]
    fn nonce_is_random() {
        let key = generate_key();
        let ct1 = encrypt_secretbox(b"x", &key).unwrap();
        let ct2 = encrypt_secretbox(b"x", &key).unwrap();
        assert_ne!(ct1, ct2); // different nonces
    }

    #[test]
    fn ciphertext_length() {
        let key = generate_key();
        let ct_b64 = encrypt_secretbox(b"test", &key).unwrap();
        let ct = b64::decode(&ct_b64).unwrap();
        assert_eq!(ct.len(), NONCE_LEN + 4 + MAC_LEN);
    }

    #[test]
    fn bad_key_length() {
        let short = b64::encode(&[0u8; 16]);
        assert!(encrypt_secretbox(b"x", &short).is_err());
    }

    #[test]
    fn empty_plaintext() {
        let key = generate_key();
        let ct = encrypt_secretbox(b"", &key).unwrap();
        assert_eq!(decrypt_secretbox(&ct, &key).unwrap(), b"");
    }
}
