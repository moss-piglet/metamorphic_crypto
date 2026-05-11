//! X25519 sealed box (anonymous public-key encryption).
//!
//! Implements the libsodium `crypto_box_seal` / `crypto_box_seal_open` construction:
//! - Generate an ephemeral X25519 keypair
//! - Derive nonce = `BLAKE2b-24(ephemeral_pk || recipient_pk)`
//! - Encrypt with `crypto_box(msg, nonce, recipient_pk, ephemeral_sk)`
//! - Output: `ephemeral_pk (32 B) || box ciphertext (len + 16 B MAC)`

use blake2::digest::consts::U24;
use blake2::{Blake2b, Digest};
use crypto_box::aead::Aead;
use crypto_box::aead::generic_array::GenericArray;
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use zeroize::Zeroize;

use crate::CryptoError;
use crate::b64;

/// X25519 key size (32 bytes).
const KEY_LEN: usize = 32;
/// Minimum sealed ciphertext: ephemeral_pk (32) + MAC (16).
const MIN_SEALED_LEN: usize = KEY_LEN + 16;

type Blake2b24 = Blake2b<U24>;

/// Fill `buf` with OS-random bytes.
#[inline]
fn random_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

/// Derive the 24-byte nonce from `ephemeral_pk || recipient_pk` (BLAKE2b).
fn seal_nonce(epk: &[u8; KEY_LEN], rpk: &[u8; KEY_LEN]) -> [u8; 24] {
    let mut h = Blake2b24::new();
    h.update(epk);
    h.update(rpk);
    h.finalize().into()
}

/// Encrypt `plaintext` for `recipient_public_key_b64` (anonymous sealed box).
///
/// Returns base64-encoded ciphertext. Matches libsodium `crypto_box_seal`.
pub fn box_seal(plaintext: &[u8], recipient_pk_b64: &str) -> Result<String, CryptoError> {
    let pk_bytes = b64::decode(recipient_pk_b64)?;
    if pk_bytes.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: pk_bytes.len(),
        });
    }

    let recipient_pk =
        PublicKey::from_slice(&pk_bytes).map_err(|_| CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: pk_bytes.len(),
        })?;

    // Generate ephemeral keypair
    let mut sk_bytes = [0u8; KEY_LEN];
    random_bytes(&mut sk_bytes);
    let ephemeral_sk = SecretKey::from_slice(&sk_bytes).map_err(|_| CryptoError::Decryption)?;
    sk_bytes.zeroize();
    let ephemeral_pk = ephemeral_sk.public_key();

    // Derive nonce
    let epk_arr: [u8; KEY_LEN] = *ephemeral_pk.as_bytes();
    let rpk_arr: [u8; KEY_LEN] = pk_bytes.try_into().unwrap();
    let nonce = seal_nonce(&epk_arr, &rpk_arr);

    // Encrypt
    let salsa_box = SalsaBox::new(&recipient_pk, &ephemeral_sk);
    let ct = salsa_box
        .encrypt(GenericArray::from_slice(&nonce), plaintext)
        .map_err(|_| CryptoError::Decryption)?;

    // Output: ephemeral_pk || ciphertext
    let mut out = Vec::with_capacity(KEY_LEN + ct.len());
    out.extend_from_slice(&epk_arr);
    out.extend_from_slice(&ct);

    Ok(b64::encode(&out))
}

/// Decrypt a sealed box using the recipient's keypair.
///
/// Returns base64-encoded plaintext (matching JS `boxSealOpen` convention).
pub fn box_seal_open(
    ciphertext_b64: &str,
    public_key_b64: &str,
    private_key_b64: &str,
) -> Result<String, CryptoError> {
    let combined = b64::decode(ciphertext_b64)?;
    let pk_bytes = b64::decode(public_key_b64)?;
    let sk_bytes = b64::decode(private_key_b64)?;

    if pk_bytes.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: pk_bytes.len(),
        });
    }
    if sk_bytes.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: sk_bytes.len(),
        });
    }
    if combined.len() < MIN_SEALED_LEN {
        return Err(CryptoError::TooShort);
    }

    let (epk_slice, ct) = combined.split_at(KEY_LEN);
    let epk_arr: [u8; KEY_LEN] = epk_slice.try_into().unwrap();
    let rpk_arr: [u8; KEY_LEN] = pk_bytes.try_into().unwrap();

    let ephemeral_pk = PublicKey::from_slice(&epk_arr).map_err(|_| CryptoError::Decryption)?;
    let recipient_sk = SecretKey::from_slice(&sk_bytes).map_err(|_| CryptoError::Decryption)?;

    let nonce = seal_nonce(&epk_arr, &rpk_arr);

    let salsa_box = SalsaBox::new(&ephemeral_pk, &recipient_sk);
    let pt = salsa_box
        .decrypt(GenericArray::from_slice(&nonce), ct)
        .map_err(|_| CryptoError::Decryption)?;

    Ok(b64::encode(&pt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;

    #[test]
    fn roundtrip() {
        let kp = generate_keypair();
        let pt = b"context key bytes";
        let ct = box_seal(pt, &kp.public_key).unwrap();
        let opened = box_seal_open(&ct, &kp.public_key, &kp.private_key).unwrap();
        assert_eq!(b64::decode(&opened).unwrap(), pt);
    }

    #[test]
    fn wrong_key() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let ct = box_seal(b"secret", &kp1.public_key).unwrap();
        assert!(box_seal_open(&ct, &kp2.public_key, &kp2.private_key).is_err());
    }

    #[test]
    fn nondeterministic() {
        let kp = generate_keypair();
        let ct1 = box_seal(b"x", &kp.public_key).unwrap();
        let ct2 = box_seal(b"x", &kp.public_key).unwrap();
        assert_ne!(ct1, ct2);
    }
}
