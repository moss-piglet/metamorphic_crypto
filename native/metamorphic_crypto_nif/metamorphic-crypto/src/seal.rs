//! Unified seal/unseal that auto-detects hybrid (v2) vs legacy (v1) format.
//!
//! These are the primary interface for wrapping/unwrapping per-context symmetric
//! keys for distribution to users.

use crate::CryptoError;
use crate::b64;
use crate::box_seal;
use crate::hybrid;

/// Seal `plaintext` bytes to a user's public key(s).
///
/// - If `pq_public_key_b64` is provided (non-empty), uses hybrid ML-KEM-768.
/// - Otherwise, falls back to legacy X25519 `box_seal`.
pub fn seal_for_user(
    plaintext: &[u8],
    public_key_b64: &str,
    pq_public_key_b64: Option<&str>,
) -> Result<String, CryptoError> {
    match pq_public_key_b64 {
        Some(pq) if !pq.is_empty() => hybrid::hybrid_seal(plaintext, pq),
        _ => box_seal::box_seal(plaintext, public_key_b64),
    }
}

/// Unseal a ciphertext using the user's private key(s).
///
/// Auto-detects the format:
/// - If the ciphertext starts with version tag `0x02` and a PQ secret key is
///   available, uses `hybrid_open`.
/// - Otherwise, uses legacy `box_seal_open`.
///
/// Returns base64-encoded plaintext (matching the JS `boxSealOpen` convention).
pub fn unseal_from_user(
    ciphertext_b64: &str,
    public_key_b64: &str,
    private_key_b64: &str,
    pq_secret_key_b64: Option<&str>,
) -> Result<String, CryptoError> {
    if let Some(pq_sk) = pq_secret_key_b64 {
        if !pq_sk.is_empty() && hybrid::is_hybrid_ciphertext(ciphertext_b64) {
            let pt = hybrid::hybrid_open(ciphertext_b64, pq_sk)?;
            return Ok(b64::encode(&pt));
        }
    }
    box_seal::box_seal_open(ciphertext_b64, public_key_b64, private_key_b64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::generate_hybrid_keypair;
    use crate::keys::generate_keypair;

    #[test]
    fn legacy_roundtrip() {
        let kp = generate_keypair();
        let pt = b"context key material";
        let ct = seal_for_user(pt, &kp.public_key, None).unwrap();
        assert!(!hybrid::is_hybrid_ciphertext(&ct));
        let opened = unseal_from_user(&ct, &kp.public_key, &kp.private_key, None).unwrap();
        assert_eq!(b64::decode(&opened).unwrap(), pt);
    }

    #[test]
    fn hybrid_roundtrip() {
        let kp = generate_keypair();
        let hkp = generate_hybrid_keypair();
        let pt = b"context key material";
        let ct = seal_for_user(pt, &kp.public_key, Some(&hkp.public_key)).unwrap();
        assert!(hybrid::is_hybrid_ciphertext(&ct));
        let opened =
            unseal_from_user(&ct, &kp.public_key, &kp.private_key, Some(&hkp.secret_key)).unwrap();
        assert_eq!(b64::decode(&opened).unwrap(), pt);
    }

    #[test]
    fn empty_pq_key_falls_back_to_legacy() {
        let kp = generate_keypair();
        let pt = b"context key";
        let ct = seal_for_user(pt, &kp.public_key, Some("")).unwrap();
        assert!(!hybrid::is_hybrid_ciphertext(&ct));
        let opened = unseal_from_user(&ct, &kp.public_key, &kp.private_key, None).unwrap();
        assert_eq!(b64::decode(&opened).unwrap(), pt);
    }

    #[test]
    fn legacy_ct_with_pq_key_available() {
        let kp = generate_keypair();
        let hkp = generate_hybrid_keypair();
        let pt = b"old pre-migration key";
        // Seal with legacy
        let ct = seal_for_user(pt, &kp.public_key, None).unwrap();
        // Open with PQ key available — detects legacy format
        let opened =
            unseal_from_user(&ct, &kp.public_key, &kp.private_key, Some(&hkp.secret_key)).unwrap();
        assert_eq!(b64::decode(&opened).unwrap(), pt);
    }
}
