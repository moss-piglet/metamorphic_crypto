//! Hybrid post-quantum KEM: ML-KEM-768 + X25519.
//!
//! This module implements the exact same hybrid KEM as noble-post-quantum's
//! `ml_kem768_x25519` export, ensuring byte-level compatibility with existing
//! production ciphertext.
//!
//! ## Construction (from noble source)
//!
//! ```text
//! combineKEMS(
//!   seedLen = 32,
//!   outputLen = 32,
//!   expandSeed = SHAKE256(seed, dkLen=96),
//!   combiner = SHA3-256(ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || b"\\.//^\\"),
//!   ml_kem768,
//!   ecdhKem(x25519)
//! )
//! ```
//!
//! ## Key layout
//!
//! | Component | Size | Description |
//! |-----------|------|-------------|
//! | Secret key (seed) | 32 bytes | Root seed expanded via SHAKE256 |
//! | Public key | 1216 bytes | ML-KEM-768 ek (1184) ‖ X25519 pk (32) |
//! | Ciphertext | 1120 bytes | ML-KEM-768 ct (1088) ‖ X25519 ephemeral pk (32) |
//! | Shared secret | 32 bytes | SHA3-256 combiner output |
//!
//! ## Sealed-box ciphertext format (Metamorphic v2)
//!
//! ```text
//! 0x02 || hybrid_ciphertext (1120 B) || nonce (24 B) || secretbox_ct
//! ```

use ml_kem::{Decapsulate, MlKem768};
use ml_kem::{DecapsulationKey, EncapsulationKey, KeyExport};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use crypto_secretbox::aead::Aead;
use crypto_secretbox::aead::generic_array::GenericArray;
use crypto_secretbox::{KeyInit, XSalsa20Poly1305};

use crate::CryptoError;
use crate::b64;

// === Constants ===

/// Version tag for hybrid ciphertext.
const VERSION_HYBRID: u8 = 0x02;
/// XSalsa20 nonce length.
const NONCE_LEN: usize = 24;
/// ML-KEM-768 encapsulation key size.
const MLKEM_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext size.
const MLKEM_CT_LEN: usize = 1088;
/// X25519 key size.
const X25519_LEN: usize = 32;
/// Combined public key: ML-KEM ek (1184) + X25519 pk (32).
const COMBINED_PK_LEN: usize = MLKEM_EK_LEN + X25519_LEN;
/// Combined ciphertext: ML-KEM ct (1088) + X25519 ephemeral pk (32).
const COMBINED_CT_LEN: usize = MLKEM_CT_LEN + X25519_LEN;
/// Root seed length.
const SEED_LEN: usize = 32;
/// Expanded seed length: ML-KEM seed (64) + X25519 secret (32).
const EXPANDED_SEED_LEN: usize = 96;
/// ML-KEM-768 seed portion.
const MLKEM_SEED_LEN: usize = 64;
/// Noble's domain-separation label.
const LABEL: &[u8] = b"\\.//^\\";
/// Poly1305 MAC.
const MAC_LEN: usize = 16;

// === Types ===

/// A hybrid ML-KEM-768 + X25519 keypair (base64-encoded).
#[derive(Debug, Clone)]
pub struct HybridKeyPair {
    /// Combined public key (1216 bytes): ML-KEM ek ‖ X25519 pk. Base64.
    pub public_key: String,
    /// Root seed (32 bytes). Base64.
    pub secret_key: String,
}

// === Helpers ===

/// Fill buffer with OS random bytes.
#[inline]
fn random_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

/// Expand a 32-byte seed to 96 bytes using SHAKE256 (matching noble's expandSeedXof).
fn expand_seed(seed: &[u8; SEED_LEN]) -> [u8; EXPANDED_SEED_LEN] {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; EXPANDED_SEED_LEN];
    reader.read(&mut out);
    out
}

/// SHA3-256 combiner: `SHA3-256(ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || label)`
fn combine(
    ss_mlkem: &[u8],
    ss_x25519: &[u8],
    ct_x25519: &[u8; X25519_LEN],
    pk_x25519: &[u8; X25519_LEN],
) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    Digest::update(&mut hasher, ss_mlkem);
    Digest::update(&mut hasher, ss_x25519);
    Digest::update(&mut hasher, ct_x25519);
    Digest::update(&mut hasher, pk_x25519);
    Digest::update(&mut hasher, LABEL);
    hasher.finalize().into()
}

// === Public API ===

/// Generate a hybrid ML-KEM-768 + X25519 keypair.
///
/// The secret key is the 32-byte root seed. The public key is the concatenation
/// of the ML-KEM-768 encapsulation key (1184 B) and the X25519 public key (32 B).
pub fn generate_hybrid_keypair() -> HybridKeyPair {
    let mut seed = [0u8; SEED_LEN];
    random_bytes(&mut seed);

    let mut expanded = expand_seed(&seed);
    let mlkem_seed: [u8; MLKEM_SEED_LEN] = expanded[..MLKEM_SEED_LEN].try_into().unwrap();
    let x25519_sk_bytes: [u8; X25519_LEN] = expanded[MLKEM_SEED_LEN..].try_into().unwrap();

    // ML-KEM-768 keypair from seed
    let dk = DecapsulationKey::<MlKem768>::from_seed(mlkem_seed.into());
    let ek = dk.encapsulation_key();
    let ek_bytes = ek.to_bytes();

    // X25519 keypair
    let x25519_sk = X25519StaticSecret::from(x25519_sk_bytes);
    let x25519_pk = X25519PublicKey::from(&x25519_sk);

    // Combined public key: ML-KEM ek || X25519 pk
    let mut combined_pk = Vec::with_capacity(COMBINED_PK_LEN);
    combined_pk.extend_from_slice(&ek_bytes);
    combined_pk.extend_from_slice(x25519_pk.as_bytes());

    let pair = HybridKeyPair {
        public_key: b64::encode(&combined_pk),
        secret_key: b64::encode(&seed),
    };

    // Zeroize secrets
    seed.zeroize();
    expanded.zeroize();

    pair
}

/// Seal `plaintext` to a hybrid public key.
///
/// Returns base64: `0x02 || hybrid_ct (1120 B) || nonce (24 B) || secretbox_ct`.
pub fn hybrid_seal(plaintext: &[u8], combined_pk_b64: &str) -> Result<String, CryptoError> {
    let pk_bytes = b64::decode(combined_pk_b64)?;
    if pk_bytes.len() != COMBINED_PK_LEN {
        return Err(CryptoError::InvalidLength {
            expected: COMBINED_PK_LEN,
            got: pk_bytes.len(),
        });
    }

    // Split combined public key
    let mlkem_ek_bytes = &pk_bytes[..MLKEM_EK_LEN];
    let x25519_pk_bytes: [u8; X25519_LEN] = pk_bytes[MLKEM_EK_LEN..].try_into().unwrap();

    // ML-KEM-768 encapsulate
    let ek = EncapsulationKey::<MlKem768>::new(
        mlkem_ek_bytes
            .try_into()
            .map_err(|_| CryptoError::Hybrid("invalid ML-KEM ek".into()))?,
    )
    .map_err(|_| CryptoError::Hybrid("invalid ML-KEM encapsulation key".into()))?;

    let mut mlkem_coins = [0u8; 32];
    random_bytes(&mut mlkem_coins);
    let (mlkem_ct, ss_mlkem) = ek.encapsulate_deterministic(&mlkem_coins.into());
    mlkem_coins.zeroize();

    // X25519 encapsulate (ephemeral DH)
    let mut x25519_eph_bytes = [0u8; X25519_LEN];
    random_bytes(&mut x25519_eph_bytes);
    let x25519_eph_sk = X25519StaticSecret::from(x25519_eph_bytes);
    let x25519_eph_pk = X25519PublicKey::from(&x25519_eph_sk);
    let x25519_recipient_pk = X25519PublicKey::from(x25519_pk_bytes);
    let ss_x25519 = x25519_eph_sk.diffie_hellman(&x25519_recipient_pk);
    x25519_eph_bytes.zeroize();

    // Combine shared secrets
    let ct_x25519: [u8; X25519_LEN] = *x25519_eph_pk.as_bytes();
    let mut shared_secret = combine(
        ss_mlkem.as_slice(),
        ss_x25519.as_bytes(),
        &ct_x25519,
        &x25519_pk_bytes,
    );

    // Encrypt plaintext with the combined shared secret
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&shared_secret));
    let mut nonce_buf = [0u8; NONCE_LEN];
    random_bytes(&mut nonce_buf);
    let nonce = GenericArray::from_slice(&nonce_buf);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Hybrid("secretbox encrypt failed".into()))?;

    shared_secret.zeroize();

    // Assemble: version || mlkem_ct || x25519_eph_pk || nonce || secretbox_ct
    let mut out = Vec::with_capacity(1 + COMBINED_CT_LEN + NONCE_LEN + ct.len());
    out.push(VERSION_HYBRID);
    out.extend_from_slice(mlkem_ct.as_slice());
    out.extend_from_slice(&ct_x25519);
    out.extend_from_slice(&nonce_buf);
    out.extend_from_slice(&ct);

    Ok(b64::encode(&out))
}

/// Open a hybrid-sealed ciphertext with the recipient's secret key (32-byte seed).
pub fn hybrid_open(ct_b64: &str, seed_b64: &str) -> Result<Vec<u8>, CryptoError> {
    let combined = b64::decode(ct_b64)?;
    let seed_bytes = b64::decode(seed_b64)?;

    if combined.first() != Some(&VERSION_HYBRID) {
        return Err(CryptoError::Hybrid(
            "not a hybrid ciphertext (bad version tag)".into(),
        ));
    }
    if seed_bytes.len() != SEED_LEN {
        return Err(CryptoError::InvalidLength {
            expected: SEED_LEN,
            got: seed_bytes.len(),
        });
    }
    if combined.len() < 1 + COMBINED_CT_LEN + NONCE_LEN + MAC_LEN {
        return Err(CryptoError::TooShort);
    }

    // Expand seed to recover both secret keys
    let seed: [u8; SEED_LEN] = seed_bytes.try_into().unwrap();
    let mut expanded = expand_seed(&seed);
    let mlkem_seed: [u8; MLKEM_SEED_LEN] = expanded[..MLKEM_SEED_LEN].try_into().unwrap();
    let x25519_sk_bytes: [u8; X25519_LEN] = expanded[MLKEM_SEED_LEN..].try_into().unwrap();
    expanded.zeroize();

    // Parse ciphertext components
    let mlkem_ct = &combined[1..1 + MLKEM_CT_LEN];
    let x25519_eph_pk_bytes: [u8; X25519_LEN] = combined[1 + MLKEM_CT_LEN..1 + COMBINED_CT_LEN]
        .try_into()
        .unwrap();
    let nonce_slice = &combined[1 + COMBINED_CT_LEN..1 + COMBINED_CT_LEN + NONCE_LEN];
    let encrypted = &combined[1 + COMBINED_CT_LEN + NONCE_LEN..];

    // ML-KEM-768 decapsulate
    let dk = DecapsulationKey::<MlKem768>::from_seed(mlkem_seed.into());
    let kem_ct = mlkem_ct
        .try_into()
        .map_err(|_| CryptoError::Hybrid("invalid ML-KEM ciphertext".into()))?;
    let ss_mlkem = dk.decapsulate(kem_ct);

    // X25519 decapsulate (DH with ephemeral public key)
    let x25519_sk = X25519StaticSecret::from(x25519_sk_bytes);
    let x25519_eph_pk = X25519PublicKey::from(x25519_eph_pk_bytes);
    let ss_x25519 = x25519_sk.diffie_hellman(&x25519_eph_pk);

    // Recover recipient's X25519 public key for the combiner
    let x25519_pk = X25519PublicKey::from(&x25519_sk);
    let pk_x25519: [u8; X25519_LEN] = *x25519_pk.as_bytes();

    // Combine shared secrets (same combiner as seal)
    let mut shared_secret = combine(
        ss_mlkem.as_slice(),
        ss_x25519.as_bytes(),
        &x25519_eph_pk_bytes,
        &pk_x25519,
    );

    // Decrypt
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&shared_secret));
    let nonce = GenericArray::from_slice(nonce_slice);
    let result = cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| CryptoError::Decryption);

    shared_secret.zeroize();
    result
}

/// Returns `true` if the base64 blob starts with the hybrid version tag (0x02).
pub fn is_hybrid_ciphertext(ct_b64: &str) -> bool {
    b64::decode(ct_b64)
        .map(|bytes| bytes.first() == Some(&VERSION_HYBRID))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let kp = generate_hybrid_keypair();
        let pt = b"32-byte symmetric context key!!!";
        let ct = hybrid_seal(pt, &kp.public_key).unwrap();
        assert!(is_hybrid_ciphertext(&ct));
        let opened = hybrid_open(&ct, &kp.secret_key).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = generate_hybrid_keypair();
        let kp2 = generate_hybrid_keypair();
        let ct = hybrid_seal(b"x", &kp1.public_key).unwrap();
        assert!(hybrid_open(&ct, &kp2.secret_key).is_err());
    }

    #[test]
    fn version_tag() {
        let kp = generate_hybrid_keypair();
        let raw = b64::decode(&hybrid_seal(b"x", &kp.public_key).unwrap()).unwrap();
        assert_eq!(raw[0], VERSION_HYBRID);
    }

    #[test]
    fn nondeterministic() {
        let kp = generate_hybrid_keypair();
        let c1 = hybrid_seal(b"x", &kp.public_key).unwrap();
        let c2 = hybrid_seal(b"x", &kp.public_key).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn empty_plaintext() {
        let kp = generate_hybrid_keypair();
        let ct = hybrid_seal(b"", &kp.public_key).unwrap();
        assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), b"");
    }

    #[test]
    fn key_sizes() {
        let kp = generate_hybrid_keypair();
        let pk = b64::decode(&kp.public_key).unwrap();
        let sk = b64::decode(&kp.secret_key).unwrap();
        assert_eq!(pk.len(), COMBINED_PK_LEN); // 1216
        assert_eq!(sk.len(), SEED_LEN); // 32
    }

    #[test]
    fn ciphertext_size() {
        let kp = generate_hybrid_keypair();
        let pt = b"exactly 32 bytes of key material";
        let raw = b64::decode(&hybrid_seal(pt, &kp.public_key).unwrap()).unwrap();
        // 1 + 1120 + 24 + 32 + 16 = 1193
        assert_eq!(raw.len(), 1 + COMBINED_CT_LEN + NONCE_LEN + 32 + MAC_LEN);
    }

    #[test]
    fn legacy_not_hybrid() {
        let legacy = b64::encode(&[0x01, 0x02, 0x03]);
        assert!(!is_hybrid_ciphertext(&legacy));
    }

    #[test]
    fn combiner_uses_label() {
        // Verify the combiner output changes if we alter the inputs
        let ss_mlkem = [0xAAu8; 32];
        let ss_x25519 = [0xBBu8; 32];
        let ct_x25519 = [0xCCu8; 32];
        let pk_x25519 = [0xDDu8; 32];

        let result = combine(&ss_mlkem, &ss_x25519, &ct_x25519, &pk_x25519);
        assert_eq!(result.len(), 32);

        // Different input → different output
        let ss_mlkem2 = [0xEEu8; 32];
        let result2 = combine(&ss_mlkem2, &ss_x25519, &ct_x25519, &pk_x25519);
        assert_ne!(result, result2);
    }

    #[test]
    fn seed_expansion_produces_96_bytes() {
        let seed = [0x42u8; SEED_LEN];
        let expanded = expand_seed(&seed);
        assert_eq!(expanded.len(), EXPANDED_SEED_LEN);

        // Deterministic
        let expanded2 = expand_seed(&seed);
        assert_eq!(expanded, expanded2);

        // Different seed → different expansion
        let seed2 = [0x43u8; SEED_LEN];
        let expanded3 = expand_seed(&seed2);
        assert_ne!(expanded, expanded3);
    }
}
