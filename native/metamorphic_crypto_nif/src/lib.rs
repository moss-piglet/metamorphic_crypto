//! Rustler NIF bindings for metamorphic-crypto.
//!
//! Exposes the Rust crypto library to Elixir via NIF functions.
//! All functions accept and return base64-encoded strings matching
//! the wire format used by the JavaScript/WASM client.

use metamorphic_crypto::{
    CryptoError, b64, box_seal, hybrid, kdf, keys, recovery, seal, secretbox, sha3_256, sha3_512,
    sha3_512_with_context, sha256, sha512,
};
use rustler::{Error, NifResult};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn to_nif_error(e: CryptoError) -> Error {
    Error::Term(Box::new(e.to_string()))
}

// ─── Key Derivation ──────────────────────────────────────────────────────────

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_derive_session_key(password: &str, salt_b64: &str) -> NifResult<String> {
    kdf::derive_session_key(password, salt_b64).map_err(to_nif_error)
}

// ─── SecretBox (Symmetric Encryption) ────────────────────────────────────────

#[rustler::nif]
fn nif_encrypt_secretbox(plaintext_b64: &str, key_b64: &str) -> NifResult<String> {
    let pt = b64::decode(plaintext_b64).map_err(to_nif_error)?;
    secretbox::encrypt_secretbox(&pt, key_b64).map_err(to_nif_error)
}

#[rustler::nif]
fn nif_decrypt_secretbox(ciphertext_b64: &str, key_b64: &str) -> NifResult<String> {
    let pt = secretbox::decrypt_secretbox(ciphertext_b64, key_b64).map_err(to_nif_error)?;
    Ok(b64::encode(&pt))
}

#[rustler::nif]
fn nif_encrypt_secretbox_string(plaintext: &str, key_b64: &str) -> NifResult<String> {
    secretbox::encrypt_secretbox_string(plaintext, key_b64).map_err(to_nif_error)
}

#[rustler::nif]
fn nif_decrypt_secretbox_to_string(ciphertext_b64: &str, key_b64: &str) -> NifResult<String> {
    secretbox::decrypt_secretbox_to_string(ciphertext_b64, key_b64).map_err(to_nif_error)
}

// ─── BoxSeal (Public-Key Encryption) ─────────────────────────────────────────

#[rustler::nif]
fn nif_box_seal(plaintext_b64: &str, public_key_b64: &str) -> NifResult<String> {
    let pt = b64::decode(plaintext_b64).map_err(to_nif_error)?;
    box_seal::box_seal(&pt, public_key_b64).map_err(to_nif_error)
}

#[rustler::nif]
fn nif_box_seal_open(
    ciphertext_b64: &str,
    public_key_b64: &str,
    private_key_b64: &str,
) -> NifResult<String> {
    box_seal::box_seal_open(ciphertext_b64, public_key_b64, private_key_b64).map_err(to_nif_error)
}

// ─── Unified Seal/Unseal ─────────────────────────────────────────────────────

#[rustler::nif]
fn nif_seal_for_user(
    plaintext_b64: &str,
    public_key_b64: &str,
    pq_public_key_b64: Option<String>,
) -> NifResult<String> {
    let pt = b64::decode(plaintext_b64).map_err(to_nif_error)?;
    seal::seal_for_user(&pt, public_key_b64, pq_public_key_b64.as_deref()).map_err(to_nif_error)
}

#[rustler::nif]
fn nif_unseal_from_user(
    ciphertext_b64: &str,
    public_key_b64: &str,
    private_key_b64: &str,
    pq_secret_key_b64: Option<String>,
) -> NifResult<String> {
    seal::unseal_from_user(
        ciphertext_b64,
        public_key_b64,
        private_key_b64,
        pq_secret_key_b64.as_deref(),
    )
    .map_err(to_nif_error)
}

// ─── Hybrid PQ KEM (Cat-3: ML-KEM-768) ───────────────────────────────────────

#[rustler::nif]
fn nif_generate_hybrid_keypair() -> (String, String) {
    let kp = hybrid::generate_hybrid_keypair();
    (kp.public_key, kp.secret_key)
}

#[rustler::nif]
fn nif_hybrid_seal(plaintext_b64: &str, combined_pk_b64: &str) -> NifResult<String> {
    let pt = b64::decode(plaintext_b64).map_err(to_nif_error)?;
    hybrid::hybrid_seal(&pt, combined_pk_b64).map_err(to_nif_error)
}

#[rustler::nif]
fn nif_hybrid_open(ciphertext_b64: &str, seed_b64: &str) -> NifResult<String> {
    let pt = hybrid::hybrid_open(ciphertext_b64, seed_b64).map_err(to_nif_error)?;
    Ok(b64::encode(&pt))
}

#[rustler::nif]
fn nif_is_hybrid_ciphertext(ciphertext_b64: &str) -> bool {
    hybrid::is_hybrid_ciphertext(ciphertext_b64)
}

// ─── Hybrid PQ KEM (Cat-5: ML-KEM-1024) ─────────────────────────────────────

#[rustler::nif]
fn nif_generate_hybrid_keypair_1024() -> (String, String) {
    let kp = hybrid::generate_hybrid_keypair_1024();
    (kp.public_key, kp.secret_key)
}

#[rustler::nif]
fn nif_hybrid_seal_1024(plaintext_b64: &str, combined_pk_b64: &str) -> NifResult<String> {
    let pt = b64::decode(plaintext_b64).map_err(to_nif_error)?;
    hybrid::hybrid_seal_1024(&pt, combined_pk_b64).map_err(to_nif_error)
}

// ─── Key Generation ──────────────────────────────────────────────────────────

#[rustler::nif]
fn nif_generate_key() -> String {
    keys::generate_key()
}

#[rustler::nif]
fn nif_generate_keypair() -> (String, String) {
    let kp = keys::generate_keypair();
    (kp.public_key, kp.private_key)
}

#[rustler::nif]
fn nif_generate_salt() -> String {
    keys::generate_salt()
}

#[rustler::nif]
fn nif_encrypt_private_key(private_key_b64: &str, session_key_b64: &str) -> NifResult<String> {
    keys::encrypt_private_key(private_key_b64, session_key_b64).map_err(to_nif_error)
}

#[rustler::nif]
fn nif_decrypt_private_key(ciphertext_b64: &str, session_key_b64: &str) -> NifResult<String> {
    keys::decrypt_private_key(ciphertext_b64, session_key_b64).map_err(to_nif_error)
}

// ─── Recovery Key ────────────────────────────────────────────────────────────

#[rustler::nif]
fn nif_generate_recovery_key() -> NifResult<(String, String)> {
    let rk = recovery::generate_recovery_key().map_err(to_nif_error)?;
    Ok((rk.recovery_key, rk.recovery_secret_b64))
}

#[rustler::nif]
fn nif_recovery_key_to_secret(recovery_key: &str) -> NifResult<String> {
    recovery::recovery_key_to_secret(recovery_key).map_err(to_nif_error)
}

#[rustler::nif]
fn nif_encrypt_private_key_for_recovery(
    private_key_b64: &str,
    recovery_secret_b64: &str,
) -> NifResult<String> {
    recovery::encrypt_private_key_for_recovery(private_key_b64, recovery_secret_b64)
        .map_err(to_nif_error)
}

#[rustler::nif]
fn nif_decrypt_private_key_with_recovery(
    ciphertext_b64: &str,
    recovery_secret_b64: &str,
) -> NifResult<String> {
    recovery::decrypt_private_key_with_recovery(ciphertext_b64, recovery_secret_b64)
        .map_err(to_nif_error)
}

// ─── Utility ─────────────────────────────────────────────────────────────────

#[rustler::nif]
fn nif_parse_salt_from_key_hash(key_hash: &str) -> NifResult<String> {
    b64::parse_salt_from_key_hash(key_hash)
        .map(|s| s.to_string())
        .map_err(to_nif_error)
}

// ─── Hashing (SHA-3 / SHA-2) ─────────────────────────────────────────────────
//
// Public, infallible digests for *public* data (key fingerprints, safety
// numbers, key-transparency-log entries). Base64 in, base64 out — byte-identical
// to the crate's native and WASM outputs. Cheap, so plain scheduler (NOT
// DirtyCpu — that is reserved for the Argon2 KDF). Do NOT hash secrets with
// these; use the Argon2id KDF for secret material.

#[rustler::nif]
fn nif_sha3_512(data_b64: &str) -> NifResult<String> {
    let data = b64::decode(data_b64).map_err(to_nif_error)?;
    Ok(b64::encode(&sha3_512(&data)))
}

#[rustler::nif]
fn nif_sha3_256(data_b64: &str) -> NifResult<String> {
    let data = b64::decode(data_b64).map_err(to_nif_error)?;
    Ok(b64::encode(&sha3_256(&data)))
}

#[rustler::nif]
fn nif_sha256(data_b64: &str) -> NifResult<String> {
    let data = b64::decode(data_b64).map_err(to_nif_error)?;
    Ok(b64::encode(&sha256(&data)))
}

#[rustler::nif]
fn nif_sha512(data_b64: &str) -> NifResult<String> {
    let data = b64::decode(data_b64).map_err(to_nif_error)?;
    Ok(b64::encode(&sha512(&data)))
}

#[rustler::nif]
fn nif_sha3_512_with_context(context: &str, data_b64: &str) -> NifResult<String> {
    let data = b64::decode(data_b64).map_err(to_nif_error)?;
    Ok(b64::encode(&sha3_512_with_context(context, &data)))
}

// ─── NIF Registration ────────────────────────────────────────────────────────

rustler::init!("Elixir.MetamorphicCrypto.Native");
