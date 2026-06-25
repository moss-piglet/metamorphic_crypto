//! Rustler NIF bindings for metamorphic-crypto.
//!
//! Exposes the Rust crypto library to Elixir via NIF functions.
//! All functions accept and return base64-encoded strings matching
//! the wire format used by the JavaScript/WASM client.

use metamorphic_crypto::{
    CryptoError, SecurityLevel, SignatureLevel, Suite, b64, box_seal, hybrid, kdf, keys, recovery,
    seal, secretbox, sha3_256, sha3_512, sha3_512_with_context, sha256, sha512, sign,
};
use rustler::{Binary, Error, NifResult};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn to_nif_error(e: CryptoError) -> Error {
    Error::Term(Box::new(e.to_string()))
}

/// Parse the CNSA 2.0 `Suite` axis from the lowercase atom name passed by
/// Elixir (`"hybrid"` / `"hybrid_matched"` / `"pure_cnsa2"`).
fn suite_from_str(suite: &str) -> NifResult<Suite> {
    match suite {
        "hybrid" => Ok(Suite::Hybrid),
        "hybrid_matched" => Ok(Suite::HybridMatched),
        "pure_cnsa2" => Ok(Suite::PureCnsa2),
        _ => Err(Error::Term(Box::new(format!("unknown suite: {suite}")))),
    }
}

/// Parse the KEM/seal `SecurityLevel` from the lowercase atom name passed by
/// Elixir (`"cat1"` / `"cat3"` / `"cat5"`).
fn security_level_from_str(level: &str) -> NifResult<SecurityLevel> {
    match level {
        "cat1" => Ok(SecurityLevel::Cat1),
        "cat3" => Ok(SecurityLevel::Cat3),
        "cat5" => Ok(SecurityLevel::Cat5),
        _ => Err(Error::Term(Box::new(format!(
            "unknown security level: {level}"
        )))),
    }
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

#[rustler::nif]
fn nif_seal_for_user_with_suite(
    plaintext_b64: &str,
    public_key_b64: &str,
    pq_public_key_b64: Option<String>,
    suite: &str,
    level: &str,
) -> NifResult<String> {
    let pt = b64::decode(plaintext_b64).map_err(to_nif_error)?;
    let suite = suite_from_str(suite)?;
    let level = security_level_from_str(level)?;
    seal::seal_for_user_with_suite(
        &pt,
        public_key_b64,
        pq_public_key_b64.as_deref(),
        suite,
        level,
    )
    .map_err(to_nif_error)
}

#[rustler::nif]
fn nif_generate_hybrid_keypair_512() -> (String, String) {
    let kp = hybrid::generate_hybrid_keypair_512();
    (kp.public_key, kp.secret_key)
}

#[rustler::nif]
fn nif_hybrid_seal_512(plaintext_b64: &str, combined_pk_b64: &str) -> NifResult<String> {
    let pt = b64::decode(plaintext_b64).map_err(to_nif_error)?;
    hybrid::hybrid_seal_512(&pt, combined_pk_b64).map_err(to_nif_error)
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

// ─── CNSA 2.0 Suite axis (KEM / seal) ────────────────────────────────────────
//
// Orthogonal `Suite` axis added in core v0.7.0: `Suite::Hybrid` (default,
// unchanged bytes), `Suite::HybridMatched` (classical partner matched to the PQ
// category — Cat-3 → X448, Cat-5 → P-521 ECDH), and `Suite::PureCnsa2` (pure
// ML-KEM-1024 + AES-256-GCM, Cat-5 only). The suite is passed as a lowercase
// atom name; the level mirrors the existing "cat1"/"cat3"/"cat5" parsing. The
// new suites bind a versioned context label into the HKDF-SHA512 `info` + GCM
// AAD; `hybrid_open` auto-detects suite + level from the version tag.

#[rustler::nif]
fn nif_generate_hybrid_keypair_suite(suite: &str, level: &str) -> NifResult<(String, String)> {
    let suite = suite_from_str(suite)?;
    let level = security_level_from_str(level)?;
    let kp = hybrid::generate_hybrid_keypair_suite(suite, level).map_err(to_nif_error)?;
    Ok((kp.public_key, kp.secret_key))
}

#[rustler::nif]
fn nif_hybrid_seal_suite(
    plaintext_b64: &str,
    combined_pk_b64: &str,
    suite: &str,
    level: &str,
) -> NifResult<String> {
    let pt = b64::decode(plaintext_b64).map_err(to_nif_error)?;
    let suite = suite_from_str(suite)?;
    let level = security_level_from_str(level)?;
    hybrid::hybrid_seal_suite(&pt, combined_pk_b64, suite, level).map_err(to_nif_error)
}

#[rustler::nif]
fn nif_hybrid_seal_suite_with_context(
    plaintext_b64: &str,
    combined_pk_b64: &str,
    suite: &str,
    level: &str,
    context_label: &str,
) -> NifResult<String> {
    let pt = b64::decode(plaintext_b64).map_err(to_nif_error)?;
    let suite = suite_from_str(suite)?;
    let level = security_level_from_str(level)?;
    hybrid::hybrid_seal_suite_with_context(&pt, combined_pk_b64, suite, level, context_label)
        .map_err(to_nif_error)
}

#[rustler::nif]
fn nif_hybrid_open_with_context(
    ciphertext_b64: &str,
    seed_b64: &str,
    context_label: &str,
) -> NifResult<String> {
    let pt = hybrid::hybrid_open_with_context(ciphertext_b64, seed_b64, context_label)
        .map_err(to_nif_error)?;
    Ok(b64::encode(&pt))
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

// ─── Hybrid PQ Signatures (ML-DSA + Ed25519, strict-AND verify) ──────────────
//
// Composite post-quantum signatures: every artifact is signed by *both* ML-DSA
// (FIPS 204) and Ed25519, and verification requires *both* (strict AND). The
// native crate takes raw message bytes and returns/accepts base64 strings for
// keys/signatures; the NIF mirrors that exactly (message is a raw Erlang
// binary, everything else base64). Level is passed as the lowercase atom name
// ("cat2" / "cat3" / "cat5"); Cat-3 (ML-DSA-65) is the default on the Elixir
// side. ML-DSA signing is hedged/randomized, so signature bytes are
// non-reproducible — but keys, framing, and `derive_public_key` are fully
// deterministic and pinnable. Plain scheduler (mirrors the hybrid KEM keygen);
// DirtyCpu stays reserved for the Argon2 KDF.

fn signature_level_from_str(level: &str) -> NifResult<SignatureLevel> {
    match level {
        "cat2" => Ok(SignatureLevel::Cat2),
        "cat3" => Ok(SignatureLevel::Cat3),
        "cat5" => Ok(SignatureLevel::Cat5),
        _ => Err(Error::Term(Box::new(format!(
            "unknown signature level: {level}"
        )))),
    }
}

#[rustler::nif]
fn nif_generate_signing_keypair(level: &str) -> NifResult<(String, String)> {
    let level = signature_level_from_str(level)?;
    let kp = sign::generate_signing_keypair_with_level(level);
    Ok((kp.public_key.clone(), kp.secret_key.clone()))
}

// CNSA 2.0 Suite axis (signatures). `sign` / `verify` / `derive_public_key`
// auto-detect the suite from the version tag, so only keypair generation needs
// a suite-aware binding. `Suite::PureCnsa2` is ML-DSA-87 (Cat-5) only;
// `Suite::HybridMatched` pairs ML-DSA with a category-matched classical curve
// (Cat-3 → Ed448, Cat-5 → ECDSA-P-521 hedged).
#[rustler::nif]
fn nif_generate_signing_keypair_suite(suite: &str, level: &str) -> NifResult<(String, String)> {
    let suite = suite_from_str(suite)?;
    let level = signature_level_from_str(level)?;
    let kp = sign::generate_signing_keypair_suite(suite, level).map_err(to_nif_error)?;
    Ok((kp.public_key.clone(), kp.secret_key.clone()))
}

#[rustler::nif]
fn nif_derive_signing_public_key(secret_key_b64: &str) -> NifResult<String> {
    sign::derive_public_key(secret_key_b64).map_err(to_nif_error)
}

#[rustler::nif]
fn nif_sign(message: Binary, context: &str, secret_key_b64: &str) -> NifResult<String> {
    sign::sign(message.as_slice(), context, secret_key_b64).map_err(to_nif_error)
}

#[rustler::nif]
fn nif_verify(
    message: Binary,
    context: &str,
    signature_b64: &str,
    public_key_b64: &str,
) -> NifResult<bool> {
    sign::verify(message.as_slice(), context, signature_b64, public_key_b64).map_err(to_nif_error)
}

// ─── NIF Registration ────────────────────────────────────────────────────────
rustler::init!("Elixir.MetamorphicCrypto.Native");
