//! Rustler NIF bindings for metamorphic-crypto.
//!
//! Exposes the Rust crypto library to Elixir via NIF functions.
//! All functions accept and return base64-encoded strings matching
//! the wire format used by the JavaScript/WASM client.

use metamorphic_crypto::{
    CryptoError, SecurityLevel, SignatureLevel, Suite, b64, box_seal, hkdf, hmac_sha256, hybrid,
    kdf, keys, on_signing_stack, recovery, seal, secretbox, sha3_256, sha3_512,
    sha3_512_with_context, sha256, sha512, sign, vrf, vrf_p256,
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

/// Map a `Suite` back to the lowercase atom name Elixir uses.
fn suite_to_str(suite: Suite) -> &'static str {
    match suite {
        Suite::Hybrid => "hybrid",
        Suite::HybridMatched => "hybrid_matched",
        Suite::PureCnsa2 => "pure_cnsa2",
    }
}

/// Map a `SignatureLevel` back to the lowercase atom name Elixir uses.
fn signature_level_to_str(level: SignatureLevel) -> &'static str {
    match level {
        SignatureLevel::Cat2 => "cat2",
        SignatureLevel::Cat3 => "cat3",
        SignatureLevel::Cat5 => "cat5",
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
// deterministic and pinnable.
//
// SCHEDULING: ML-DSA signing / keygen / verifying-key expansion are CPU-bound
// and — critically — allocate large intermediate lattice matrices *on the
// stack* inside the upstream `ml-dsa` crate (fixed-size arrays we cannot box
// from here). On the BEAM dirty-CPU scheduler thread's modest default stack
// (`+sssdcpu`, ~320 KB) that overflows the guard page and takes the whole VM
// down with SIGBUS. So these four entry points run `schedule = "DirtyCpu"` AND
// route the ML-DSA-bearing body through `metamorphic_crypto::on_signing_stack`,
// which borrows a generous (32 MiB) worker-thread stack and blocks the dirty
// scheduler on the join. Only the crate call runs on the worker; cheap argument
// parsing and all Rustler term construction stay on the caller (owned, `Send`
// data crosses the boundary). `nif_verify` and posture introspection use far
// less stack and stay as-is.

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

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_generate_signing_keypair(level: &str) -> NifResult<(String, String)> {
    let level = signature_level_from_str(level)?;
    let kp = on_signing_stack(move || sign::generate_signing_keypair_with_level(level));
    Ok((kp.public_key.clone(), kp.secret_key.clone()))
}

// CNSA 2.0 Suite axis (signatures). `sign` / `verify` / `derive_public_key`
// auto-detect the suite from the version tag, so only keypair generation needs
// a suite-aware binding. `Suite::PureCnsa2` is ML-DSA-87 (Cat-5) only;
// `Suite::HybridMatched` pairs ML-DSA with a category-matched classical curve
// (Cat-3 → Ed448, Cat-5 → ECDSA-P-521 hedged).
#[rustler::nif(schedule = "DirtyCpu")]
fn nif_generate_signing_keypair_suite(suite: &str, level: &str) -> NifResult<(String, String)> {
    let suite = suite_from_str(suite)?;
    let level = signature_level_from_str(level)?;
    let kp = on_signing_stack(move || sign::generate_signing_keypair_suite(suite, level))
        .map_err(to_nif_error)?;
    Ok((kp.public_key.clone(), kp.secret_key.clone()))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_derive_signing_public_key(secret_key_b64: &str) -> NifResult<String> {
    on_signing_stack(move || sign::derive_public_key(secret_key_b64)).map_err(to_nif_error)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_sign(message: Binary, context: &str, secret_key_b64: &str) -> NifResult<String> {
    let msg = message.as_slice();
    on_signing_stack(move || sign::sign(msg, context, secret_key_b64)).map_err(to_nif_error)
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

// ─── Signature posture introspection (metamorphic-crypto 0.8/0.9) ─────────────
//
// Composite artifacts are self-describing: their leading version tag encodes the
// `(Suite, SignatureLevel)` posture that produced them. These read-only accessors
// surface that posture as `(suite_str, level_str)` tuples (mapped to typed atoms
// on the Elixir side) without exposing the raw wire tag. The full decoded length
// is validated for the decoded posture, so a truncated / over-long / garbage blob
// is a structural error rather than a silently misreported posture.

#[rustler::nif]
fn nif_signature_posture(public_key_b64: &str) -> NifResult<(&'static str, &'static str)> {
    let (suite, level) = sign::signature_posture(public_key_b64).map_err(to_nif_error)?;
    Ok((suite_to_str(suite), signature_level_to_str(level)))
}

#[rustler::nif]
fn nif_signature_posture_from_signature(
    signature_b64: &str,
) -> NifResult<(&'static str, &'static str)> {
    let (suite, level) =
        sign::signature_posture_from_signature(signature_b64).map_err(to_nif_error)?;
    Ok((suite_to_str(suite), signature_level_to_str(level)))
}

// ─── HMAC-SHA256 (RFC 2104 / FIPS 198-1) ─────────────────────────────────────
//
// One-shot keyed MAC over the audited `hmac` crate. The generic HMAC-SHA256
// primitive the IETF KEYTRANS standard suites need for commitments. Base64 in,
// base64 out — byte-identical to the crate's native and WASM outputs. Cheap, so
// the plain scheduler (DirtyCpu stays reserved for Argon2 / VRF prove-verify).

#[rustler::nif]
fn nif_hmac_sha256(key_b64: &str, msg_b64: &str) -> NifResult<String> {
    let key = b64::decode(key_b64).map_err(to_nif_error)?;
    let msg = b64::decode(msg_b64).map_err(to_nif_error)?;
    Ok(b64::encode(&hmac_sha256(&key, &msg)))
}

// ─── HKDF-SHA512 (RFC 5869, Extract-then-Expand) ─────────────────────────────
//
// One-shot HKDF over SHA-512 — the *correct* construction for combining and
// diversifying SECRET key material (unlike the bare hashes above). `salt` and
// `ikm` are base64; `info` is a raw binary domain-separation label bound into
// Expand (a UTF-8 label is just an Erlang binary, and passing raw bytes lets the
// canonical RFC 5869 KAT — whose `info` is not valid UTF-8 — be asserted
// end-to-end); `length` is the desired OKM length in bytes. An empty `salt`
// means "not provided" (RFC 5869 §2.2). Byte-identical to the crate's native and
// WASM outputs, so a wrapping key derived in the browser re-derives identically
// here. Cheap, so the plain scheduler (DirtyCpu stays reserved for Argon2 / VRF).

#[rustler::nif]
fn nif_hkdf_sha512(
    salt_b64: &str,
    ikm_b64: &str,
    info: Binary,
    length: usize,
) -> NifResult<String> {
    let salt = b64::decode(salt_b64).map_err(to_nif_error)?;
    let ikm = b64::decode(ikm_b64).map_err(to_nif_error)?;
    let okm = hkdf::hkdf_sha512(&salt, &ikm, info.as_slice(), length).map_err(to_nif_error)?;
    Ok(b64::encode(&okm))
}

// ─── ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381, suite 0x03) ────────────────────
//
// Verifiable Random Function over Edwards25519. `verify` returns the VRF output
// on a valid proof and `nil` on a cryptographic rejection (wrong key, tampered
// input/proof); a wrong-length key/proof is a structural `{:error, _}`. Base64
// throughout, mirroring the crate/WASM. Prove/verify run on DirtyCpu (curve
// arithmetic + hash-to-curve counter loop).

#[rustler::nif]
fn nif_ecvrf_generate_keypair() -> (String, String) {
    let (sk, pk) = vrf::ecvrf_generate_keypair();
    (b64::encode(&sk), b64::encode(&pk))
}

#[rustler::nif]
fn nif_ecvrf_public_key(secret_key_b64: &str) -> NifResult<String> {
    let sk = b64::decode(secret_key_b64).map_err(to_nif_error)?;
    Ok(b64::encode(
        &vrf::ecvrf_public_key(&sk).map_err(to_nif_error)?,
    ))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_ecvrf_prove(secret_key_b64: &str, alpha_b64: &str) -> NifResult<String> {
    let sk = b64::decode(secret_key_b64).map_err(to_nif_error)?;
    let alpha = b64::decode(alpha_b64).map_err(to_nif_error)?;
    Ok(b64::encode(
        &vrf::ecvrf_prove(&sk, &alpha).map_err(to_nif_error)?,
    ))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_ecvrf_verify(
    public_key_b64: &str,
    alpha_b64: &str,
    proof_b64: &str,
) -> NifResult<Option<String>> {
    let pk = b64::decode(public_key_b64).map_err(to_nif_error)?;
    let alpha = b64::decode(alpha_b64).map_err(to_nif_error)?;
    let proof = b64::decode(proof_b64).map_err(to_nif_error)?;
    Ok(vrf::ecvrf_verify(&pk, &alpha, &proof)
        .map_err(to_nif_error)?
        .map(|beta| b64::encode(&beta)))
}

#[rustler::nif]
fn nif_ecvrf_proof_to_hash(proof_b64: &str) -> NifResult<String> {
    let proof = b64::decode(proof_b64).map_err(to_nif_error)?;
    Ok(b64::encode(
        &vrf::ecvrf_proof_to_hash(&proof).map_err(to_nif_error)?,
    ))
}

// ─── ECVRF-P256-SHA256-TAI (RFC 9381, suite 0x01) ────────────────────────────
//
// The NIST P-256 sibling VRF, backing the on-spec IETF `KT_128_SHA256_P256`
// KEYTRANS suite. Same shape and semantics as the Edwards25519 VRF above
// (`verify` -> output / nil / structural error). Base64 throughout; prove/verify
// on DirtyCpu.

#[rustler::nif]
fn nif_ecvrf_p256_generate_keypair() -> (String, String) {
    let (sk, pk) = vrf_p256::ecvrf_p256_generate_keypair();
    (b64::encode(&sk), b64::encode(&pk))
}

#[rustler::nif]
fn nif_ecvrf_p256_public_key(secret_key_b64: &str) -> NifResult<String> {
    let sk = b64::decode(secret_key_b64).map_err(to_nif_error)?;
    Ok(b64::encode(
        &vrf_p256::ecvrf_p256_public_key(&sk).map_err(to_nif_error)?,
    ))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_ecvrf_p256_prove(secret_key_b64: &str, alpha_b64: &str) -> NifResult<String> {
    let sk = b64::decode(secret_key_b64).map_err(to_nif_error)?;
    let alpha = b64::decode(alpha_b64).map_err(to_nif_error)?;
    Ok(b64::encode(
        &vrf_p256::ecvrf_p256_prove(&sk, &alpha).map_err(to_nif_error)?,
    ))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_ecvrf_p256_verify(
    public_key_b64: &str,
    alpha_b64: &str,
    proof_b64: &str,
) -> NifResult<Option<String>> {
    let pk = b64::decode(public_key_b64).map_err(to_nif_error)?;
    let alpha = b64::decode(alpha_b64).map_err(to_nif_error)?;
    let proof = b64::decode(proof_b64).map_err(to_nif_error)?;
    Ok(vrf_p256::ecvrf_p256_verify(&pk, &alpha, &proof)
        .map_err(to_nif_error)?
        .map(|beta| b64::encode(&beta)))
}

#[rustler::nif]
fn nif_ecvrf_p256_proof_to_hash(proof_b64: &str) -> NifResult<String> {
    let proof = b64::decode(proof_b64).map_err(to_nif_error)?;
    Ok(b64::encode(
        &vrf_p256::ecvrf_p256_proof_to_hash(&proof).map_err(to_nif_error)?,
    ))
}

// ─── NIF Registration ────────────────────────────────────────────────────────
rustler::init!("Elixir.MetamorphicCrypto.Native");
