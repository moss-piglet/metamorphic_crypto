# Changelog

## v0.4.0 (unreleased)

- Add `MetamorphicCrypto.Sign` — hybrid post-quantum signatures combining
  **ML-DSA (FIPS 204) + Ed25519** in a composite, strict-AND verified scheme:
  - `generate_signing_keypair/0` (default `:cat3`) and
    `generate_signing_keypair/1` (`:cat2` / `:cat3` / `:cat5`) returning
    `%{public_key, secret_key}` (base64 strings).
  - `sign/3` (raw message binary + UTF-8 `context` + base64 secret key →
    base64 signature) and `verify/4` (→ boolean, both components must verify).
  - `derive_public_key/1` deterministically re-derives the base64 verifying key
    from a secret key — so a key recovered from backup regenerates
    **byte-identically** (no false key-change alert for TOFU-pinned keys).
  - `sign_context_v1/0` exposes the recommended `"metamorphic/sign/v1"` context
    label; plus `derive_public_key!/1` and `sign!/3` raising variants.
  - Convenience facade: `MetamorphicCrypto.generate_signing_keypair/0,1`,
    `sign/3`, `verify/4`, and `derive_public_key/1`.
- ML-DSA uses the **hedged (randomized)** FIPS 204 variant, so signature bytes
  are non-reproducible (both-valid); the wire format — version tags, byte
  layout, domain-separation framing
  (`I2OSP(len(context), 8) || context || message`), and public-key derivation —
  is fully deterministic and pinnable across native Rust, WASM, and this NIF.
- Sync the native crate dependency to
  [`metamorphic-crypto` 0.5.0](https://crates.io/crates/metamorphic-crypto),
  which exposes the composite signature API. No change to existing encryption,
  hashing, or wire formats.

## v0.3.0 (unreleased)

- Add `MetamorphicCrypto.Hash` — SHA-3 / SHA-2 hashing for **public** data
  (key fingerprints, safety numbers, key-transparency-log entries):
  - `sha3_512/1` (recommended default, Cat-5), `sha3_256/1`, `sha256/1`,
    `sha512/1`, and the domain-separated `sha3_512_with_context/2` — plus `!`
    raising variants.
  - Base64 in, base64 out, matching the rest of the package and the WASM wire
    format, so a digest computed in Elixir is byte-for-byte identical to one
    computed in the browser/native (verified by a locked parity vector).
  - `MetamorphicCrypto.sha3_512/1` and `MetamorphicCrypto.sha3_512_with_context/2`
    added to the top-level convenience facade.
- These digests are for **public data only** and intentionally add no
  zeroize/constant-time ceremony; do not hash secrets with them (use
  `MetamorphicCrypto.KDF.derive_session_key/2` for secret material).
- Sync the native crate dependency to
  [`metamorphic-crypto` 0.4.0](https://crates.io/crates/metamorphic-crypto),
  which exposes the public hashing API. No change to existing encryption
  behavior or wire formats.

## v0.2.2 (2026-06-10)

- No functional or API changes; encryption output is unchanged.
- Sync the native crate dependency to `metamorphic-crypto` 0.3.7, deduping the
  `sha3`/`keccak` tree for a cleaner SBOM.
- Supply-chain hardening of the release pipeline: SHA-pinned actions,
  build-provenance attestation of each precompiled NIF, `cargo audit` gate,
  grouped Dependabot, and a `SECURITY.md`.
- Packaging: exclude the maintainer-only release task from the published
  package.

## v0.2.1 (2026-05-23)

- Add `t:MetamorphicCrypto.Hybrid.security_level/0` type (`:cat3 | :cat5`)
- `MetamorphicCrypto.Hybrid.generate_keypair/1` now accepts an optional security
  level — `generate_keypair(:cat5)` for ML-KEM-1024, `generate_keypair()` for
  ML-KEM-768 (default, unchanged behavior)
- `MetamorphicCrypto.Hybrid.seal/3` and `seal_raw/3` now accept an optional
  security level parameter
- `MetamorphicCrypto.Seal.seal_for_user/3` and `seal_for_user_raw/3` now accept
  a `:level` option (`:cat3` or `:cat5`) for choosing the PQ security level when
  a PQ public key is provided
- Existing `generate_keypair_1024/0`, `seal_1024/2`, and `seal_raw_1024/2` are
  preserved as convenience aliases
- All changes are backwards compatible — no NIF or binary changes required

## v0.2.0 (2026-05-13)

- Switch from vendored `metamorphic-crypto` Rust source to
  [`metamorphic-crypto` v0.2.0](https://crates.io/crates/metamorphic-crypto) on crates.io
  (no user-facing changes — the public Elixir API is fully backwards compatible)
- Add ML-KEM-1024 + X25519 (Cat-5, NIST Category 5, ~AES-256) hybrid encryption:
  - `MetamorphicCrypto.Hybrid.generate_keypair_1024/0` — generate Cat-5 keypair
  - `MetamorphicCrypto.Hybrid.seal_1024/2` — encrypt with Cat-5
  - `MetamorphicCrypto.Hybrid.seal_raw_1024/2` — encrypt raw bytes with Cat-5
- `MetamorphicCrypto.Hybrid.open/2` now auto-detects Cat-3 (v2) and Cat-5 (v3) ciphertext
- `MetamorphicCrypto.Hybrid.hybrid_ciphertext?/1` now detects both v2 and v3 formats

## v0.1.2 (2026-05-12)

- Add explicit `targets` list to `RustlerPrecompiled` config
  - Prevents download attempts for unsupported platforms (e.g. `arm-unknown-linux-gnueabihf`)
  - `mix rustler_precompiled.download --all` now only fetches the 5 supported targets

## v0.1.1 (2026-05-12)

- Fix precompiled NIF loading on macOS and Windows
  - Binary inside tar archive was named incorrectly (`libmetamorphic_crypto_nif.dylib`
    instead of the versioned `.so` name that RustlerPrecompiled expects)
  - Users without Rust installed would get `nif_not_loaded` errors

## v0.1.0 (2026-05-11)

- Initial release
- XSalsa20-Poly1305 symmetric encryption (`MetamorphicCrypto.SecretBox`)
- X25519 sealed box public-key encryption (`MetamorphicCrypto.BoxSeal`)
- ML-KEM-768 + X25519 hybrid post-quantum encryption (`MetamorphicCrypto.Hybrid`)
- Unified seal/unseal with auto-format-detection (`MetamorphicCrypto.Seal`)
- Argon2id key derivation (`MetamorphicCrypto.KDF`)
- Key generation utilities (`MetamorphicCrypto.Keys`)
- Human-readable recovery keys (`MetamorphicCrypto.Recovery`)
- Precompiled NIF binaries for all major platforms
