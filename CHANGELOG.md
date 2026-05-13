# Changelog

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
