# Changelog

## v0.8.1 (2026-07-08)

Supply-chain / dependency maintenance release. Fully **non-breaking**: no NIF,
wire format, default, or export changes.

- Bump native `metamorphic-crypto` `0.10.0` → `0.10.2`, and refresh the NIF
  `Cargo.lock` so the transitive **`cmov` 0.5.3 → 0.5.4** security fix
  (RustSec **GHSA-3rjw-m598-pq24 / CVE-2026-50185**, aarch64 `Cmov`/`CmovEq`
  correctness) and **`aes-gcm` 0.11.0** (rc → stable) are actually pulled in.
- Bump `rustler` `0.37.3` → `0.38.0`; precompiled NIFs rebuilt for all targets.
- CI: github-actions group updated (checkout v7, cache v6,
  attest-build-provenance v4.1.1, gh-release v3, etc.).
- Dev tooling: `ex_doc` 0.40.3, `earmark_parser` 1.4.45, `makeup` 1.2.2.

## v0.8.0 (2026-07-01)

Surfaces the standalone **HKDF-SHA512** (RFC 5869) primitive added in
[`metamorphic-crypto` 0.10.0](https://crates.io/crates/metamorphic-crypto), for
cross-language parity with the Rust core and WASM build. Fully **additive and
non-breaking**: no existing NIF, wire format, default, or export changes — only
one new function pair and its NIF binding. The native dependency is bumped
`0.9` → `0.10` (published crate only; no `[patch]`/path deps). `p256` remains
pinned at `=0.14.0-rc.14`.

- **`MetamorphicCrypto.KDF.hkdf_sha512/4`** (+ `!`) — HKDF-SHA512 (RFC 5869),
  one call performing Extract-then-Expand. Base64 in/out, byte-identical across
  native Rust, WASM (`hkdfSha512`), this NIF, and `@noble/hashes` / WebCrypto
  HKDF-SHA-512. Unlike the bare hashes in `MetamorphicCrypto.Hash`, this is the
  **correct** construction for deriving a key from *secret* input keying
  material, especially when combining more than one secret with auditable domain
  separation. `salt` / `ikm` are base64; `info` is a binary domain-separation
  label (normally a versioned UTF-8 string); `length` is the OKM length in bytes.
- **Salt semantics:** an empty `salt` means "not provided" (RFC 5869 §2.2), i.e.
  `HashLen` (64) zero bytes. `MetamorphicCrypto.KDF.hkdf_sha512_hash_len/0`
  returns the SHA-512 output length (`64`); the maximum OKM is `255 * 64 = 16320`
  bytes (a longer `length` returns `{:error, _}`).
- **Purpose:** combining two secrets into one wrapping key with auditable domain
  separation — specifically Mosslet's WebAuthn-PRF device-bound `user_key` wrap
  (board #362/#369):
  `HKDF-SHA512(salt = wrap_salt, ikm = password_key ‖ prf_output, info = "mosslet/user_key-wrap/v1", len = 32)`.
  The combine runs only in the browser (the server never sees the inputs); this
  NIF exists for parity, testing, and general server-side use.
- Cross-language parity: pinned **through the NIF** to the RFC 5869 Test Case 1
  inputs recomputed with SHA-512 (L = 42), reusing the Rust core's locked vector
  value-for-value, plus determinism, domain-separation, salt-None, and
  output-length tests.

## v0.7.0 (2026-06-30)

Surfaces the additive primitives added in
[`metamorphic-crypto` 0.8/0.9](https://crates.io/crates/metamorphic-crypto),
completing on-spec IETF KEYTRANS standard-suite support. Everything here is
**additive and non-breaking**: no existing NIF, wire format, default, or export
changes — only new modules and accessors. The native dependency is bumped
`0.7` → `0.9` (published crate only; no `[patch]`/path deps). `p256` remains
pinned at `=0.14.0-rc.14`.

- **`MetamorphicCrypto.Mac`** — HMAC-SHA256 (RFC 2104 / FIPS 198-1) via
  `hmac_sha256/2` (+ `!`). Base64 in/out, byte-identical across native Rust,
  WASM, and this NIF. The generic keyed-MAC primitive KEYTRANS standard suites
  use for commitments. Pinned to RFC 4231 test cases 1/2/3/6.
- **`MetamorphicCrypto.Vrf`** — ECVRF-Edwards25519-SHA512-TAI (RFC 9381, suite
  `0x03`): `generate_keypair/0`, `public_key/1`, `prove/2`, `verify/3`,
  `proof_to_hash/1`, and the suite/length constants. `verify/3` returns
  `{:ok, output}` for a valid proof, `:invalid` for a cryptographic rejection,
  and `{:error, reason}` for a structural (malformed-input) failure. Prove/verify
  run on the dirty CPU scheduler. Pinned to RFC 9381 Appendix B vectors.
- **`MetamorphicCrypto.VrfP256`** — ECVRF-P256-SHA256-TAI (RFC 9381, suite
  `0x01`; sk 32 / pk 33 / proof 81 / output 32), the on-spec VRF for the IETF
  `KT_128_SHA256_P256` KEYTRANS suite. Identical API shape and result contract to
  `MetamorphicCrypto.Vrf`. Pinned to RFC 9381 Appendix B.1 Examples 10/11/12.
- **`MetamorphicCrypto.Sign`** gains posture introspection:
  `signature_posture/1` (public key) and `signature_posture_from_signature/1`
  (signature) return `{:ok, {suite, level}}` typed atoms
  (`:hybrid | :hybrid_matched | :pure_cnsa2`, `:cat2 | :cat3 | :cat5`), or
  `{:error, reason}` for a malformed/wrong-length artifact. Read-only, no
  secrets; the raw wire tag stays private. Cat-2 canonically decodes to
  `{:hybrid, :cat2}`.
- Cross-language parity: HMAC and both VRFs verify their RFC known-answer vectors
  **through the NIF**, reusing the Rust core's locked vectors value-for-value so
  parity across native Rust / WASM / NIF is proven.

## v0.6.0 (2026-06-25)

Surfaces the **CNSA 2.0 suite axis** added in
[`metamorphic-crypto` 0.7.0](https://crates.io/crates/metamorphic-crypto). The
`Suite` axis is **orthogonal** to the existing security/signature level — pick
the ML-* parameter set with `level`, pick the *composition posture* with
`suite` — and is fully additive: existing keys, ciphertexts, signatures, and
wire formats are byte-for-byte unchanged, and `:hybrid` stays the default.

- `MetamorphicCrypto.Hybrid` (KEM / seal) gains the suite axis:
  - `generate_keypair_suite/2` — `{:ok, {pk, sk}}` for `(suite, level)`;
    `{:error, _}` for unsupported combinations (e.g. `:pure_cnsa2` below
    `:cat5`).
  - `seal_suite/5` and `seal_suite_raw/5` — seal under a `(suite, level)` with an
    optional `:context_label` (default `seal_context_v1/0`,
    `"metamorphic/seal/v1"`) bound into the HKDF-SHA512 `info` and AES-256-GCM
    AAD.
  - `open/3` and `open_raw/3` — open a new-suite ciphertext with an explicit
    context label. `open/2` still auto-detects the suite + level from the version
    tag and opens new suites under the default label.
  - New wire tags: `0x10` PureCnsa2 Cat-5 (ML-KEM-1024 + AES-256-GCM), `0x13`
    HybridMatched Cat-3 (ML-KEM-768 + X448), `0x14` HybridMatched Cat-5
    (ML-KEM-1024 + P-521 ECDH). HybridMatched Cat-1 reuses the existing `0x01`
    X25519 construction (no new format).
- `MetamorphicCrypto.Seal.seal_for_user/3` (and `seal_for_user_raw/3`) accept a
  `:suite` option. Non-default suites carry a new wire tag and must be opened
  with `MetamorphicCrypto.Hybrid.open/2,3` — `unseal_from_user/4` only
  auto-detects the legacy `:hybrid` tags.
- `MetamorphicCrypto.Sign` gains `generate_signing_keypair_suite/2`
  (`{:ok, keypair}` | `{:error, _}`) for the signature suites: `:pure_cnsa2`
  (ML-DSA-87, Cat-5; tag `0x10`) and `:hybrid_matched` (Cat-3 → Ed448 `0x13`,
  Cat-5 → hedged ECDSA-P-521 `0x14`). `sign/3`, `verify/4`, and
  `derive_public_key/1` are unchanged — they auto-detect the suite from the wire
  tag.
- Cross-language parity: new tests pin the deterministic signature public keys
  (SHA3-512 digests) to the exact vectors in the Rust core
  (`tests/cnsa2_vectors.rs`), and assert the documented FIPS-determined artifact
  sizes, so the NIF stays byte-identical to native Rust and WASM.
- Honesty posture (per project policy): "CNSA 2.0 algorithm suite, NCC-audited
  primitives, pure-Rust and memory-safe (`#![forbid(unsafe_code)]` at our
  layer)" — **not** "FIPS 140-3 validated." `:hybrid` remains the default and
  recommended posture: its strict-AND classical backstop guards against a
  lattice-implementation flaw until those implementations are independently
  audited. `:pure_cnsa2` is standards-compliant but drops that backstop.
- Sync the native crate dependency to `metamorphic-crypto` 0.7.

## v0.5.0 (2026-06-25)

- `MetamorphicCrypto.Hybrid` now surfaces the **Cat-1 (ML-KEM-512 + X25519)**
  tier, completing the full standardized ML-KEM range (NIST categories 1/3/5):
  - `generate_keypair/1` accepts `:cat1` (832-byte public key, 32-byte seed);
    `generate_keypair_512/0` is the convenience alias.
  - `seal/3` and `seal_raw/3` accept `:cat1`; `seal_512/2` and `seal_raw_512/2`
    are convenience aliases. Cat-1 ciphertexts carry version tag `0x01`
    (`0x01 || ML-KEM-512 ct (768 B) || X25519 eph pk (32 B) || nonce (24 B) || secretbox ct`).
  - `open/2` auto-detects Cat-1/Cat-3/Cat-5 from the version tag — no API change.
    `hybrid_ciphertext?/1` is length-aware, so short legacy ciphertexts that
    happen to begin with `0x01` are **not** misdetected as Cat-1.
- `MetamorphicCrypto.Seal.seal_for_user/3` (and `seal_for_user_raw/3`) now accept
  `level: :cat1`, mirroring the existing `:cat3`/`:cat5` options, so the unified
  seal/unseal API spans the full standardized ML-KEM range. `unseal_from_user/4`
  is unchanged — it already auto-detects the level from the version tag.
- Honesty note (NIST defines ML-KEM only at categories 1/3/5): there is no
  Cat-2/Cat-4 KEM. The classical half is always X25519 (~Cat-1 classical), the
  floor at every tier; the post-quantum half grows Cat-1 → Cat-3 → Cat-5. Wire
  version tags are scoped per artifact type: on the KEM side `0x01` = Cat-1
  (ML-KEM-512), whereas on the signature side `0x01` = Cat-2 (ML-DSA-44).
- Sync the native crate dependency to
  [`metamorphic-crypto` 0.6.0](https://crates.io/crates/metamorphic-crypto),
  which adds the Cat-1 KEM API. No change to existing encryption, hashing,
  signature, or wire formats.

## v0.4.0 (2026-06-24)

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

## v0.3.0 (2026-06-22)

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
