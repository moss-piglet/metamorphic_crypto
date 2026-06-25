# MetamorphicCrypto

[![Hex.pm](https://img.shields.io/hexpm/v/metamorphic_crypto.svg)](https://hex.pm/packages/metamorphic_crypto)
[![Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/metamorphic_crypto)

NaCl-compatible encryption for Elixir — server-side.

Symmetric and public-key encryption, Argon2id key derivation,
**ML-KEM-512/768/1024 + X25519 hybrid post-quantum encryption**, and human-readable
recovery keys — powered by Rust NIFs with precompiled binaries.

```elixir
key = MetamorphicCrypto.generate_key()
{:ok, ciphertext} = MetamorphicCrypto.encrypt("hello", key)
{:ok, "hello"} = MetamorphicCrypto.decrypt(ciphertext, key)
```

## Installation

Add `metamorphic_crypto` to your `mix.exs`:

```elixir
def deps do
  [
    {:metamorphic_crypto, "~> 0.2"}
  ]
end
```

Then:

```bash
mix deps.get
```

That's it. Precompiled NIF binaries download automatically for your platform.
No Rust toolchain, no C compiler, no system packages.

### Why not enacl?

`enacl` wraps libsodium via C NIFs. It requires libsodium headers installed
system-wide, a C compiler toolchain, and often breaks on OTP upgrades or macOS
updates. CI pipelines need extra setup. Docker builds need `libsodium-dev`.

MetamorphicCrypto produces **identical ciphertext** (same NaCl wire format) but
ships as precompiled binaries — `mix deps.get` and it works. No system deps,
no compilation headaches, no chasing build failures across platforms.

## Quick Start

### Symmetric Encryption (SecretBox)

XSalsa20-Poly1305 authenticated encryption. Same format as libsodium.

```elixir
key = MetamorphicCrypto.generate_key()

{:ok, ciphertext} = MetamorphicCrypto.encrypt("sensitive data", key)
{:ok, "sensitive data"} = MetamorphicCrypto.decrypt(ciphertext, key)
```

### Public-Key Encryption (Sealed Box)

Anonymous encryption to a recipient's public key. Only they can decrypt.

```elixir
{public_key, private_key} = MetamorphicCrypto.generate_keypair()

{:ok, sealed} = MetamorphicCrypto.seal("for your eyes only", public_key)
{:ok, "for your eyes only"} = MetamorphicCrypto.unseal(sealed, public_key, private_key)
```

### Post-Quantum Hybrid Encryption

Three security levels available, spanning the full standardized ML-KEM range
(NIST categories 1/3/5). Cat-3 (ML-KEM-768, ~AES-192) is the default. Cat-5
(ML-KEM-1024, ~AES-256) is available for highest-security use cases, and Cat-1
(ML-KEM-512, ~AES-128) for lightweight/constrained ones.

```elixir
# Cat-3 (default) — ML-KEM-768 + X25519
{pq_pk, pq_sk} = MetamorphicCrypto.Hybrid.generate_keypair()

{:ok, ciphertext} = MetamorphicCrypto.Hybrid.seal("quantum-safe", pq_pk)
{:ok, "quantum-safe"} = MetamorphicCrypto.Hybrid.open(ciphertext, pq_sk)

# Cat-1 (opt-in) — ML-KEM-512 + X25519, lightest standardized tier
{pq_pk_512, pq_sk_512} = MetamorphicCrypto.Hybrid.generate_keypair_512()

{:ok, ciphertext} = MetamorphicCrypto.Hybrid.seal_512("quantum-safe", pq_pk_512)
{:ok, "quantum-safe"} = MetamorphicCrypto.Hybrid.open(ciphertext, pq_sk_512)

# Cat-5 (opt-in) — ML-KEM-1024 + X25519, highest security
{pq_pk_1024, pq_sk_1024} = MetamorphicCrypto.Hybrid.generate_keypair_1024()

{:ok, ciphertext} = MetamorphicCrypto.Hybrid.seal_1024("top secret", pq_pk_1024)
{:ok, "top secret"} = MetamorphicCrypto.Hybrid.open(ciphertext, pq_sk_1024)
```

`open/2` auto-detects the ciphertext format from the version tag byte:

| Version | Format                       | Security                  |
| ------- | ---------------------------- | ------------------------- |
| (none)  | Legacy X25519 sealed box     | Classical                 |
| `0x01`  | ML-KEM-512 + X25519 (Cat-1)  | ~AES-128, NIST Category 1 |
| `0x02`  | ML-KEM-768 + X25519 (Cat-3)  | ~AES-192, NIST Category 3 |
| `0x03`  | ML-KEM-1024 + X25519 (Cat-5) | ~AES-256, NIST Category 5 |

This means you can upgrade security levels progressively — existing ciphertext
always decrypts correctly regardless of which level it was sealed at.

### Unified Seal/Unseal (Auto-Detecting)

Automatically uses PQ when available, falls back to classical. Detects format
on decrypt — old and new ciphertexts coexist seamlessly.

```elixir
{pk, sk} = MetamorphicCrypto.Keys.generate_keypair()
{pq_pk, pq_sk} = MetamorphicCrypto.Hybrid.generate_keypair()

# Encrypts with hybrid PQ
{:ok, ct} = MetamorphicCrypto.Seal.seal_for_user("secret", pk, pq_public_key: pq_pk)

# Decrypts (auto-detects format)
{:ok, "secret"} = MetamorphicCrypto.Seal.unseal_from_user(ct, pk, sk, pq_secret_key: pq_sk)
```

### Key Derivation (Argon2id)

Derive a session key from a password. Uses libsodium's interactive parameters
(64 MiB, 2 iterations).

```elixir
salt = MetamorphicCrypto.Keys.generate_salt()
{:ok, session_key} = MetamorphicCrypto.KDF.derive_session_key("user password", salt)
```

### Recovery Keys

Human-readable backup keys (like Matrix or Signal recovery codes).

```elixir
{:ok, recovery_key, secret} = MetamorphicCrypto.Recovery.generate()
# recovery_key => "ABCDE-FGHJK-LMNPQ-RSTUV-..."

# Back up a private key
{:ok, backup} = MetamorphicCrypto.Recovery.encrypt_private_key(private_key, secret)

# Restore later
{:ok, restored_secret} = MetamorphicCrypto.Recovery.key_to_secret(recovery_key)
{:ok, private_key} = MetamorphicCrypto.Recovery.decrypt_private_key(backup, restored_secret)
```

### Key Generation (Mix Task)

```bash
mix metamorphic_crypto.gen.key
```

### Hashing (SHA-3 / SHA-2)

Public-data hashing for key fingerprints, safety numbers, and
key-transparency-log entries — the same audited primitive used by the browser
WASM build, so digests are byte-for-byte identical across native and browser.

Base64 in, base64 out. Standardize on **SHA3-512**, and use the
domain-separated variant (with a versioned context label) for anything
identity-like:

```elixir
# General-purpose SHA3-512
{:ok, digest} = MetamorphicCrypto.sha3_512(Base.encode64("public data"))

# Recommended for fingerprints / safety numbers / log entries
{:ok, fingerprint} =
  MetamorphicCrypto.sha3_512_with_context(
    "mosslet/key-fingerprint/v1",
    Base.encode64("public key bytes")
  )

# Full menu lives in MetamorphicCrypto.Hash: sha3_512, sha3_256, sha256, sha512,
# sha3_512_with_context (+ ! variants).
```

Want hex instead of base64? `digest |> Base.decode64!() |> Base.encode16(case: :lower)`.

> **Public data only.** These digests are for data whose input and output are
> both meant to be public. They intentionally add no zeroize/constant-time
> ceremony. **Do not hash secrets** (passwords, private keys) with them — use
> `MetamorphicCrypto.KDF.derive_session_key/2` (Argon2id) for secret material.

### Signatures (hybrid ML-DSA + Ed25519)

Hybrid post-quantum signatures for transparency logs and key-transparency work
— every artifact is signed by **both** ML-DSA (FIPS 204) and Ed25519, and
verification requires **both** (strict AND), so an attacker must break a lattice
_and_ an elliptic-curve scheme to forge. Keys and signatures are base64; the
message is a raw binary and the context a UTF-8 label.

```elixir
# Cat-3 (ML-DSA-65 + Ed25519) is the default; :cat2 and :cat5 also available
kp = MetamorphicCrypto.generate_signing_keypair()

{:ok, sig} =
  MetamorphicCrypto.sign("log entry", MetamorphicCrypto.Sign.sign_context_v1(), kp.secret_key)

true = MetamorphicCrypto.verify("log entry", "metamorphic/sign/v1", sig, kp.public_key)

# Re-derive the verifying key from a (recovered) secret — byte-identical
{:ok, pk} = MetamorphicCrypto.derive_public_key(kp.secret_key)
```

ML-DSA uses the hedged/randomized FIPS 204 mode, so **signature bytes are
non-reproducible** (both verify). The wire format — version tags, byte layout,
and the `I2OSP(len(ctx), 8) || ctx || msg` domain separation — is deterministic,
so `derive_public_key/1` reproduces a verifying key byte-identically across
native, WASM, and this NIF (this is what keeps a TOFU-pinned key stable through
account recovery). Full menu in `MetamorphicCrypto.Sign`.

> **Keep the `secret_key` sensitive.** It is a 65-byte base64 blob. The native
> core zeroizes seed material on drop, but the Elixir base64 string is a regular
> binary — store it encrypted at rest and avoid logging it.

## Architecture Patterns

### When to Use This Library

MetamorphicCrypto runs **server-side** in the BEAM VM. Use it when:

- **You're replacing `enacl`** — drop-in replacement with precompiled binaries
  (no libsodium C compilation), same wire format, plus post-quantum
- **Your server legitimately holds encryption keys** — server-side NaCl crypto
  that's faster than pure Elixir and wire-compatible with libsodium clients
- **You need post-quantum encryption server-side** — ML-KEM-768 + X25519, first
  on Hex
- **You're transitioning to ZK incrementally** — existing server-side operations
  stay on MetamorphicCrypto while new features move to client-side WASM
- **Tests and fixtures** — generate NaCl-compatible ciphertext in ExUnit tests

### What This Library Does NOT Do

This library does **not** give you client-side zero-knowledge encryption. For
full ZK where the server never sees plaintext, the encryption must happen in
the browser — that requires the WASM build of the same Rust core, loaded via
a LiveView JS hook.

In a full ZK architecture (like [Metamorphic](https://metamorphic.app)), the
server is a dumb storage layer. The client does all the crypto. The server
doesn't need this library for that — it just stores and retrieves opaque blobs.

### Full Zero-Knowledge Architecture

If you want to build a ZK app, see the
[Zero-Knowledge Guide](docs/zero-knowledge-guide.md). The short version:

- **Client (WASM):** does ALL the encryption/decryption
- **Server:** stores opaque ciphertext, orchestrates key distribution events,
  wraps blobs with Cloak for defense-in-depth
- **This library's role:** optional — useful during migration, for generating
  test fixtures, or if you have specific server-side operations that need
  NaCl-compatible crypto

```
┌─────────────────────────────────────────────────────────────────┐
│  Client (browser)                                               │
│                                                                 │
│  password ──► Argon2id KDF ──► session_key                      │
│                                    │                            │
│                            decrypt private_key                  │
│                                    │                            │
│  plaintext ──► metamorphic-crypto (WASM) ──► ciphertext ──────┐ │
│                                                               │ │
└───────────────────────────────────────────────────────────────┼─┘
                                                                │
                                                         ───────┼──────
                                                                │
┌───────────────────────────────────────────────────────────────┼─┐
│  Server (Phoenix/LiveView)                                    ▼ │
│                                                                 │
│  Receives opaque ciphertext (cannot decrypt)                    │
│  Cloak wraps it in AES-256-GCM before writing to DB             │
│  (defense-in-depth against DB-level compromise)                 │
│                                                                 │
│  MetamorphicCrypto (optional): test fixtures, migration helper  │
└─────────────────────────────────────────────────────────────────┘
```

### Pattern: Replacing enacl

If you currently use `enacl` for server-side NaCl crypto, MetamorphicCrypto
is a direct replacement with better DX:

```elixir
# Before (enacl — requires compiling libsodium)
:enacl.crypto_secretbox(plaintext, nonce, key)

# After (MetamorphicCrypto — precompiled, no C toolchain)
MetamorphicCrypto.SecretBox.encrypt(plaintext, key)
```

Same ciphertext format. No data migration needed.

### Pattern: Transitioning to Zero-Knowledge

If your app currently does server-side encryption (with enacl or Cloak):

1. **Replace enacl** with MetamorphicCrypto (same wire format, no migration)
2. **Add the WASM client** to your Phoenix app (LiveView JS hooks)
3. **Move operations to the client** one by one — new features use client-side
   crypto, old features stay server-side temporarily
4. **Eventually** the server only stores opaque blobs and you may not need
   this library at all for user-data crypto

MetamorphicCrypto makes step 1 easy and ensures wire compatibility between
server and client during the transition (both produce identical ciphertext
from the same Rust core).

## Using with Cloak

MetamorphicCrypto and Cloak solve different problems:

|                       | Cloak                          | MetamorphicCrypto                  |
| --------------------- | ------------------------------ | ---------------------------------- |
| **Purpose**           | Server-side encryption-at-rest | NaCl-compatible crypto primitives  |
| **Who holds the key** | Server (env vars)              | Depends on your architecture       |
| **Cipher**            | AES-256-GCM                    | XSalsa20-Poly1305, ML-KEM-512/768/1024 |
| **Key rotation**      | Built-in                       | —                                  |
| **Ecto types**        | Binary, Map, Integer, HMAC     | —                                  |
| **Use for**           | PII at rest, blind indexes     | NaCl ops, enacl replacement, PQ    |

For encrypted Ecto fields and blind indexes, use Cloak. For NaCl-compatible
encryption operations and post-quantum crypto, use MetamorphicCrypto.

## Modules

| Module                        | Purpose                                                          |
| ----------------------------- | ---------------------------------------------------------------- |
| `MetamorphicCrypto`           | Top-level convenience API                                        |
| `MetamorphicCrypto.SecretBox` | XSalsa20-Poly1305 symmetric encryption                           |
| `MetamorphicCrypto.BoxSeal`   | X25519 anonymous sealed box                                      |
| `MetamorphicCrypto.Hybrid`    | ML-KEM-512/768/1024 + X25519 post-quantum hybrid                     |
| `MetamorphicCrypto.Seal`      | Unified seal/unseal with auto-detection                          |
| `MetamorphicCrypto.KDF`       | Argon2id key derivation                                          |
| `MetamorphicCrypto.Keys`      | Key generation and private key management                        |
| `MetamorphicCrypto.Hash`      | SHA3/SHA2 hashing for public data (fingerprints, safety numbers) |
| `MetamorphicCrypto.Sign`      | Hybrid ML-DSA + Ed25519 post-quantum signatures (strict-AND)     |
| `MetamorphicCrypto.Recovery`  | Human-readable recovery keys                                     |

## Wire Format Compatibility

All ciphertext produced by this library is **byte-compatible** with:

- [libsodium](https://doc.libsodium.org/) / NaCl (symmetric + sealed box)
- [TweetNaCl.js](https://tweetnacl.js.org/) (symmetric + sealed box)
- [enacl](https://github.com/aeternity/enacl) (Erlang libsodium bindings)
- The [`metamorphic-crypto`](https://crates.io/crates/metamorphic-crypto) WASM module (browser clients)

This means you can:

- **Replace `enacl`** in existing projects with no data migration
- **Decrypt on the server** what was encrypted in the browser (and vice versa)
- **Incrementally adopt** post-quantum encryption without breaking existing data

## Deployment

**No special deployment steps required.** Precompiled binaries cover:

| Platform      | Architectures                   |
| ------------- | ------------------------------- |
| Linux (glibc) | x86_64, aarch64                 |
| macOS         | x86_64, aarch64 (Apple Silicon) |
| Windows       | x86_64                          |

If you deploy to a platform not listed above, set `METAMORPHIC_CRYPTO_BUILD=true`
and ensure Rust is available in your build environment:

```bash
# In your Dockerfile (only if your platform isn't precompiled)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
ENV METAMORPHIC_CRYPTO_BUILD=true
```

For standard deployments (Fly.io, Gigalixir, Heroku, Docker on linux/amd64 or arm64),
precompiled binaries just work — no configuration needed.

## Building from Source

If you want to compile the NIF yourself (e.g., for development on this library):

```bash
export METAMORPHIC_CRYPTO_BUILD=true
mix deps.get
mix compile
```

Requires Rust 1.85+ (`rustup update`).

## Contributing

Contributions welcome! Please open an issue first for significant changes.

```bash
git clone https://github.com/moss-piglet/metamorphic_crypto.git
cd metamorphic_crypto
export METAMORPHIC_CRYPTO_BUILD=true
mix deps.get
mix test
```

## License

MIT — see [LICENSE](LICENSE).

Built by [Moss Piglet](https://github.com/moss-piglet). Maintained by [@f0rest8](https://github.com/f0rest8).
