defmodule MetamorphicCrypto.Sign do
  @moduledoc """
  Hybrid post-quantum signatures: ML-DSA (FIPS 204) + Ed25519 composite.

  Thin, idiomatic wrappers over the audited `metamorphic-crypto` Rust core — the
  same primitives used by the browser WASM build, so a key derived or a
  signature verified here behaves **byte-identically** across native Rust, WASM,
  and this NIF.

  Every message is signed by **both** a post-quantum algorithm (ML-DSA) **and** a
  classical one (Ed25519), and verification requires **both** component
  signatures to be valid (strict AND). An attacker must therefore break *both* a
  lattice scheme *and* an elliptic-curve scheme to forge a signature, and cannot
  strip one algorithm to downgrade the other — the length-framed, version-tagged
  wire format rejects signature-stripping and cross-protocol mix-and-match.

  This is the signing counterpart to `MetamorphicCrypto.Hybrid` (ML-KEM + X25519
  for *confidentiality*); here we combine ML-DSA + Ed25519 for *authenticity /
  integrity*. It is the foundational primitive for transparency logs and
  key-transparency work, where entries must be signed once and verified
  identically everywhere.

  ## Security levels

  ML-DSA is standardized by NIST at three parameter sets only — categories 2, 3,
  and 5 — and each is paired here with Ed25519:

  | Level   | ML-DSA    | NIST Category | Equivalent | Wire Tag | Default |
  |---------|-----------|---------------|------------|----------|---------|
  | `:cat2` | ML-DSA-44 | 2             | ~AES-128   | `0x01`   | No      |
  | `:cat3` | ML-DSA-65 | 3             | ~AES-192   | `0x02`   | Yes     |
  | `:cat5` | ML-DSA-87 | 5             | ~AES-256   | `0x03`   | No      |

  `:cat3` is the default, mirroring this package's KEM default posture.

  ### About the wire tags (namespacing note)

  The leading tag byte is a **per-artifact-type wire-format version**, *not* a
  global NIST-category code. A signature tag only ever appears as the first byte
  of a signature / key blob produced by this module and is parsed only by
  `verify/4` / `derive_public_key/1`; it is never handed to the KEM / seal code.
  Signatures and ciphertexts are distinct artifacts processed by distinct
  functions, so a signature tag can never be confused with a sealed-box or
  hybrid-KEM byte. The tags agree with the KEM tags on every level the two
  families share (`:cat3` = `0x02`, `:cat5` = `0x03`); they diverge only at
  `0x01` because NIST standardizes ML-KEM at categories {1, 3, 5} but ML-DSA at
  {2, 3, 5}, so "tag == category" cannot hold for both families.

  ## Signing mode (hedged / randomized ML-DSA)

  ML-DSA signatures use the **hedged (randomized)** variant from FIPS 204 — the
  standard's default and most conservative mode — which mixes fresh OS
  randomness into each signature. As a result the **signature bytes are not
  reproducible** (two signatures over the same message differ), but both verify.
  Ed25519 remains deterministic per RFC 8032.

  The **wire format is fully deterministic and pinnable**: the layout, version
  tags, public-key derivation, and the domain-separation framing are all fixed.
  Tests must therefore pin `derive_public_key/1` outputs, framing, and
  roundtrips — **never raw signature bytes**.

  ## Domain separation (stable wire format)

  Both algorithms sign the *same* domain-separated message, framed exactly like
  `MetamorphicCrypto.Hash.sha3_512_with_context/2` (a length-prefixed context):

      signed_msg = I2OSP(byte_size(context), 8) || context || message

  where `I2OSP(len, 8)` is the UTF-8 byte length of `context` as a big-endian
  unsigned 64-bit integer. The 8-byte length prefix makes the
  `(context, message)` boundary unambiguous. `context` is a UTF-8 label,
  conventionally a versioned namespace — see `sign_context_v1/0`.

  ## Byte layout

      signature  = tag || ed25519_sig (64 B) || ml_dsa_sig (2420 / 3309 / 4627 B)
      public_key = tag || ed25519_pk  (32 B) || ml_dsa_pk  (1312 / 1952 / 2592 B)
      secret_key = tag || ed25519_seed(32 B) || ml_dsa_seed(32 B)              = 65 B

  ## Encoding

  Keys and signatures are **base64 strings** (consistent with the rest of this
  package and the WASM wire format). The `message` argument is a **raw binary**
  (the bytes you are signing), and `context` is a plain UTF-8 string.

  ## Recovery hook

  `derive_public_key/1` re-derives the base64 public key deterministically from a
  base64 secret key. A secret recovered from backup (e.g. via
  `MetamorphicCrypto.Recovery`) therefore regenerates a **byte-identical**
  verifying key — so a pinned key (TOFU) stays the same across a recovery, and
  recovery will not false-trigger a key-change alert.

  ## Security: secret key handling

  > #### Treat the `secret_key` as sensitive {: .warning}
  >
  > The native core zeroizes secret seed material on drop. On the Elixir side the
  > base64 `secret_key` is a regular binary and is **not** zeroized — keep it
  > only as long as needed, store it encrypted at rest (see
  > `MetamorphicCrypto.Keys.encrypt_private_key/2`), and avoid logging it.
  """

  alias MetamorphicCrypto.Native

  @typedoc """
  Security level for a hybrid signing keypair.

  * `:cat2` — ML-DSA-44 + Ed25519 (~AES-128)
  * `:cat3` — ML-DSA-65 + Ed25519 (~AES-192), the default
  * `:cat5` — ML-DSA-87 + Ed25519 (~AES-256)
  """
  @type level :: :cat2 | :cat3 | :cat5

  @typedoc """
  CNSA 2.0 **suite** axis for signatures (orthogonal to `t:level/0`).

  - `:hybrid` — **default & recommended.** Existing ML-DSA + Ed25519 strict-AND
    composite, byte-for-byte unchanged (tags `0x01`/`0x02`/`0x03`).
  - `:hybrid_matched` — opt-in. The classical partner is matched to the PQ
    category: Cat-2 → Ed25519 (identical to `:hybrid`), Cat-3 → Ed448 (tag
    `0x13`), Cat-5 → ECDSA-P-521 hedged (tag `0x14`).
  - `:pure_cnsa2` — opt-in, **Cat-5 only.** Pure ML-DSA-87, no classical half —
    the NSA CNSA 2.0 signature box (tag `0x10`). Standards-compliant but without
    the classical backstop the default `:hybrid` keeps until the lattice
    implementation is independently audited.

  `sign/3`, `verify/4`, and `derive_public_key/1` auto-detect the suite from the
  wire tag, so only keypair generation takes a `suite` argument.
  """
  @type suite :: :hybrid | :hybrid_matched | :pure_cnsa2

  @typedoc """
  A hybrid ML-DSA + Ed25519 signing keypair, both fields base64-encoded.
  """
  @type keypair :: %{public_key: String.t(), secret_key: String.t()}

  @sign_context_v1 "metamorphic/sign/v1"

  @doc """
  The recommended versioned context label for general-purpose signing:
  `"metamorphic/sign/v1"`.

  Pass this (or another versioned `"namespace/purpose/vN"` label) as the
  `context` argument to `sign/3` / `verify/4` to bind signatures to a purpose.

  ## Example

      iex> MetamorphicCrypto.Sign.sign_context_v1()
      "metamorphic/sign/v1"

  """
  @spec sign_context_v1() :: String.t()
  def sign_context_v1, do: @sign_context_v1

  @doc """
  Generate a hybrid signing keypair at the given security `level` (default
  `:cat3`).

  Returns a map `%{public_key: base64, secret_key: base64}` using the documented
  byte layout. The two component algorithms are seeded from independent OS
  randomness.

  ## Examples

      kp = MetamorphicCrypto.Sign.generate_signing_keypair()
      kp = MetamorphicCrypto.Sign.generate_signing_keypair(:cat5)

  """
  @spec generate_signing_keypair(level()) :: keypair()
  def generate_signing_keypair(level \\ :cat3) when level in [:cat2, :cat3, :cat5] do
    {public_key, secret_key} = Native.nif_generate_signing_keypair(Atom.to_string(level))
    %{public_key: public_key, secret_key: secret_key}
  end

  @doc """
  Generate a hybrid signing keypair for the given `t:suite/0` + `t:level/0`
  (default `:cat5`).

  `:hybrid` (any level) and `:hybrid_matched` at `:cat2` produce the existing
  ML-DSA + Ed25519 keys (byte-identical to `generate_signing_keypair/1`). The
  matched Cat-3/Cat-5 and pure suites produce the new combined-key layouts.
  `sign/3` / `verify/4` / `derive_public_key/1` need no suite argument — they
  read it from the wire tag.

  Returns `{:ok, %{public_key: base64, secret_key: base64}}`, or
  `{:error, reason}` for unsupported combinations (e.g. `:pure_cnsa2` below
  `:cat5`).

  ## Examples

      # Pure CNSA 2.0 (ML-DSA-87, Cat-5 only)
      {:ok, kp} = MetamorphicCrypto.Sign.generate_signing_keypair_suite(:pure_cnsa2, :cat5)

      # Matched-strength hybrid (ML-DSA-65 + Ed448)
      {:ok, kp} = MetamorphicCrypto.Sign.generate_signing_keypair_suite(:hybrid_matched, :cat3)

  """
  @spec generate_signing_keypair_suite(suite(), level()) ::
          {:ok, keypair()} | {:error, String.t()}
  def generate_signing_keypair_suite(suite, level \\ :cat5)
      when suite in [:hybrid, :hybrid_matched, :pure_cnsa2] and level in [:cat2, :cat3, :cat5] do
    case Native.nif_generate_signing_keypair_suite(nif_suite(suite), Atom.to_string(level)) do
      {:error, reason} -> {:error, reason}
      {public_key, secret_key} -> {:ok, %{public_key: public_key, secret_key: secret_key}}
    end
  end

  @doc """
  Re-derive the base64 `public_key` from a base64 hybrid `secret_key`.

  Both component public keys are a deterministic function of the secret seeds, so
  this reproduces exactly the `public_key` returned by
  `generate_signing_keypair/1`. Useful for recovering a public key from a
  backed-up secret, or for checking that a secret/public pair belong together.
  The security level is read from the secret key's wire tag.

  Returns `{:ok, public_key_b64}` or `{:error, reason}` (invalid base64, wrong
  length, or unknown version tag).

  ## Example

      kp = MetamorphicCrypto.Sign.generate_signing_keypair()
      {:ok, pk} = MetamorphicCrypto.Sign.derive_public_key(kp.secret_key)
      # pk == kp.public_key

  """
  @spec derive_public_key(secret_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def derive_public_key(secret_key_b64) when is_binary(secret_key_b64) do
    wrap(Native.nif_derive_signing_public_key(secret_key_b64))
  end

  @doc """
  Same as `derive_public_key/1` but returns the public key directly, raising on
  invalid input.
  """
  @spec derive_public_key!(secret_key_b64 :: String.t()) :: String.t()
  def derive_public_key!(secret_key_b64), do: unwrap!(derive_public_key(secret_key_b64))

  @doc """
  Sign `message` under `context` with a base64 hybrid `secret_key`.

  `message` is a raw binary, `context` is a UTF-8 label (use `sign_context_v1/0`
  or another versioned string), and `secret_key` is base64. Produces a composite
  signature — a hedged (randomized) ML-DSA signature and a deterministic Ed25519
  signature, both over the domain-separated `frame(context, message)`. The
  security level is read from the secret key's wire tag.

  Returns `{:ok, signature_b64}` or `{:error, reason}`. Because ML-DSA signing is
  randomized, signing the same message twice yields different (both-valid)
  signatures — never pin the signature bytes.

  ## Example

      kp = MetamorphicCrypto.Sign.generate_signing_keypair()
      {:ok, sig} =
        MetamorphicCrypto.Sign.sign("log entry", MetamorphicCrypto.Sign.sign_context_v1(), kp.secret_key)

  """
  @spec sign(message :: binary(), context :: String.t(), secret_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def sign(message, context, secret_key_b64)
      when is_binary(message) and is_binary(context) and is_binary(secret_key_b64) do
    wrap(Native.nif_sign(message, context, secret_key_b64))
  end

  @doc """
  Same as `sign/3` but returns the signature directly, raising on invalid input.
  """
  @spec sign!(message :: binary(), context :: String.t(), secret_key_b64 :: String.t()) ::
          String.t()
  def sign!(message, context, secret_key_b64),
    do: unwrap!(sign(message, context, secret_key_b64))

  @doc """
  Verify a composite `signature` over `message` / `context` against `public_key`.

  `message` is a raw binary, `context` is the UTF-8 label used at signing time,
  and `signature` / `public_key` are base64. Returns `true` **only if both** the
  Ed25519 and ML-DSA component signatures verify (strict AND).

  Returns `false` for any verification failure — a tampered message/context, a
  wrong key, a tampered half-signature, a cross-level or stripped artifact, **or**
  a malformed input (invalid base64 / unknown version tag). The function never
  raises and never returns an error tuple: a non-`true` result always means "not
  a valid signature", which is the safe default for a verifier.

  ## Example

      kp = MetamorphicCrypto.Sign.generate_signing_keypair()
      {:ok, sig} = MetamorphicCrypto.Sign.sign("msg", "metamorphic/sign/v1", kp.secret_key)
      true = MetamorphicCrypto.Sign.verify("msg", "metamorphic/sign/v1", sig, kp.public_key)

  """
  @spec verify(
          message :: binary(),
          context :: String.t(),
          signature_b64 :: String.t(),
          public_key_b64 :: String.t()
        ) :: boolean()
  def verify(message, context, signature_b64, public_key_b64)
      when is_binary(message) and is_binary(context) and is_binary(signature_b64) and
             is_binary(public_key_b64) do
    case Native.nif_verify(message, context, signature_b64, public_key_b64) do
      result when is_boolean(result) -> result
      {:error, _reason} -> false
    end
  end

  # ─── Internal ──────────────────────────────────────────────────────────────

  defp nif_suite(:hybrid), do: "hybrid"
  defp nif_suite(:hybrid_matched), do: "hybrid_matched"
  defp nif_suite(:pure_cnsa2), do: "pure_cnsa2"

  defp wrap({:error, reason}), do: {:error, reason}
  defp wrap(value) when is_binary(value), do: {:ok, value}

  defp unwrap!({:ok, value}), do: value
  defp unwrap!({:error, reason}), do: raise("signing failed: #{reason}")
end
