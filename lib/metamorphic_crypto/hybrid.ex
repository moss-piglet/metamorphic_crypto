defmodule MetamorphicCrypto.Hybrid do
  @moduledoc """
  ML-KEM + X25519 hybrid post-quantum encryption.

  Provides quantum-resistant key encapsulation by combining:

  - **ML-KEM** (NIST FIPS 203) — lattice-based post-quantum KEM
  - **X25519** — classical elliptic-curve Diffie-Hellman

  ## Security Levels

  | Level | ML-KEM | NIST Category | Equivalent | Version Tag |
  |-------|--------|---------------|------------|-------------|
  | Cat-1 | 512    | 1             | ~AES-128   | `0x01`      |
  | Cat-3 | 768    | 3             | ~AES-192   | `0x02`      |
  | Cat-5 | 1024   | 5             | ~AES-256   | `0x03`      |

  Pass `:cat1`, `:cat3`, or `:cat5` to choose the security level. The default is `:cat3`.

  > #### NIST defines ML-KEM only at categories 1/3/5 {: .info}
  >
  > FIPS 203 standardizes ML-KEM at parameter sets 512/768/1024, mapping to NIST
  > security categories 1/3/5. There is intentionally **no** Cat-2 or Cat-4 KEM —
  > this module never invents one. The classical half of the hybrid is always
  > X25519 (~Cat-1 classical), so X25519 is the classical floor at every tier; the
  > post-quantum half is what grows from Cat-1 → Cat-3 → Cat-5.
  >
  > Note the per-artifact-type wire-format version tags: on the **KEM** side `0x01`
  > denotes Cat-1 (ML-KEM-512), whereas on the **signature** side `0x01` denotes
  > Cat-2 (ML-DSA-44). The version byte is scoped to its artifact type; the two
  > schemes agree on the shared Cat-3/Cat-5 rungs.

  ## Ciphertext formats

      v1 (Cat-1): 0x01 || ML-KEM-512 ct (768 B)  || X25519 eph pk (32 B) || nonce (24 B) || secretbox ct
      v2 (Cat-3): 0x02 || ML-KEM-768 ct (1088 B) || X25519 eph pk (32 B) || nonce (24 B) || secretbox ct
      v3 (Cat-5): 0x03 || ML-KEM-1024 ct (1568 B) || X25519 eph pk (32 B) || nonce (24 B) || secretbox ct

  ## Key sizes

  | Component | Cat-1 | Cat-3 | Cat-5 |
  |-----------|-------|-------|-------|
  | Public key | 832 bytes | 1216 bytes | 1600 bytes |
  | Secret key (seed) | 32 bytes | 32 bytes | 32 bytes |

  ## Usage

      # Cat-3 (default)
      {pk, sk} = MetamorphicCrypto.Hybrid.generate_keypair()
      {:ok, ct} = MetamorphicCrypto.Hybrid.seal("quantum-safe secret", pk)
      {:ok, "quantum-safe secret"} = MetamorphicCrypto.Hybrid.open(ct, sk)

      # Cat-1 (ML-KEM-512, lightest standardized tier)
      {pk, sk} = MetamorphicCrypto.Hybrid.generate_keypair(:cat1)
      {:ok, ct} = MetamorphicCrypto.Hybrid.seal("quantum-safe secret", pk, :cat1)
      {:ok, "quantum-safe secret"} = MetamorphicCrypto.Hybrid.open(ct, sk)

      # Cat-5 (ML-KEM-1024, highest security)
      {pk, sk} = MetamorphicCrypto.Hybrid.generate_keypair(:cat5)
      {:ok, ct} = MetamorphicCrypto.Hybrid.seal("top secret", pk, :cat5)
      {:ok, "top secret"} = MetamorphicCrypto.Hybrid.open(ct, sk)

  """

  alias MetamorphicCrypto.Native

  @typedoc """
  NIST post-quantum security level.

  - `:cat1` — ML-KEM-512 + X25519 (~AES-128, NIST Category 1).
  - `:cat3` — ML-KEM-768 + X25519 (~AES-192, NIST Category 3). Default.
  - `:cat5` — ML-KEM-1024 + X25519 (~AES-256, NIST Category 5).
  """
  @type security_level :: :cat1 | :cat3 | :cat5

  @typedoc """
  CNSA 2.0 **suite** axis (orthogonal to `t:security_level/0`).

  `security_level` picks the ML-KEM parameter set; `suite` picks the
  *composition posture*:

  - `:hybrid` — **default & recommended.** Existing ML-KEM + X25519 strict-AND
    construction. Byte-for-byte unchanged; classical floor is X25519 (~Cat-1) at
    every level. Wire tags `0x01`/`0x02`/`0x03`.
  - `:hybrid_matched` — opt-in. The classical partner is matched *to the PQ
    category* so it is never the weak link: Cat-1 → X25519 (identical to
    `:hybrid`, no new format), Cat-3 → X448 (tag `0x13`), Cat-5 → P-521 ECDH
    (tag `0x14`).
  - `:pure_cnsa2` — opt-in, **Cat-5 only.** Pure ML-KEM-1024 + AES-256-GCM, no
    classical half — the NSA CNSA 2.0 box (tag `0x10`). Standards-compliant but
    without the classical backstop the default `:hybrid` keeps until the lattice
    implementation is independently audited.

  > #### Honest posture {: .info}
  >
  > CNSA 2.0 algorithm suite, NCC-audited primitives, pure-Rust and memory-safe
  > (`#![forbid(unsafe_code)]` at our layer) — **not** "FIPS 140-3 validated."
  """
  @type suite :: :hybrid | :hybrid_matched | :pure_cnsa2

  @seal_context_v1 "metamorphic/seal/v1"

  @doc """
  The default versioned context label bound into the new CNSA 2.0 seal suites:
  `"metamorphic/seal/v1"`.

  Grammar: `"<namespace>/<purpose>/v<major>"`. The **namespace** is the one
  per-tenant knob (pass your own, e.g. `"mosslet/seal/v1"`); the label is bound
  into both the HKDF-SHA512 `info` and the AES-256-GCM AAD. It is ignored by the
  legacy `:hybrid` suite (tags `0x01`/`0x02`/`0x03`), which binds no context.

  ## Example

      iex> MetamorphicCrypto.Hybrid.seal_context_v1()
      "metamorphic/seal/v1"

  """
  @spec seal_context_v1() :: String.t()
  def seal_context_v1, do: @seal_context_v1

  # ─── Key generation ──────────────────────────────────────────────────────────

  @doc """
  Generate a hybrid ML-KEM + X25519 keypair.

  Accepts an optional `t:security_level/0` (defaults to `:cat3`).

  Returns `{public_key_b64, secret_key_b64}`.

  ## Examples

      # Cat-3 (default)
      {pk, sk} = MetamorphicCrypto.Hybrid.generate_keypair()

      # Cat-5
      {pk, sk} = MetamorphicCrypto.Hybrid.generate_keypair(:cat5)

  """
  @spec generate_keypair(security_level()) :: {String.t(), String.t()}
  def generate_keypair(level \\ :cat3)

  def generate_keypair(:cat1), do: Native.nif_generate_hybrid_keypair_512()
  def generate_keypair(:cat3), do: Native.nif_generate_hybrid_keypair()
  def generate_keypair(:cat5), do: Native.nif_generate_hybrid_keypair_1024()

  @doc """
  Generate a hybrid ML-KEM-512 + X25519 keypair (Cat-1, lightest standardized tier).

  Convenience alias for `generate_keypair(:cat1)`.

  Returns `{public_key_b64, secret_key_b64}`.

  ## Example

      {pk, sk} = MetamorphicCrypto.Hybrid.generate_keypair_512()

  """
  @spec generate_keypair_512() :: {String.t(), String.t()}
  def generate_keypair_512, do: generate_keypair(:cat1)

  @doc """
  Generate a hybrid ML-KEM-1024 + X25519 keypair (Cat-5, highest security).

  Convenience alias for `generate_keypair(:cat5)`.

  Returns `{public_key_b64, secret_key_b64}`.

  ## Example

      {pk, sk} = MetamorphicCrypto.Hybrid.generate_keypair_1024()

  """
  @spec generate_keypair_1024() :: {String.t(), String.t()}
  def generate_keypair_1024, do: generate_keypair(:cat5)

  # ─── Seal ────────────────────────────────────────────────────────────────────

  @doc """
  Seal a UTF-8 plaintext string using hybrid post-quantum encryption.

  Accepts an optional `t:security_level/0` (defaults to `:cat3`).

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.

  ## Examples

      # Cat-3 (default)
      {pk, _sk} = MetamorphicCrypto.Hybrid.generate_keypair()
      {:ok, ct} = MetamorphicCrypto.Hybrid.seal("secret data", pk)

      # Cat-5
      {pk, _sk} = MetamorphicCrypto.Hybrid.generate_keypair(:cat5)
      {:ok, ct} = MetamorphicCrypto.Hybrid.seal("secret data", pk, :cat5)

  """
  @spec seal(plaintext :: String.t(), public_key_b64 :: String.t(), security_level()) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal(plaintext, public_key_b64, level \\ :cat3) when is_binary(plaintext) do
    plaintext_b64 = Base.encode64(plaintext)
    seal_raw(plaintext_b64, public_key_b64, level)
  end

  @doc """
  Seal a UTF-8 plaintext string using Cat-1 hybrid post-quantum encryption (ML-KEM-512).

  Convenience alias for `seal(plaintext, public_key_b64, :cat1)`.

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.

  ## Example

      {pk, _sk} = MetamorphicCrypto.Hybrid.generate_keypair(:cat1)
      {:ok, ct} = MetamorphicCrypto.Hybrid.seal_512("quantum-safe secret", pk)

  """
  @spec seal_512(plaintext :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal_512(plaintext, public_key_b64) when is_binary(plaintext) do
    seal(plaintext, public_key_b64, :cat1)
  end

  @doc """
  Seal a UTF-8 plaintext string using Cat-5 hybrid post-quantum encryption (ML-KEM-1024).

  Convenience alias for `seal(plaintext, public_key_b64, :cat5)`.

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.

  ## Example

      {pk, _sk} = MetamorphicCrypto.Hybrid.generate_keypair(:cat5)
      {:ok, ct} = MetamorphicCrypto.Hybrid.seal_1024("top secret", pk)

  """
  @spec seal_1024(plaintext :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal_1024(plaintext, public_key_b64) when is_binary(plaintext) do
    seal(plaintext, public_key_b64, :cat5)
  end

  @doc """
  Seal raw bytes (as base64) using hybrid post-quantum encryption.

  Accepts an optional `t:security_level/0` (defaults to `:cat3`).

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.
  """
  @spec seal_raw(plaintext_b64 :: String.t(), public_key_b64 :: String.t(), security_level()) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal_raw(plaintext_b64, public_key_b64, level \\ :cat3)

  def seal_raw(plaintext_b64, public_key_b64, :cat1) do
    case Native.nif_hybrid_seal_512(plaintext_b64, public_key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  def seal_raw(plaintext_b64, public_key_b64, :cat3) do
    case Native.nif_hybrid_seal(plaintext_b64, public_key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  def seal_raw(plaintext_b64, public_key_b64, :cat5) do
    case Native.nif_hybrid_seal_1024(plaintext_b64, public_key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  @doc """
  Seal raw bytes (as base64) using Cat-5 hybrid post-quantum encryption.

  Convenience alias for `seal_raw(plaintext_b64, public_key_b64, :cat5)`.

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.
  """
  @spec seal_raw_1024(plaintext_b64 :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal_raw_1024(plaintext_b64, public_key_b64) do
    seal_raw(plaintext_b64, public_key_b64, :cat5)
  end

  @doc """
  Seal raw bytes (as base64) using Cat-1 hybrid post-quantum encryption.

  Convenience alias for `seal_raw(plaintext_b64, public_key_b64, :cat1)`.

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.
  """
  @spec seal_raw_512(plaintext_b64 :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal_raw_512(plaintext_b64, public_key_b64) do
    seal_raw(plaintext_b64, public_key_b64, :cat1)
  end

  # ─── CNSA 2.0 Suite axis ─────────────────────────────────────────────────────

  @doc """
  Generate a keypair for the given `t:suite/0` + `t:security_level/0`.

  `:hybrid` (any level) and `:hybrid_matched` at `:cat1` produce the existing
  ML-KEM + X25519 keys (byte-identical to `generate_keypair/1`). The matched
  Cat-3/Cat-5 and pure suites produce the new combined-key layouts; the secret
  key stays a single 32-byte root seed.

  Returns `{:ok, {public_key_b64, secret_key_b64}}`, or `{:error, reason}` for
  unsupported combinations (e.g. `:pure_cnsa2` below `:cat5`).

  ## Examples

      # Pure CNSA 2.0 (ML-KEM-1024, Cat-5 only)
      {:ok, {pk, sk}} = MetamorphicCrypto.Hybrid.generate_keypair_suite(:pure_cnsa2, :cat5)

      # Matched-strength hybrid (ML-KEM-768 + X448)
      {:ok, {pk, sk}} = MetamorphicCrypto.Hybrid.generate_keypair_suite(:hybrid_matched, :cat3)

  """
  @spec generate_keypair_suite(suite(), security_level()) ::
          {:ok, {String.t(), String.t()}} | {:error, String.t()}
  def generate_keypair_suite(suite, level \\ :cat5)
      when suite in [:hybrid, :hybrid_matched, :pure_cnsa2] and
             level in [:cat1, :cat3, :cat5] do
    suite
    |> nif_suite()
    |> then(&Native.nif_generate_hybrid_keypair_suite(&1, Atom.to_string(level)))
    |> wrap_pair()
  end

  @doc """
  Seal a UTF-8 plaintext string under the given `t:suite/0` + `t:security_level/0`.

  Accepts an optional `:context_label` (defaults to `seal_context_v1/0`) which is
  bound into the HKDF-SHA512 `info` and AES-256-GCM AAD for the new CNSA 2.0
  suites; it is ignored by the legacy `:hybrid` suite. Open the result with
  `open/2` (default label) or `open/3` (custom label).

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.

  ## Examples

      {:ok, {pk, sk}} = MetamorphicCrypto.Hybrid.generate_keypair_suite(:pure_cnsa2, :cat5)
      {:ok, ct} = MetamorphicCrypto.Hybrid.seal_suite("top secret", pk, :pure_cnsa2, :cat5)
      {:ok, "top secret"} = MetamorphicCrypto.Hybrid.open(ct, sk)

      # Custom per-tenant context label
      {:ok, ct} =
        MetamorphicCrypto.Hybrid.seal_suite("secret", pk, :pure_cnsa2, :cat5,
          context_label: "mosslet/seal/v1")
      {:ok, "secret"} = MetamorphicCrypto.Hybrid.open(ct, sk, "mosslet/seal/v1")

  """
  @spec seal_suite(
          plaintext :: String.t(),
          public_key_b64 :: String.t(),
          suite(),
          security_level(),
          opts :: keyword()
        ) :: {:ok, String.t()} | {:error, String.t()}
  def seal_suite(plaintext, public_key_b64, suite, level, opts \\ [])
      when is_binary(plaintext) do
    plaintext
    |> Base.encode64()
    |> seal_suite_raw(public_key_b64, suite, level, opts)
  end

  @doc """
  Seal raw bytes (as base64) under the given `t:suite/0` + `t:security_level/0`.

  Same as `seal_suite/5` but accepts pre-encoded base64 plaintext. Supports the
  same `:context_label` option.

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.
  """
  @spec seal_suite_raw(
          plaintext_b64 :: String.t(),
          public_key_b64 :: String.t(),
          suite(),
          security_level(),
          opts :: keyword()
        ) :: {:ok, String.t()} | {:error, String.t()}
  def seal_suite_raw(plaintext_b64, public_key_b64, suite, level, opts \\ [])
      when suite in [:hybrid, :hybrid_matched, :pure_cnsa2] and
             level in [:cat1, :cat3, :cat5] do
    s = nif_suite(suite)
    l = Atom.to_string(level)

    result =
      case Keyword.get(opts, :context_label) do
        nil ->
          Native.nif_hybrid_seal_suite(plaintext_b64, public_key_b64, s, l)

        label when is_binary(label) ->
          Native.nif_hybrid_seal_suite_with_context(plaintext_b64, public_key_b64, s, l, label)
      end

    case result do
      {:error, reason} -> {:error, reason}
      ct -> {:ok, ct}
    end
  end

  # ─── Open (auto-detects Cat-1, Cat-3, or Cat-5) ─────────────────────────────

  @doc """
  Open a hybrid-sealed ciphertext, returning the decrypted UTF-8 string.

  Automatically detects the suite + level from the version tag byte: legacy
  `:hybrid` Cat-1/Cat-3/Cat-5 (`0x01`/`0x02`/`0x03`) and the new CNSA 2.0 suites
  (`0x10` PureCnsa2, `0x13`/`0x14` HybridMatched). The new suites are opened with
  the **default** context label (`seal_context_v1/0`); use `open/3` to supply a
  custom per-tenant label.

  Returns `{:ok, plaintext}` or `{:error, reason}`.

  ## Example

      {pk, sk} = MetamorphicCrypto.Hybrid.generate_keypair()
      {:ok, ct} = MetamorphicCrypto.Hybrid.seal("hello PQ", pk)
      {:ok, "hello PQ"} = MetamorphicCrypto.Hybrid.open(ct, sk)

  """
  @spec open(ciphertext_b64 :: String.t(), secret_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def open(ciphertext_b64, secret_key_b64) do
    case open_raw(ciphertext_b64, secret_key_b64) do
      {:ok, plaintext_b64} -> {:ok, Base.decode64!(plaintext_b64)}
      error -> error
    end
  end

  @doc """
  Open a hybrid-sealed ciphertext, returning plaintext as base64.

  Automatically detects Cat-1, Cat-3, or Cat-5 from the version tag.

  Returns `{:ok, plaintext_b64}` or `{:error, reason}`.
  """
  @spec open_raw(ciphertext_b64 :: String.t(), secret_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def open_raw(ciphertext_b64, secret_key_b64) do
    case Native.nif_hybrid_open(ciphertext_b64, secret_key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  @doc """
  Open a hybrid-sealed ciphertext using an explicit `context_label`.

  Required only for ciphertexts produced by a new CNSA 2.0 suite
  (`:hybrid_matched` Cat-3/Cat-5, `:pure_cnsa2`) with a non-default context
  label. Legacy `:hybrid` tags (`0x01`/`0x02`/`0x03`) ignore the label. The
  label must match the one passed to `seal_suite/5` at seal time.

  Returns `{:ok, plaintext}` or `{:error, reason}`.

  ## Example

      {:ok, ct} =
        MetamorphicCrypto.Hybrid.seal_suite("secret", pk, :pure_cnsa2, :cat5,
          context_label: "mosslet/seal/v1")
      {:ok, "secret"} = MetamorphicCrypto.Hybrid.open(ct, sk, "mosslet/seal/v1")

  """
  @spec open(
          ciphertext_b64 :: String.t(),
          secret_key_b64 :: String.t(),
          context_label :: String.t()
        ) ::
          {:ok, String.t()} | {:error, String.t()}
  def open(ciphertext_b64, secret_key_b64, context_label) when is_binary(context_label) do
    case open_raw(ciphertext_b64, secret_key_b64, context_label) do
      {:ok, plaintext_b64} -> {:ok, Base.decode64!(plaintext_b64)}
      error -> error
    end
  end

  @doc """
  Open a hybrid-sealed ciphertext with an explicit `context_label`, returning
  plaintext as base64. See `open/3`.

  Returns `{:ok, plaintext_b64}` or `{:error, reason}`.
  """
  @spec open_raw(
          ciphertext_b64 :: String.t(),
          secret_key_b64 :: String.t(),
          context_label :: String.t()
        ) :: {:ok, String.t()} | {:error, String.t()}
  def open_raw(ciphertext_b64, secret_key_b64, context_label) when is_binary(context_label) do
    case Native.nif_hybrid_open_with_context(ciphertext_b64, secret_key_b64, context_label) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  # ─── Utility ─────────────────────────────────────────────────────────────────

  @doc """
  Check if a base64 ciphertext uses the hybrid format (v1 Cat-1, v2 Cat-3, or v3 Cat-5).

  ## Example

      MetamorphicCrypto.Hybrid.hybrid_ciphertext?(ciphertext)
      #=> true

  """
  @spec hybrid_ciphertext?(ciphertext_b64 :: String.t()) :: boolean()
  def hybrid_ciphertext?(ciphertext_b64) do
    Native.nif_is_hybrid_ciphertext(ciphertext_b64)
  end

  # ─── Internal ────────────────────────────────────────────────────────────────

  defp nif_suite(:hybrid), do: "hybrid"
  defp nif_suite(:hybrid_matched), do: "hybrid_matched"
  defp nif_suite(:pure_cnsa2), do: "pure_cnsa2"

  defp wrap_pair({:error, reason}), do: {:error, reason}
  defp wrap_pair({pk, sk}) when is_binary(pk) and is_binary(sk), do: {:ok, {pk, sk}}
end
