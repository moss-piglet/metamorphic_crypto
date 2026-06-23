defmodule MetamorphicCrypto.Hash do
  @moduledoc """
  SHA-3 and SHA-2 cryptographic hashing for **public** data.

  Thin, idiomatic wrappers over the audited `metamorphic-crypto` Rust core — the
  same primitives used by the native NIF and the browser WASM build, so a digest
  computed here is **byte-for-byte identical** to one computed in the browser.

  ## Which function?

  | Function                  | Algorithm | Output | Use for                              |
  |---------------------------|-----------|--------|--------------------------------------|
  | `sha3_512_with_context/2` | SHA3-512  | 64 B   | **Recommended** for fingerprints, safety numbers, transparency-log entries |
  | `sha3_512/1`              | SHA3-512  | 64 B   | General-purpose primitive (Cat-5)    |
  | `sha3_256/1`              | SHA3-256  | 32 B   | Same family as the hybrid KEM combiner |
  | `sha256/1`                | SHA-256   | 32 B   | SHA-2 interop with external systems  |
  | `sha512/1`                | SHA-512   | 64 B   | SHA-2 interop with external systems  |

  New code should standardize on **SHA3-512**, and on the domain-separated
  `sha3_512_with_context/2` for anything identity-like (key fingerprints, safety
  numbers, key-transparency-log entries). Use a versioned context label such as
  `"mosslet/key-fingerprint/v1"` so digests for different purposes can never
  collide and the scheme can be revised without ambiguity.

  ## Encoding (base64 in, base64 out)

  Every function takes **base64-encoded** data and returns the digest
  **base64-encoded**. This matches the rest of this package and the WASM wire
  format, which is what makes cross-target digests identical. If you have a raw
  Elixir binary, encode it first with `Base.encode64/1`; the `*_string/*`
  helpers do this for you.

  Want hex instead of base64? Decode then re-encode:

      {:ok, b64} = MetamorphicCrypto.Hash.sha3_512(Base.encode64("abc"))
      hex = b64 |> Base.decode64!() |> Base.encode16(case: :lower)

  ## Return shape

  Hashing itself is infallible, but base64 decoding of the input can fail, so
  these functions return `{:ok, digest_b64} | {:error, reason}` for consistency
  with the rest of the package. Each has a `!` variant that returns the digest
  directly and raises on invalid input.

  ## Security: public data only

  > #### These digests are for public data {: .warning}
  >
  > Hash both *input* and *output* that are meant to be public — key
  > fingerprints, safety numbers, transparency-log entries. The hashing path
  > intentionally performs **no** zeroize / constant-time ceremony. This is
  > deliberate: a bare hash makes no guarantees about its inputs, the underlying
  > RustCrypto primitives don't zeroize their state, and wiping a transient copy
  > of already-public data adds cost without protection (consistent with the
  > crate's "zeroize secrets only" policy).
  >
  > **Do not hash secret material** (passwords, private keys) with these. For
  > secrets, use `MetamorphicCrypto.KDF.derive_session_key/2` (Argon2id) or a
  > dedicated KDF/MAC.
  """

  alias MetamorphicCrypto.Native

  @doc """
  SHA3-512 of base64-encoded `data`, returning a base64-encoded 64-byte digest.

  This is the recommended general-purpose digest. For fingerprints, safety
  numbers, and log entries prefer `sha3_512_with_context/2`.

  ## Example

      iex> MetamorphicCrypto.Hash.sha3_512(Base.encode64("abc"))
      {:ok, "t1GFCxpXFopWk82SS2sJbgj2IYJ0RPcNiE9dAkDScS4Q4RbpGSrzyRp+xXZH45NAVzQLTPQI1aVlkvgnTuxT8A=="}

  """
  @spec sha3_512(data_b64 :: String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def sha3_512(data_b64) when is_binary(data_b64) do
    wrap(Native.nif_sha3_512(data_b64))
  end

  @doc """
  Same as `sha3_512/1` but returns the digest directly, raising on invalid input.
  """
  @spec sha3_512!(data_b64 :: String.t()) :: String.t()
  def sha3_512!(data_b64), do: unwrap!(sha3_512(data_b64))

  @doc """
  Domain-separated SHA3-512 — the **recommended** function for key fingerprints,
  safety numbers, and key-transparency-log entries.

  `context` is a UTF-8 label (use a versioned string like
  `"mosslet/key-fingerprint/v1"`); `data_b64` is the base64-encoded payload.
  Returns a base64-encoded 64-byte digest.

  The wire format is `SHA3-512(u64_be(byte_size(context)) || context || data)`,
  so different contexts over the same data yield unrelated digests, and the
  length prefix prevents `(context, data)` boundary ambiguities. It is exactly
  as collision- and preimage-resistant as `sha3_512/1` — it *is* SHA3-512 over a
  framed input.

  ## Example

      iex> MetamorphicCrypto.Hash.sha3_512_with_context("mosslet/key-fingerprint/v1", Base.encode64("public key bytes"))
      {:ok, "y/pbnlfUE85DjRUSFYNCJR1B19NFtpK8eJvoO6Ig2tsKOaknFLYbmUg5KWjtaiQn98nBDCI7X2Su8xFT0xQJng=="}

  """
  @spec sha3_512_with_context(context :: String.t(), data_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def sha3_512_with_context(context, data_b64)
      when is_binary(context) and is_binary(data_b64) do
    wrap(Native.nif_sha3_512_with_context(context, data_b64))
  end

  @doc """
  Same as `sha3_512_with_context/2` but returns the digest directly, raising on
  invalid input.
  """
  @spec sha3_512_with_context!(context :: String.t(), data_b64 :: String.t()) :: String.t()
  def sha3_512_with_context!(context, data_b64),
    do: unwrap!(sha3_512_with_context(context, data_b64))

  @doc """
  SHA3-256 of base64-encoded `data`, returning a base64-encoded 32-byte digest.

  ## Example

      iex> MetamorphicCrypto.Hash.sha3_256(Base.encode64("abc"))
      {:ok, "Ophdp0/iJbIEXBcta9OQvYVfCG4+nVJbRr/iRRFDFTI="}

  """
  @spec sha3_256(data_b64 :: String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def sha3_256(data_b64) when is_binary(data_b64) do
    wrap(Native.nif_sha3_256(data_b64))
  end

  @doc """
  Same as `sha3_256/1` but returns the digest directly, raising on invalid input.
  """
  @spec sha3_256!(data_b64 :: String.t()) :: String.t()
  def sha3_256!(data_b64), do: unwrap!(sha3_256(data_b64))

  @doc """
  SHA-256 (SHA-2) of base64-encoded `data`, returning a base64-encoded 32-byte
  digest. Provided for interop; prefer `sha3_512/1` for new code.

  ## Example

      iex> MetamorphicCrypto.Hash.sha256(Base.encode64("abc"))
      {:ok, "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="}

  """
  @spec sha256(data_b64 :: String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def sha256(data_b64) when is_binary(data_b64) do
    wrap(Native.nif_sha256(data_b64))
  end

  @doc """
  Same as `sha256/1` but returns the digest directly, raising on invalid input.
  """
  @spec sha256!(data_b64 :: String.t()) :: String.t()
  def sha256!(data_b64), do: unwrap!(sha256(data_b64))

  @doc """
  SHA-512 (SHA-2) of base64-encoded `data`, returning a base64-encoded 64-byte
  digest. Provided for interop; prefer `sha3_512/1` for new code.

  ## Example

      iex> MetamorphicCrypto.Hash.sha512(Base.encode64("abc"))
      {:ok, "3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw=="}

  """
  @spec sha512(data_b64 :: String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def sha512(data_b64) when is_binary(data_b64) do
    wrap(Native.nif_sha512(data_b64))
  end

  @doc """
  Same as `sha512/1` but returns the digest directly, raising on invalid input.
  """
  @spec sha512!(data_b64 :: String.t()) :: String.t()
  def sha512!(data_b64), do: unwrap!(sha512(data_b64))

  # ─── Internal ──────────────────────────────────────────────────────────────

  defp wrap({:error, reason}), do: {:error, reason}
  defp wrap(digest) when is_binary(digest), do: {:ok, digest}

  defp unwrap!({:ok, digest}), do: digest
  defp unwrap!({:error, reason}), do: raise("hashing failed: #{reason}")
end
