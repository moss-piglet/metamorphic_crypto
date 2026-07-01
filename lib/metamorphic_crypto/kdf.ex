defmodule MetamorphicCrypto.KDF do
  @moduledoc """
  Key derivation functions.

  Two complementary KDFs, both thin wrappers over the audited `metamorphic-crypto`
  Rust core so their outputs are byte-for-byte identical to the native and WASM
  builds:

  - `derive_session_key/2` — **Argon2id**, for stretching a low-entropy
    *password* into a key (deliberately slow + memory-hard).
  - `hkdf_sha512/4` — **HKDF-SHA512** (RFC 5869), for combining and diversifying
    already-high-entropy *secret* key material with domain separation (fast).

  ## Argon2id (`derive_session_key/2`)

  Derives a 32-byte session key from a password and 16-byte salt using Argon2id
  with libsodium's `OPSLIMIT_INTERACTIVE` / `MEMLIMIT_INTERACTIVE` parameters:

  - Time cost: 2 iterations
  - Memory cost: 64 MiB
  - Output: 32 bytes

  This is typically used to derive a session key from a user's password, which
  then decrypts their private key stored on the server.

      salt = MetamorphicCrypto.Keys.generate_salt()
      {:ok, session_key} = MetamorphicCrypto.KDF.derive_session_key("my password", salt)

  > **Note**: This function is intentionally expensive (64 MiB memory, ~200ms).
  > It runs on a dirty CPU scheduler to avoid blocking the BEAM.

  ## HKDF-SHA512 (`hkdf_sha512/4`)

  Extract-then-Expand over SHA-512. Use this — not the bare hashes in
  `MetamorphicCrypto.Hash` — whenever you need to derive a key from **secret**
  input keying material, especially when combining more than one secret. See
  `hkdf_sha512/4` for details.

  """

  alias MetamorphicCrypto.Native

  @doc """
  Derive a 32-byte session key from a password and base64-encoded 16-byte salt.

  Returns `{:ok, key_b64}` or `{:error, reason}`.

  ## Example

      salt = MetamorphicCrypto.Keys.generate_salt()
      {:ok, key} = MetamorphicCrypto.KDF.derive_session_key("correct horse battery staple", salt)

  """
  @spec derive_session_key(password :: String.t(), salt_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def derive_session_key(password, salt_b64) when is_binary(password) and is_binary(salt_b64) do
    case Native.nif_derive_session_key(password, salt_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  @doc """
  Derive a session key, raising on failure.

  ## Example

      key = MetamorphicCrypto.KDF.derive_session_key!("password", salt)

  """
  @spec derive_session_key!(password :: String.t(), salt_b64 :: String.t()) :: String.t()
  def derive_session_key!(password, salt_b64) do
    case derive_session_key(password, salt_b64) do
      {:ok, key} -> key
      {:error, reason} -> raise "key derivation failed: #{reason}"
    end
  end

  @doc """
  Parse the salt portion from a key_hash string.

  Key hashes are stored as `{salt_b64}$argon2id`. This extracts the salt.

  ## Example

      {:ok, salt} = MetamorphicCrypto.KDF.parse_salt_from_key_hash("c2FsdA==$argon2id")
      #=> {:ok, "c2FsdA=="}

  """
  @spec parse_salt_from_key_hash(key_hash :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def parse_salt_from_key_hash(key_hash) when is_binary(key_hash) do
    case Native.nif_parse_salt_from_key_hash(key_hash) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  @hkdf_sha512_hash_len 64

  @doc """
  SHA-512 output length in bytes (`64`). The maximum HKDF-SHA512 output is
  `255 * 64 = 16320` bytes.

  ## Example

      iex> MetamorphicCrypto.KDF.hkdf_sha512_hash_len()
      64

  """
  @spec hkdf_sha512_hash_len() :: pos_integer()
  def hkdf_sha512_hash_len, do: @hkdf_sha512_hash_len

  @doc """
  Derive `length` bytes of output keying material via HKDF-SHA512 (RFC 5869).

  Performs Extract-then-Expand in one call. Unlike the bare hashes in
  `MetamorphicCrypto.Hash`, HKDF is the **correct** construction for deriving a
  key from *secret* input keying material — in particular when combining more
  than one secret (e.g. a password-derived key concatenated with a WebAuthn-PRF
  output) with auditable domain separation.

  ## Arguments

  - `salt_b64` — base64-encoded, non-secret salt bound into Extract. An **empty**
    string means "not provided" (RFC 5869 §2.2), i.e. `HashLen` zero bytes. Pass
    a per-derivation salt to bind the output to it (recommended).
  - `ikm_b64` — base64-encoded input keying material. **May be secret.**
  - `info` — a binary domain-separation label bound into Expand. Normally a
    versioned UTF-8 string like `"mosslet/user_key-wrap/v1"`; arbitrary bytes are
    also accepted (matching the RFC 5869 test vectors).
  - `length` — desired output length in bytes; must be `<= 16320`.

  Returns `{:ok, okm_b64}` or `{:error, reason}` (invalid base64, or a `length`
  above the RFC maximum).

  Base64 in, base64 out — the output is byte-for-byte identical to the crate's
  native Rust, the WASM build (`hkdfSha512`), and `@noble/hashes` / WebCrypto
  HKDF-SHA-512, so a wrapping key derived in the browser re-derives identically
  here without the server ever seeing the inputs.

  ## Example

      # RFC 5869 Test Case 1 inputs, recomputed with SHA-512 (L = 42).
      iex> ikm = String.duplicate(<<0x0B>>, 22)
      iex> salt = Enum.into(0..0x0C, <<>>, &<<&1>>)
      iex> info = <<0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9>>
      iex> {:ok, okm_b64} =
      ...>   MetamorphicCrypto.KDF.hkdf_sha512(Base.encode64(salt), Base.encode64(ikm), info, 42)
      iex> Base.decode64!(okm_b64) |> Base.encode16(case: :lower)
      "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"

  """
  @spec hkdf_sha512(
          salt_b64 :: String.t(),
          ikm_b64 :: String.t(),
          info :: binary(),
          length :: non_neg_integer()
        ) :: {:ok, String.t()} | {:error, String.t()}
  def hkdf_sha512(salt_b64, ikm_b64, info, length)
      when is_binary(salt_b64) and is_binary(ikm_b64) and is_binary(info) and
             is_integer(length) and length >= 0 do
    case Native.nif_hkdf_sha512(salt_b64, ikm_b64, info, length) do
      {:error, reason} -> {:error, reason}
      okm when is_binary(okm) -> {:ok, okm}
    end
  end

  @doc """
  Same as `hkdf_sha512/4` but returns the OKM directly, raising on failure.
  """
  @spec hkdf_sha512!(
          salt_b64 :: String.t(),
          ikm_b64 :: String.t(),
          info :: binary(),
          length :: non_neg_integer()
        ) :: String.t()
  def hkdf_sha512!(salt_b64, ikm_b64, info, length) do
    case hkdf_sha512(salt_b64, ikm_b64, info, length) do
      {:ok, okm} -> okm
      {:error, reason} -> raise "HKDF-SHA512 failed: #{reason}"
    end
  end
end
