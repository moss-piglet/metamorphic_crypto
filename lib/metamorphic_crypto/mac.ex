defmodule MetamorphicCrypto.Mac do
  @moduledoc """
  Message authentication codes — HMAC-SHA256 (RFC 2104 / FIPS 198-1).

  A thin, idiomatic wrapper over the audited `metamorphic-crypto` Rust core — the
  same one-shot HMAC primitive used by the browser WASM build, so a tag computed
  here is **byte-for-byte identical** to one computed in the browser or native
  Rust.

  ## Why this exists

  The IETF KEYTRANS protocol (`draft-ietf-keytrans-protocol`) specifies that
  commitments in its **standard** cipher suites are computed as
  `HMAC(Kc, CommitmentValue)` using the suite hash (SHA-256 for both currently
  defined suites). `MetamorphicLog` owns the KEYTRANS-specific framing; this
  module supplies only the generic HMAC-SHA256 primitive, keeping
  `metamorphic_crypto` the single source of truth for cryptographic primitives.

  ## Encoding (base64 in, base64 out)

  `key` and `msg` are **base64-encoded** and the 32-byte tag is returned
  **base64-encoded**, matching the rest of this package and the WASM wire format.
  This is standard HMAC-SHA256: any conformant implementation computes an
  identical tag for the same `(key, msg)`. If you have raw binaries, encode them
  first with `Base.encode64/1`.

  The key may be any length: HMAC internally hashes an over-long key and
  zero-pads a short one, so no length validation is required or performed.

  ## Security note

  > #### HMAC security depends on how you use it {: .warning}
  >
  > HMAC's authenticator security rests on the key being **secret**. In the
  > KEYTRANS commitment construction the "key" is a fixed, *public* per-suite
  > constant and hiding comes from the random opening inside the message — there
  > HMAC is a committing PRF, not an authenticator. This primitive is generic;
  > callers are responsible for using it in a construction whose security
  > properties they understand.
  """

  alias MetamorphicCrypto.Native

  @hmac_sha256_len 32

  @doc """
  HMAC-SHA256 output length in bytes (`32`, a SHA-256 digest).

  ## Example

      iex> MetamorphicCrypto.Mac.hmac_sha256_len()
      32

  """
  @spec hmac_sha256_len() :: pos_integer()
  def hmac_sha256_len, do: @hmac_sha256_len

  @doc """
  Compute `HMAC-SHA256(key, msg)`, returning a base64-encoded 32-byte tag.

  `key` and `msg` are base64-encoded. Returns `{:ok, tag_b64}` or
  `{:error, reason}` (invalid base64 input). Hashing itself is infallible.

  ## Example

      # RFC 4231 Test Case 2: key "Jefe", message "what do ya want for nothing?"
      {:ok, tag} =
        MetamorphicCrypto.Mac.hmac_sha256(Base.encode64("Jefe"), Base.encode64("what do ya want for nothing?"))
      # Base.decode64!(tag) == <<0x5b, 0xdc, 0xc1, 0x46, ...>>

  """
  @spec hmac_sha256(key_b64 :: String.t(), msg_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def hmac_sha256(key_b64, msg_b64) when is_binary(key_b64) and is_binary(msg_b64) do
    wrap(Native.nif_hmac_sha256(key_b64, msg_b64))
  end

  @doc """
  Same as `hmac_sha256/2` but returns the tag directly, raising on invalid input.
  """
  @spec hmac_sha256!(key_b64 :: String.t(), msg_b64 :: String.t()) :: String.t()
  def hmac_sha256!(key_b64, msg_b64), do: unwrap!(hmac_sha256(key_b64, msg_b64))

  # ─── Internal ──────────────────────────────────────────────────────────────

  defp wrap({:error, reason}), do: {:error, reason}
  defp wrap(tag) when is_binary(tag), do: {:ok, tag}

  defp unwrap!({:ok, tag}), do: tag
  defp unwrap!({:error, reason}), do: raise("HMAC failed: #{reason}")
end
