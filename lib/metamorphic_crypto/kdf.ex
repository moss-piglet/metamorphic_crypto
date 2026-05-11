defmodule MetamorphicCrypto.KDF do
  @moduledoc """
  Argon2id key derivation.

  Derives a 32-byte session key from a password and 16-byte salt using Argon2id
  with libsodium's `OPSLIMIT_INTERACTIVE` / `MEMLIMIT_INTERACTIVE` parameters:

  - Time cost: 2 iterations
  - Memory cost: 64 MiB
  - Output: 32 bytes

  This is typically used to derive a session key from a user's password, which
  then decrypts their private key stored on the server.

  ## Usage

      salt = MetamorphicCrypto.Keys.generate_salt()
      {:ok, session_key} = MetamorphicCrypto.KDF.derive_session_key("my password", salt)

  > **Note**: This function is intentionally expensive (64 MiB memory, ~200ms).
  > It runs on a dirty CPU scheduler to avoid blocking the BEAM.

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
end
