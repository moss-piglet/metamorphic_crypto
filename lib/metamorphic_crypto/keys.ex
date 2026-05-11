defmodule MetamorphicCrypto.Keys do
  @moduledoc """
  Key generation and private key management.

  ## Key types

  | Type | Size | Use |
  |------|------|-----|
  | Symmetric key | 32 bytes | SecretBox encryption |
  | X25519 keypair | 32 + 32 bytes | BoxSeal / Seal public-key encryption |
  | Salt | 16 bytes | Argon2id KDF input |

  ## Usage

      # Symmetric key for SecretBox
      key = MetamorphicCrypto.Keys.generate_key()

      # X25519 keypair for BoxSeal
      {public_key, private_key} = MetamorphicCrypto.Keys.generate_keypair()

      # Salt for KDF
      salt = MetamorphicCrypto.Keys.generate_salt()

  """

  alias MetamorphicCrypto.Native

  @doc """
  Generate a random 32-byte symmetric key (base64-encoded).

  ## Example

      key = MetamorphicCrypto.Keys.generate_key()

  """
  @spec generate_key() :: String.t()
  def generate_key do
    Native.nif_generate_key()
  end

  @doc """
  Generate a random X25519 keypair.

  Returns `{public_key_b64, private_key_b64}`.

  ## Example

      {public_key, private_key} = MetamorphicCrypto.Keys.generate_keypair()

  """
  @spec generate_keypair() :: {String.t(), String.t()}
  def generate_keypair do
    Native.nif_generate_keypair()
  end

  @doc """
  Generate a random 16-byte Argon2id salt (base64-encoded).

  ## Example

      salt = MetamorphicCrypto.Keys.generate_salt()

  """
  @spec generate_salt() :: String.t()
  def generate_salt do
    Native.nif_generate_salt()
  end

  @doc """
  Encrypt a private key (base64) with a session key for storage.

  The private key is treated as a UTF-8 string (its base64 representation)
  and encrypted with XSalsa20-Poly1305.

  ## Example

      {_pk, sk} = MetamorphicCrypto.Keys.generate_keypair()
      session_key = MetamorphicCrypto.Keys.generate_key()
      {:ok, encrypted_sk} = MetamorphicCrypto.Keys.encrypt_private_key(sk, session_key)

  """
  @spec encrypt_private_key(private_key_b64 :: String.t(), session_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def encrypt_private_key(private_key_b64, session_key_b64) do
    case Native.nif_encrypt_private_key(private_key_b64, session_key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  @doc """
  Decrypt an encrypted private key with a session key.

  Returns `{:ok, private_key_b64}` or `{:error, reason}`.

  ## Example

      {:ok, private_key} = MetamorphicCrypto.Keys.decrypt_private_key(encrypted_sk, session_key)

  """
  @spec decrypt_private_key(ciphertext_b64 :: String.t(), session_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def decrypt_private_key(ciphertext_b64, session_key_b64) do
    case Native.nif_decrypt_private_key(ciphertext_b64, session_key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end
end
