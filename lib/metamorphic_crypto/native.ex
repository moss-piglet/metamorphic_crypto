defmodule MetamorphicCrypto.Native do
  @moduledoc false
  # Low-level NIF bindings. Use the public API modules instead.

  version = Mix.Project.config()[:version]

  use RustlerPrecompiled,
    otp_app: :metamorphic_crypto,
    crate: "metamorphic_crypto_nif",
    base_url: "https://github.com/moss-piglet/metamorphic_crypto/releases/download/v#{version}",
    force_build: System.get_env("METAMORPHIC_CRYPTO_BUILD") in ["1", "true"],
    version: version

  # Key Derivation
  def nif_derive_session_key(_password, _salt_b64), do: :erlang.nif_error(:nif_not_loaded)

  # SecretBox
  def nif_encrypt_secretbox(_plaintext_b64, _key_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_decrypt_secretbox(_ciphertext_b64, _key_b64), do: :erlang.nif_error(:nif_not_loaded)

  def nif_encrypt_secretbox_string(_plaintext, _key_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_decrypt_secretbox_to_string(_ciphertext_b64, _key_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  # BoxSeal
  def nif_box_seal(_plaintext_b64, _public_key_b64), do: :erlang.nif_error(:nif_not_loaded)

  def nif_box_seal_open(_ciphertext_b64, _public_key_b64, _private_key_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  # Seal/Unseal
  def nif_seal_for_user(_plaintext_b64, _public_key_b64, _pq_public_key_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_unseal_from_user(
        _ciphertext_b64,
        _public_key_b64,
        _private_key_b64,
        _pq_secret_key_b64
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  # Hybrid
  def nif_generate_hybrid_keypair, do: :erlang.nif_error(:nif_not_loaded)
  def nif_hybrid_seal(_plaintext_b64, _combined_pk_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_hybrid_open(_ciphertext_b64, _seed_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_is_hybrid_ciphertext(_ciphertext_b64), do: :erlang.nif_error(:nif_not_loaded)

  # Keys
  def nif_generate_key, do: :erlang.nif_error(:nif_not_loaded)
  def nif_generate_keypair, do: :erlang.nif_error(:nif_not_loaded)
  def nif_generate_salt, do: :erlang.nif_error(:nif_not_loaded)

  def nif_encrypt_private_key(_private_key_b64, _session_key_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_decrypt_private_key(_ciphertext_b64, _session_key_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  # Recovery
  def nif_generate_recovery_key, do: :erlang.nif_error(:nif_not_loaded)
  def nif_recovery_key_to_secret(_recovery_key), do: :erlang.nif_error(:nif_not_loaded)

  def nif_encrypt_private_key_for_recovery(_private_key_b64, _recovery_secret_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_decrypt_private_key_with_recovery(_ciphertext_b64, _recovery_secret_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  # Utility
  def nif_parse_salt_from_key_hash(_key_hash), do: :erlang.nif_error(:nif_not_loaded)
end
