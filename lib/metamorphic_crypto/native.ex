defmodule MetamorphicCrypto.Native do
  @moduledoc false
  # Low-level NIF bindings. Use the public API modules instead.

  version = Mix.Project.config()[:version]

  use RustlerPrecompiled,
    otp_app: :metamorphic_crypto,
    crate: "metamorphic_crypto_nif",
    base_url: "https://github.com/moss-piglet/metamorphic_crypto/releases/download/v#{version}",
    force_build: System.get_env("METAMORPHIC_CRYPTO_BUILD") in ["1", "true"],
    version: version,
    nif_versions: ["2.15", "2.16", "2.17"],
    targets: [
      "aarch64-apple-darwin",
      "x86_64-apple-darwin",
      "x86_64-unknown-linux-gnu",
      "aarch64-unknown-linux-gnu",
      "x86_64-pc-windows-msvc"
    ]

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

  def nif_seal_for_user_with_suite(
        _plaintext_b64,
        _public_key_b64,
        _pq_public_key_b64,
        _suite,
        _level
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  def nif_unseal_from_user(
        _ciphertext_b64,
        _public_key_b64,
        _private_key_b64,
        _pq_secret_key_b64
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  # Hybrid (Cat-1: ML-KEM-512)
  def nif_generate_hybrid_keypair_512, do: :erlang.nif_error(:nif_not_loaded)

  def nif_hybrid_seal_512(_plaintext_b64, _combined_pk_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  # Hybrid (Cat-3: ML-KEM-768)
  def nif_generate_hybrid_keypair, do: :erlang.nif_error(:nif_not_loaded)
  def nif_hybrid_seal(_plaintext_b64, _combined_pk_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_hybrid_open(_ciphertext_b64, _seed_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_is_hybrid_ciphertext(_ciphertext_b64), do: :erlang.nif_error(:nif_not_loaded)

  # Hybrid (Cat-5: ML-KEM-1024)
  def nif_generate_hybrid_keypair_1024, do: :erlang.nif_error(:nif_not_loaded)

  def nif_hybrid_seal_1024(_plaintext_b64, _combined_pk_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  # CNSA 2.0 Suite axis (KEM / seal)
  def nif_generate_hybrid_keypair_suite(_suite, _level),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_hybrid_seal_suite(_plaintext_b64, _combined_pk_b64, _suite, _level),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_hybrid_seal_suite_with_context(
        _plaintext_b64,
        _combined_pk_b64,
        _suite,
        _level,
        _context_label
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  def nif_hybrid_open_with_context(_ciphertext_b64, _seed_b64, _context_label),
    do: :erlang.nif_error(:nif_not_loaded)

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

  # Hashing
  def nif_sha3_512(_data_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_sha3_256(_data_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_sha256(_data_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_sha512(_data_b64), do: :erlang.nif_error(:nif_not_loaded)

  def nif_sha3_512_with_context(_context, _data_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  # Hybrid PQ Signatures (ML-DSA + Ed25519)
  def nif_generate_signing_keypair(_level), do: :erlang.nif_error(:nif_not_loaded)

  def nif_generate_signing_keypair_suite(_suite, _level),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_derive_signing_public_key(_secret_key_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_sign(_message, _context, _secret_key_b64), do: :erlang.nif_error(:nif_not_loaded)

  def nif_verify(_message, _context, _signature_b64, _public_key_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  # Signature posture introspection
  def nif_signature_posture(_public_key_b64), do: :erlang.nif_error(:nif_not_loaded)

  def nif_signature_posture_from_signature(_signature_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  # HMAC-SHA256
  def nif_hmac_sha256(_key_b64, _msg_b64), do: :erlang.nif_error(:nif_not_loaded)

  # HKDF-SHA512 (RFC 5869)
  def nif_hkdf_sha512(_salt_b64, _ikm_b64, _info, _length),
    do: :erlang.nif_error(:nif_not_loaded)

  # ECVRF-Edwards25519-SHA512-TAI (suite 0x03)
  def nif_ecvrf_generate_keypair, do: :erlang.nif_error(:nif_not_loaded)
  def nif_ecvrf_public_key(_secret_key_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_ecvrf_prove(_secret_key_b64, _alpha_b64), do: :erlang.nif_error(:nif_not_loaded)

  def nif_ecvrf_verify(_public_key_b64, _alpha_b64, _proof_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_ecvrf_proof_to_hash(_proof_b64), do: :erlang.nif_error(:nif_not_loaded)

  # ECVRF-P256-SHA256-TAI (suite 0x01)
  def nif_ecvrf_p256_generate_keypair, do: :erlang.nif_error(:nif_not_loaded)
  def nif_ecvrf_p256_public_key(_secret_key_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_ecvrf_p256_prove(_secret_key_b64, _alpha_b64), do: :erlang.nif_error(:nif_not_loaded)

  def nif_ecvrf_p256_verify(_public_key_b64, _alpha_b64, _proof_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_ecvrf_p256_proof_to_hash(_proof_b64), do: :erlang.nif_error(:nif_not_loaded)
end
