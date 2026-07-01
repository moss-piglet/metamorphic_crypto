defmodule MetamorphicCrypto.VrfP256 do
  @moduledoc """
  Verifiable Random Function — ECVRF-P256-SHA256-TAI (RFC 9381, suite `0x01`).

  Thin, idiomatic wrappers over the audited `metamorphic-crypto` Rust core — the
  same primitive used by the browser WASM build, so a proof produced or verified
  here behaves **byte-identically** across native Rust, WASM, and this NIF.

  This is the NIST P-256 sibling of `MetamorphicCrypto.Vrf` (Edwards25519). It
  implements RFC 9381 ciphersuite `0x01`: the P-256 curve, SHA-256, and
  *try-and-increment* hash-to-curve. It exists so that `MetamorphicLog`'s
  KEYTRANS layer can offer the **on-spec IETF `KT_128_SHA256_P256` cipher
  suite**, whose VRF is defined as ECVRF-P256-SHA256-TAI.

  See `MetamorphicCrypto.Vrf` for the general VRF concept and the *index
  privacy* role in key transparency; the two modules share an identical API
  shape and result contract, differing only in curve, lengths, and suite octet.

  ## Post-quantum posture (honest framing)

  > #### This VRF is classical, and protects only index privacy {: .warning}
  >
  > Like the Edwards25519 VRF, this is **classical** (elliptic-curve discrete
  > log) and protects exactly one property: KEYTRANS *index privacy*. Integrity,
  > authenticity, and the hash-based commitments are post-quantum and do not rely
  > on this VRF. Not FIPS-validated.

  ## Encoding & wire format (base64 in, base64 out)

  All arguments and results cross as **base64 strings**. Raw byte lengths
  (before base64):

      secret key  (SK) : 32 bytes   (big-endian secret scalar x)
      public key  (Y)  : 33 bytes   (SEC1 compressed point)
      proof       (pi) : 81 bytes   = Gamma(33) || c(16) || s(32)
      output      (beta): 32 bytes  (a SHA-256 digest)

  Correctness is pinned byte-for-byte by RFC 9381 Appendix B.1 test vectors.

  ## Verification result shape

  `verify/3` distinguishes a **cryptographic rejection** from a **structural**
  (malformed-input) error:

  - `{:ok, output_b64}` — the proof is valid; `output_b64` is the VRF output.
  - `:invalid` — a cryptographic rejection (wrong key, tampered input/proof, or a
    degenerate/non-canonical key, `Gamma`, or `s`).
  - `{:error, reason}` — a structural failure (wrong-length key/proof, invalid
    base64).
  """

  alias MetamorphicCrypto.Native

  @secret_key_len 32
  @public_key_len 33
  @proof_len 81
  @output_len 32
  @suite 0x01

  @typedoc """
  An ECVRF-P256 keypair, both fields base64-encoded (32-byte scalar / 33-byte
  SEC1 point).
  """
  @type keypair :: %{secret_key: String.t(), public_key: String.t()}

  @doc "RFC 9381 ciphersuite octet for ECVRF-P256-SHA256-TAI (`0x01`)."
  @spec suite() :: 0x01
  def suite, do: @suite

  @doc "Secret-key length in bytes (`32`)."
  @spec secret_key_len() :: pos_integer()
  def secret_key_len, do: @secret_key_len

  @doc "Public-key length in bytes (`33`)."
  @spec public_key_len() :: pos_integer()
  def public_key_len, do: @public_key_len

  @doc "Proof (`pi`) length in bytes (`81`)."
  @spec proof_len() :: pos_integer()
  def proof_len, do: @proof_len

  @doc "Output (`beta`) length in bytes (`32`)."
  @spec output_len() :: pos_integer()
  def output_len, do: @output_len

  @doc """
  Generate a fresh VRF keypair from the OS CSPRNG.

  Returns `%{secret_key: base64, public_key: base64}`. The secret key is a
  32-byte big-endian scalar; handle it as secret material.

  ## Example

      %{secret_key: sk, public_key: pk} = MetamorphicCrypto.VrfP256.generate_keypair()

  """
  @spec generate_keypair() :: keypair()
  def generate_keypair do
    {secret_key, public_key} = Native.nif_ecvrf_p256_generate_keypair()
    %{secret_key: secret_key, public_key: public_key}
  end

  @doc """
  Derive the base64 public key for a base64 `secret_key`.

  Returns `{:ok, public_key_b64}` or `{:error, reason}` (wrong length, a
  non-canonical/zero scalar, or invalid base64).

  ## Example

      %{secret_key: sk, public_key: pk} = MetamorphicCrypto.VrfP256.generate_keypair()
      {:ok, ^pk} = MetamorphicCrypto.VrfP256.public_key(sk)

  """
  @spec public_key(secret_key_b64 :: String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def public_key(secret_key_b64) when is_binary(secret_key_b64) do
    wrap(Native.nif_ecvrf_p256_public_key(secret_key_b64))
  end

  @doc """
  Produce a VRF proof `pi` (base64) for base64 `alpha` under a base64
  `secret_key`.

  Returns `{:ok, proof_b64}` or `{:error, reason}`. The construction is
  deterministic (RFC 6979 nonces): the same key and `alpha` always yield the same
  proof.

  ## Example

      %{secret_key: sk} = MetamorphicCrypto.VrfP256.generate_keypair()
      {:ok, pi} = MetamorphicCrypto.VrfP256.prove(sk, Base.encode64("identity index"))

  """
  @spec prove(secret_key_b64 :: String.t(), alpha_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def prove(secret_key_b64, alpha_b64)
      when is_binary(secret_key_b64) and is_binary(alpha_b64) do
    wrap(Native.nif_ecvrf_p256_prove(secret_key_b64, alpha_b64))
  end

  @doc """
  Same as `prove/2` but returns the proof directly, raising on invalid input.
  """
  @spec prove!(secret_key_b64 :: String.t(), alpha_b64 :: String.t()) :: String.t()
  def prove!(secret_key_b64, alpha_b64), do: unwrap!(prove(secret_key_b64, alpha_b64))

  @doc """
  Verify a VRF proof `pi` for `alpha` under `public_key` (all base64).

  Returns:

  - `{:ok, output_b64}` — the proof is valid; `output_b64` is the VRF output.
  - `:invalid` — a cryptographic rejection (wrong key, tampered input/proof,
    degenerate key/`Gamma`/`s`).
  - `{:error, reason}` — a structural failure (wrong-length key/proof, invalid
    base64).

  ## Example

      %{secret_key: sk, public_key: pk} = MetamorphicCrypto.VrfP256.generate_keypair()
      alpha = Base.encode64("identity index")
      {:ok, pi} = MetamorphicCrypto.VrfP256.prove(sk, alpha)
      {:ok, beta} = MetamorphicCrypto.VrfP256.verify(pk, alpha, pi)
      :invalid = MetamorphicCrypto.VrfP256.verify(pk, Base.encode64("other"), pi)

  """
  @spec verify(
          public_key_b64 :: String.t(),
          alpha_b64 :: String.t(),
          proof_b64 :: String.t()
        ) :: {:ok, String.t()} | :invalid | {:error, String.t()}
  def verify(public_key_b64, alpha_b64, proof_b64)
      when is_binary(public_key_b64) and is_binary(alpha_b64) and is_binary(proof_b64) do
    case Native.nif_ecvrf_p256_verify(public_key_b64, alpha_b64, proof_b64) do
      {:error, reason} -> {:error, reason}
      nil -> :invalid
      output when is_binary(output) -> {:ok, output}
    end
  end

  @doc """
  Recover the VRF output `beta` (base64) directly from a proof `pi`, **without**
  verifying it.

  Only the `Gamma -> beta` mapping; it does **not** check that `pi` is valid. Use
  it only on a proof already verified with `verify/3`, or whose provenance you
  independently trust. Returns `{:ok, output_b64}` or `{:error, reason}`.
  """
  @spec proof_to_hash(proof_b64 :: String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def proof_to_hash(proof_b64) when is_binary(proof_b64) do
    wrap(Native.nif_ecvrf_p256_proof_to_hash(proof_b64))
  end

  @doc """
  Same as `proof_to_hash/1` but returns the output directly, raising on invalid
  input.
  """
  @spec proof_to_hash!(proof_b64 :: String.t()) :: String.t()
  def proof_to_hash!(proof_b64), do: unwrap!(proof_to_hash(proof_b64))

  # ─── Internal ──────────────────────────────────────────────────────────────

  defp wrap({:error, reason}), do: {:error, reason}
  defp wrap(value) when is_binary(value), do: {:ok, value}

  defp unwrap!({:ok, value}), do: value
  defp unwrap!({:error, reason}), do: raise("VRF failed: #{reason}")
end
