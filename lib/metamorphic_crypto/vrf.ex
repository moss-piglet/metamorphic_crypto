defmodule MetamorphicCrypto.Vrf do
  @moduledoc """
  Verifiable Random Function — ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381, suite
  `0x03`).

  Thin, idiomatic wrappers over the audited `metamorphic-crypto` Rust core — the
  same primitive used by the browser WASM build, so a proof produced or verified
  here behaves **byte-identically** across native Rust, WASM, and this NIF.

  A VRF is a keyed function whose owner can compute, for any input `alpha`, a
  pseudorandom output `beta` **and** a proof `pi` that `beta` was computed
  correctly under their public key. Anyone with the public key can verify `pi`,
  but cannot compute `beta` for a new input themselves, and cannot learn `alpha`
  from `(pi, beta)` alone. It backs `MetamorphicLog`'s CONIKS-style
  key-transparency layer, mapping a (private) identity index to a pseudorandom
  tree position — giving *index privacy* together with a verifiable,
  non-equivocable mapping.

  This is the Edwards25519 suite; see `MetamorphicCrypto.VrfP256` for the NIST
  P-256 sibling (`KT_128_SHA256_P256`).

  ## Post-quantum posture (honest framing)

  > #### This VRF is classical, and protects only index privacy {: .warning}
  >
  > ECVRF is **classical** (elliptic-curve discrete log) — the one place in the
  > transparency stack whose security is not post-quantum. It protects exactly
  > one property: *index privacy*. Integrity, authenticity, and the hash-based
  > commitments are post-quantum and do not rely on this VRF. Not FIPS-validated.

  ## Encoding & wire format (base64 in, base64 out)

  All arguments and results cross as **base64 strings**, matching the WASM wire
  format. Raw byte lengths (before base64):

      secret key  (SK) : 32 bytes   (an Ed25519-style seed)
      public key  (Y)  : 32 bytes   (compressed Edwards point)
      proof       (pi) : 80 bytes   = Gamma(32) || c(16) || s(32)
      output      (beta): 64 bytes  (a SHA-512 digest)

  Correctness is pinned byte-for-byte by RFC 9381 Appendix B test vectors, so
  independent implementations interoperate exactly.

  ## Verification result shape

  `verify/3` distinguishes a **cryptographic rejection** from a **structural**
  (malformed-input) error:

  - `{:ok, output_b64}` — the proof is valid; `output_b64` is the VRF output
    `beta` (identical to `proof_to_hash/1` on the same proof).
  - `:invalid` — a cryptographic rejection: wrong key, tampered `alpha`, tampered
    proof, or a non-canonical/degenerate key or `Gamma`. The inputs were
    well-formed but the proof does not verify.
  - `{:error, reason}` — a structural failure: a wrong-length key/proof or
    invalid base64. Nothing was cryptographically decided.
  """

  alias MetamorphicCrypto.Native

  @secret_key_len 32
  @public_key_len 32
  @proof_len 80
  @output_len 64
  @suite 0x03

  @typedoc """
  An ECVRF keypair, both fields base64-encoded (32-byte seed / 32-byte point).
  """
  @type keypair :: %{secret_key: String.t(), public_key: String.t()}

  @doc "RFC 9381 ciphersuite octet for ECVRF-EDWARDS25519-SHA512-TAI (`0x03`)."
  @spec suite() :: 0x03
  def suite, do: @suite

  @doc "Secret-key length in bytes (`32`)."
  @spec secret_key_len() :: pos_integer()
  def secret_key_len, do: @secret_key_len

  @doc "Public-key length in bytes (`32`)."
  @spec public_key_len() :: pos_integer()
  def public_key_len, do: @public_key_len

  @doc "Proof (`pi`) length in bytes (`80`)."
  @spec proof_len() :: pos_integer()
  def proof_len, do: @proof_len

  @doc "Output (`beta`) length in bytes (`64`)."
  @spec output_len() :: pos_integer()
  def output_len, do: @output_len

  @doc """
  Generate a fresh VRF keypair from the OS CSPRNG.

  Returns `%{secret_key: base64, public_key: base64}`. The secret key is a
  32-byte seed; handle it as secret material.

  ## Example

      %{secret_key: sk, public_key: pk} = MetamorphicCrypto.Vrf.generate_keypair()

  """
  @spec generate_keypair() :: keypair()
  def generate_keypair do
    {secret_key, public_key} = Native.nif_ecvrf_generate_keypair()
    %{secret_key: secret_key, public_key: public_key}
  end

  @doc """
  Derive the base64 public key for a base64 `secret_key`.

  Returns `{:ok, public_key_b64}` or `{:error, reason}` (wrong length / invalid
  base64).

  ## Example

      %{secret_key: sk, public_key: pk} = MetamorphicCrypto.Vrf.generate_keypair()
      {:ok, ^pk} = MetamorphicCrypto.Vrf.public_key(sk)

  """
  @spec public_key(secret_key_b64 :: String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def public_key(secret_key_b64) when is_binary(secret_key_b64) do
    wrap(Native.nif_ecvrf_public_key(secret_key_b64))
  end

  @doc """
  Produce a VRF proof `pi` (base64) for base64 `alpha` under a base64
  `secret_key`.

  The proof both authenticates the output and lets any verifier recompute it.
  Returns `{:ok, proof_b64}` or `{:error, reason}`. TAI ECVRF is deterministic:
  the same key and `alpha` always yield the same proof.

  ## Example

      %{secret_key: sk} = MetamorphicCrypto.Vrf.generate_keypair()
      {:ok, pi} = MetamorphicCrypto.Vrf.prove(sk, Base.encode64("identity index"))

  """
  @spec prove(secret_key_b64 :: String.t(), alpha_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def prove(secret_key_b64, alpha_b64)
      when is_binary(secret_key_b64) and is_binary(alpha_b64) do
    wrap(Native.nif_ecvrf_prove(secret_key_b64, alpha_b64))
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
    degenerate key or `Gamma`). Well-formed inputs, but the proof does not verify.
  - `{:error, reason}` — a structural failure (wrong-length key/proof, invalid
    base64).

  ## Example

      %{secret_key: sk, public_key: pk} = MetamorphicCrypto.Vrf.generate_keypair()
      alpha = Base.encode64("identity index")
      {:ok, pi} = MetamorphicCrypto.Vrf.prove(sk, alpha)
      {:ok, beta} = MetamorphicCrypto.Vrf.verify(pk, alpha, pi)
      :invalid = MetamorphicCrypto.Vrf.verify(pk, Base.encode64("other"), pi)

  """
  @spec verify(
          public_key_b64 :: String.t(),
          alpha_b64 :: String.t(),
          proof_b64 :: String.t()
        ) :: {:ok, String.t()} | :invalid | {:error, String.t()}
  def verify(public_key_b64, alpha_b64, proof_b64)
      when is_binary(public_key_b64) and is_binary(alpha_b64) and is_binary(proof_b64) do
    case Native.nif_ecvrf_verify(public_key_b64, alpha_b64, proof_b64) do
      {:error, reason} -> {:error, reason}
      nil -> :invalid
      output when is_binary(output) -> {:ok, output}
    end
  end

  @doc """
  Recover the VRF output `beta` (base64) directly from a proof `pi`, **without**
  verifying it.

  This is only the `Gamma -> beta` mapping; it does **not** check that `pi` is a
  valid proof for any `(public_key, alpha)`. Use it only on a proof already
  verified with `verify/3`, or whose provenance you independently trust. Returns
  `{:ok, output_b64}` or `{:error, reason}`.
  """
  @spec proof_to_hash(proof_b64 :: String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def proof_to_hash(proof_b64) when is_binary(proof_b64) do
    wrap(Native.nif_ecvrf_proof_to_hash(proof_b64))
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
