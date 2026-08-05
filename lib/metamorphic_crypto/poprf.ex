defmodule MetamorphicCrypto.Poprf do
  @moduledoc """
  Partially Oblivious Pseudorandom Function — RFC 9497, **OPRF(ristretto255,
  SHA-512)** suite (modePOPRF `0x02`).

  Thin, idiomatic wrappers over the audited `metamorphic-crypto` Rust core — the
  same primitive used by the browser WASM build, so an evaluation produced or
  verified here behaves **byte-identically** across native Rust, WASM, and this
  NIF.

  A POPRF lets a client compute a keyed, deterministic pseudorandom value over
  its private input **without the server ever seeing that input**: the client
  blinds its input, the server evaluates the blinded element under its secret
  key and returns a DLEQ proof, and the client unblinds and verifies. Both
  parties additionally bind a *public* `info` string (the "partially" in
  partially oblivious). It backs `MetamorphicLog`'s CONIKS-style
  key-transparency layer, removing the query-time cleartext-label exposure the
  classical VRF (`MetamorphicCrypto.Vrf`) carries.

  ## The oblivious flow

      # Client (e.g. browser WASM or this NIF):
      %{blind: blind, blinded_element: blinded, tweaked_key: tweaked} =
        Poprf.blind(input, info, server_public_key)
      #   -> send ONLY `blinded` to the server

      # Server:
      {:ok, {evaluated, proof}} = Poprf.blind_evaluate(server_secret, blinded, info)

      # Client:
      {:ok, output} = Poprf.finalize(input, blind, evaluated, blinded, proof, info, tweaked)

  The operator derives the same output non-obliviously with `evaluate/3` when it
  already holds the cleartext input (directory construction).

  ## Post-quantum posture (honest framing)

  > #### Blinding is classical — transcripts are not PQ-private {: .warning}
  >
  > 2HashDH blinding is **classical** (elliptic-curve discrete log): recorded
  > evaluation transcripts are not post-quantum private
  > (harvest-now/unblind-later). This protects exactly one property:
  > *query-time index privacy against the operator today*. Authenticity and
  > integrity elsewhere in the stack are post-quantum from day one (ML-DSA
  > hybrid signatures, SHA3-512 commitments) and do not rely on this primitive.
  > Not FIPS-validated.

  ## Encoding & wire format (base64 in, base64 out)

  All arguments and results cross as **base64 strings**, matching the WASM wire
  format. Raw byte lengths (before base64):

      secret key  (skS) : 32 bytes   (canonical ristretto255 scalar)
      public key  (pkS) : 32 bytes   (ristretto255 element)
      blind             : 32 bytes   (canonical scalar — client-side state, secret)
      blinded element   : 32 bytes   (ristretto255 element)
      evaluated element : 32 bytes   (ristretto255 element)
      tweaked key       : 32 bytes   (ristretto255 element)
      DLEQ proof        : 64 bytes   = c (32) || s (32)
      output            : 64 bytes   (a SHA-512 digest)

  Correctness is pinned byte-for-byte by RFC 9497 Appendix A.1.3 test vectors,
  so independent implementations interoperate exactly.
  """

  alias MetamorphicCrypto.Native

  @typedoc """
  The client-side blinding state, all fields base64-encoded. `blind` and
  `tweaked_key` stay local to the client; only `blinded_element` is sent to the
  server.
  """
  @type blind_state :: %{
          blind: String.t(),
          blinded_element: String.t(),
          tweaked_key: String.t()
        }

  @doc """
  Generate a fresh POPRF keypair from the OS CSPRNG.

  Returns `%{secret_key: base64, public_key: base64}`. Intended for tests and
  tooling; a deployment derives its stable key with `derive_key_pair/2`.

  ## Example

      %{secret_key: sk, public_key: pk} = MetamorphicCrypto.Poprf.generate_keypair()

  """
  @spec generate_keypair() :: %{secret_key: String.t(), public_key: String.t()}
  def generate_keypair do
    {secret_key, public_key} = Native.nif_poprf_generate_keypair()
    %{secret_key: secret_key, public_key: public_key}
  end

  @doc """
  Derive a POPRF keypair deterministically from a 32-byte `seed` and a public
  `key_info` string (RFC 9497 §3.2.1 `DeriveKeyPair`) — how an operator turns a
  managed master secret into a stable deployment evaluation key.

  Returns `{:ok, %{secret_key: base64, public_key: base64}}` or `{:error,
  reason}`.

  ## Example

      {:ok, %{secret_key: sk, public_key: pk}} =
        MetamorphicCrypto.Poprf.derive_key_pair(seed_b64, key_info_b64)

  """
  @spec derive_key_pair(seed_b64 :: String.t(), key_info_b64 :: String.t()) ::
          {:ok, %{secret_key: String.t(), public_key: String.t()}} | {:error, String.t()}
  def derive_key_pair(seed_b64, key_info_b64)
      when is_binary(seed_b64) and is_binary(key_info_b64) do
    case Native.nif_poprf_derive_key_pair(seed_b64, key_info_b64) do
      {:error, reason} -> {:error, reason}
      {secret_key, public_key} -> {:ok, %{secret_key: secret_key, public_key: public_key}}
    end
  end

  @doc """
  Derive the base64 public key for a base64 `secret_key`.

  Returns `{:ok, public_key_b64}` or `{:error, reason}` (wrong length / invalid
  base64 / non-canonical scalar).
  """
  @spec public_key(secret_key_b64 :: String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def public_key(secret_key_b64) when is_binary(secret_key_b64) do
    wrap(Native.nif_poprf_public_key(secret_key_b64))
  end

  @doc """
  Blind the private `input` under the public `info` and the server's
  `public_key` (RFC 9497 §3.3.3 `Blind`).

  Returns `{:ok, %{blind:, blinded_element:, tweaked_key:}}` — keep `blind` and
  `tweaked_key` local; send only `blinded_element` to the server.

  ## Example

      {:ok, %{blinded_element: blinded} = state} =
        MetamorphicCrypto.Poprf.blind(input_b64, info_b64, server_public_b64)

  """
  @spec blind(
          input_b64 :: String.t(),
          info_b64 :: String.t(),
          public_key_b64 :: String.t()
        ) :: {:ok, blind_state()} | {:error, String.t()}
  def blind(input_b64, info_b64, public_key_b64)
      when is_binary(input_b64) and is_binary(info_b64) and is_binary(public_key_b64) do
    wrap_blind(Native.nif_poprf_blind(input_b64, info_b64, public_key_b64))
  end

  @doc """
  KAT-only `blind/3` with an explicit blind scalar (deterministic), for
  cross-language known-answer tests. Production callers use `blind/3`.
  """
  @spec blind_with_scalar(
          input_b64 :: String.t(),
          info_b64 :: String.t(),
          public_key_b64 :: String.t(),
          blind_b64 :: String.t()
        ) :: {:ok, blind_state()} | {:error, String.t()}
  def blind_with_scalar(input_b64, info_b64, public_key_b64, blind_b64)
      when is_binary(input_b64) and is_binary(info_b64) and is_binary(public_key_b64) and
             is_binary(blind_b64) do
    wrap_blind(Native.nif_poprf_blind_with_scalar(input_b64, info_b64, public_key_b64, blind_b64))
  end

  @doc """
  The server-side blind evaluation (RFC 9497 §3.3.3 `BlindEvaluate`): evaluate
  a client's `blinded_element` under `secret_key` tweaked by the public `info`.

  Returns `{:ok, {evaluated_element_b64, dleq_proof_b64}}` or `{:error,
  reason}`. The server learns nothing about the input behind the blinded
  element.
  """
  @spec blind_evaluate(
          secret_key_b64 :: String.t(),
          blinded_element_b64 :: String.t(),
          info_b64 :: String.t()
        ) :: {:ok, {String.t(), String.t()}} | {:error, String.t()}
  def blind_evaluate(secret_key_b64, blinded_element_b64, info_b64)
      when is_binary(secret_key_b64) and is_binary(blinded_element_b64) and
             is_binary(info_b64) do
    wrap(Native.nif_poprf_blind_evaluate(secret_key_b64, blinded_element_b64, info_b64))
  end

  @doc """
  KAT-only `blind_evaluate/3` with an explicit DLEQ nonce (deterministic), for
  cross-language known-answer tests.
  """
  @spec blind_evaluate_with_random(
          secret_key_b64 :: String.t(),
          blinded_element_b64 :: String.t(),
          info_b64 :: String.t(),
          random_b64 :: String.t()
        ) :: {:ok, {String.t(), String.t()}} | {:error, String.t()}
  def blind_evaluate_with_random(secret_key_b64, blinded_element_b64, info_b64, random_b64)
      when is_binary(secret_key_b64) and is_binary(blinded_element_b64) and
             is_binary(info_b64) and is_binary(random_b64) do
    wrap(
      Native.nif_poprf_blind_evaluate_with_random(
        secret_key_b64,
        blinded_element_b64,
        info_b64,
        random_b64
      )
    )
  end

  @doc """
  The client-side completion (RFC 9497 §3.3.3 `Finalize`): verify the server's
  DLEQ proof against the `tweaked_key`, unblind, and return the 64-byte output.

  Distinguishes a **cryptographic rejection** from a **structural** error:

  - `{:ok, output_b64}` — the proof is valid; `output_b64` is the PRF output.
  - `:invalid` — a cryptographic rejection (wrong key, wrong `info`, tampered
    evaluation, or a forged proof). The inputs were well-formed but the proof
    does not verify.
  - `{:error, reason}` — a structural failure (wrong lengths, invalid base64 or
    a non-canonical encoding).
  """
  @spec finalize(
          input_b64 :: String.t(),
          blind_b64 :: String.t(),
          evaluated_element_b64 :: String.t(),
          blinded_element_b64 :: String.t(),
          proof_b64 :: String.t(),
          info_b64 :: String.t(),
          tweaked_key_b64 :: String.t()
        ) :: {:ok, String.t()} | :invalid | {:error, String.t()}
  def finalize(
        input_b64,
        blind_b64,
        evaluated_element_b64,
        blinded_element_b64,
        proof_b64,
        info_b64,
        tweaked_key_b64
      )
      when is_binary(input_b64) and is_binary(blind_b64) and
             is_binary(evaluated_element_b64) and is_binary(blinded_element_b64) and
             is_binary(proof_b64) and is_binary(info_b64) and is_binary(tweaked_key_b64) do
    input_b64
    |> Native.nif_poprf_finalize(
      blind_b64,
      evaluated_element_b64,
      blinded_element_b64,
      proof_b64,
      info_b64,
      tweaked_key_b64
    )
    |> wrap_finalize()
  end

  defp wrap_finalize({:error, reason}), do: {:error, reason}
  defp wrap_finalize(nil), do: :invalid
  defp wrap_finalize(output), do: {:ok, output}

  @doc """
  The non-oblivious server-side evaluation (RFC 9497 §3.3.3 `Evaluate`):
  compute the output directly from `secret_key` and the cleartext `input` — how
  an operator derives indices for inputs it already holds (directory
  construction). Produces exactly the output a client derives obliviously via
  `blind/3` → `blind_evaluate/3` → `finalize/7`.

  Returns `{:ok, output_b64}` or `{:error, reason}`.
  """
  @spec evaluate(
          secret_key_b64 :: String.t(),
          input_b64 :: String.t(),
          info_b64 :: String.t()
        ) :: {:ok, String.t()} | {:error, String.t()}
  def evaluate(secret_key_b64, input_b64, info_b64)
      when is_binary(secret_key_b64) and is_binary(input_b64) and is_binary(info_b64) do
    wrap(Native.nif_poprf_evaluate(secret_key_b64, input_b64, info_b64))
  end

  # The NIF returns the bare value on success and `{:error, reason}` on
  # failure; wrap into the `{:ok, value}` convention.
  defp wrap({:error, reason}), do: {:error, reason}
  defp wrap(value), do: {:ok, value}

  defp wrap_blind({:error, reason}), do: {:error, reason}

  defp wrap_blind({blind, blinded_element, tweaked_key}) do
    {:ok, %{blind: blind, blinded_element: blinded_element, tweaked_key: tweaked_key}}
  end
end
