defmodule MetamorphicCrypto.PoprfTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.Poprf

  # Hex -> base64 (the NIF wire encoding). RFC 9497 vectors are published in hex.
  defp b64(hex), do: hex |> Base.decode16!(case: :lower) |> Base.encode64()

  # RFC 9497 Appendix A.1.3 (POPRF mode, ristretto255-SHA512) shared key
  # material: DeriveKeyPair(seed, KeyInfo) under the POPRF context string.
  @seed "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
  @key_info "74657374206b6579"
  @sk_sm "145c79c108538421ac164ecbe131942136d5570b16d8bf41a24d4337da981e07"
  @pk_sm "c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631"
  @info "7465737420696e666f"
  @blind "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"
  @proof_random "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"

  describe "DeriveKeyPair (RFC 9497 §3.2.1, A.1.3)" do
    test "reproduces the published keypair byte-for-byte" do
      assert {:ok, %{secret_key: sk, public_key: pk}} =
               Poprf.derive_key_pair(b64(@seed), b64(@key_info))

      assert sk == b64(@sk_sm)
      assert pk == b64(@pk_sm)
      assert {:ok, ^pk} = Poprf.public_key(sk)
    end
  end

  # One RFC 9497 A.1.3 POPRF vector, batch size 1: blind (fixed scalar),
  # blind-evaluate (fixed DLEQ nonce), and finalize must reproduce the
  # published BlindedElement, EvaluationElement, Proof, and Output — the
  # byte-parity proof across native Rust / WASM / this NIF.
  defp kat(input, blinded, evaluated, proof, output) do
    info_b = b64(@info)
    input_b = b64(input)

    assert {:ok, %{blind: blind_b, blinded_element: blinded_b, tweaked_key: tweaked_b}} =
             Poprf.blind_with_scalar(input_b, info_b, b64(@pk_sm), b64(@blind))

    assert blind_b == b64(@blind)
    assert blinded_b == b64(blinded)

    assert {:ok, {evaluated_b, proof_b}} =
             Poprf.blind_evaluate_with_random(
               b64(@sk_sm),
               blinded_b,
               info_b,
               b64(@proof_random)
             )

    assert evaluated_b == b64(evaluated)
    assert proof_b == b64(proof)

    assert {:ok, output_b} =
             Poprf.finalize(input_b, blind_b, evaluated_b, blinded_b, proof_b, info_b, tweaked_b)

    assert output_b == b64(output)

    # The non-oblivious server path derives the identical output.
    assert {:ok, ^output_b} = Poprf.evaluate(b64(@sk_sm), input_b, info_b)
  end

  describe "RFC 9497 A.1.3 known-answer vectors" do
    test "vector 1 (input 0x00)" do
      kat(
        "00",
        "c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715",
        "1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874",
        "41ad1a291aa02c80b0915fbfbb0c0afa15a57e2970067a602ddb9e8fd6b7100d" <>
          "e32e1ecff943a36f0b10e3dae6bd266cdeb8adf825d86ef27dbc6c0e30c52206",
        "ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d" <>
          "38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221"
      )
    end

    test "vector 2 (input 0x5a * 17)" do
      kat(
        "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "f0f0b209dd4d5f1844dac679acc7761b91a2e704879656cb7c201e82a99ab07d",
        "8c3c9d064c334c6991e99f286ea2301d1bde170b54003fb9c44c6d7bd6fc1540",
        "4c39992d55ffba38232cdac88fe583af8a85441fefd7d1d4a8d0394cd1de7701" <>
          "8bf135c174f20281b3341ab1f453fe72b0293a7398703384bed822bfdeec8908",
        "7c6557b276a137922a0bcfc2aa2b35dd78322bd500235eb6d6b6f91bc5b56a52" <>
          "de2d65612d503236b321f5d0bebcbc52b64b92e426f29c9b8b69f52de98ae507"
      )
    end
  end

  describe "oblivious round trip" do
    test "blind -> blind_evaluate -> finalize matches evaluate" do
      %{secret_key: sk, public_key: pk} = Poprf.generate_keypair()
      input_b = Base.encode64("alice@example.com")
      info_b = Base.encode64("mosskeys/directory/v1:test-namespace")

      assert {:ok, %{blind: blind, blinded_element: blinded, tweaked_key: tweaked}} =
               Poprf.blind(input_b, info_b, pk)

      assert {:ok, {evaluated, proof}} = Poprf.blind_evaluate(sk, blinded, info_b)

      assert {:ok, output} =
               Poprf.finalize(input_b, blind, evaluated, blinded, proof, info_b, tweaked)

      assert {:ok, ^output} = Poprf.evaluate(sk, input_b, info_b)
    end

    test "a tampered proof is a cryptographic rejection (:invalid)" do
      %{secret_key: sk, public_key: pk} = Poprf.generate_keypair()
      input_b = Base.encode64("msg")
      info_b = Base.encode64("info")

      {:ok, %{blind: blind, blinded_element: blinded, tweaked_key: tweaked}} =
        Poprf.blind(input_b, info_b, pk)

      {:ok, {evaluated, proof}} = Poprf.blind_evaluate(sk, blinded, info_b)

      <<first, rest::binary>> = Base.decode64!(proof)
      bad_proof = Base.encode64(<<first + 1, rest::binary>>)

      assert :invalid =
               Poprf.finalize(input_b, blind, evaluated, blinded, bad_proof, info_b, tweaked)
    end

    test "a wrong info binds a different tweaked key and is rejected" do
      %{secret_key: sk, public_key: pk} = Poprf.generate_keypair()
      input_b = Base.encode64("msg")

      {:ok, %{blind: blind, blinded_element: blinded}} =
        Poprf.blind(input_b, Base.encode64("info-a"), pk)

      {:ok, %{tweaked_key: tweaked_b}} = Poprf.blind(input_b, Base.encode64("info-b"), pk)
      {:ok, {evaluated, proof}} = Poprf.blind_evaluate(sk, blinded, Base.encode64("info-a"))

      assert :invalid =
               Poprf.finalize(
                 input_b,
                 blind,
                 evaluated,
                 blinded,
                 proof,
                 Base.encode64("info-a"),
                 tweaked_b
               )
    end
  end

  describe "structural errors" do
    test "wrong lengths and invalid base64 are {:error, _}" do
      assert {:error, _} = Poprf.derive_key_pair(Base.encode64(<<0::248>>), Base.encode64(""))
      assert {:error, _} = Poprf.public_key(Base.encode64(<<0::264>>))
      assert {:error, _} = Poprf.blind(Base.encode64("m"), Base.encode64("i"), "not base64!")

      %{secret_key: sk} = Poprf.generate_keypair()
      assert {:error, _} = Poprf.blind_evaluate(sk, Base.encode64(<<0::248>>), Base.encode64("i"))
      assert {:error, _} = Poprf.evaluate(sk, Base.encode64("m"), "not base64!")
    end
  end
end
