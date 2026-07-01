defmodule MetamorphicCrypto.VrfP256Test do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.VrfP256

  # Hex -> base64 (the NIF wire encoding). RFC 9381 vectors are published in hex.
  defp b64(hex), do: hex |> Base.decode16!(case: :lower) |> Base.encode64()

  # RFC 9381 Appendix B.1 known-answer vectors for ECVRF-P256-SHA256-TAI, reused
  # value-for-value from the Rust core's locked vectors so parity is proven
  # across native Rust / WASM / NIF.
  defp kat(sk, pk, alpha, pi, beta) do
    sk_b = b64(sk)
    pk_b = b64(pk)
    alpha_b = b64(alpha)
    pi_b = b64(pi)
    beta_b = b64(beta)

    assert {:ok, ^pk_b} = VrfP256.public_key(sk_b)
    assert {:ok, ^pi_b} = VrfP256.prove(sk_b, alpha_b)
    assert {:ok, ^beta_b} = VrfP256.proof_to_hash(pi_b)
    assert {:ok, ^beta_b} = VrfP256.verify(pk_b, alpha_b, pi_b)
  end

  describe "RFC 9381 Appendix B.1 known-answer tests (P-256)" do
    test "example 10 (sample)" do
      kat(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        "73616d706c65",
        "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4" <>
          "a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af376" <>
          "b33edf7de17c6ea056d4d82de6bc02f",
        "a3ad7b0ef73d8fc6655053ea22f9bede8c743f08bbed3d38821f0e16474b505e"
      )
    end

    test "example 11 (test)" do
      kat(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        "74657374",
        "034dac60aba508ba0c01aa9be80377ebd7562c4a52d74722e0abae7dc3080ddb56" <>
          "c19e067b15a8a8174905b13617804534214f935b94c2287f797e393eb0816969d" <>
          "864f37625b443f30f1a5a33f2b3c854",
        "a284f94ceec2ff4b3794629da7cbafa49121972671b466cab4ce170aa365f26d"
      )
    end

    test "example 12 (ANSI)" do
      kat(
        "2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8",
        "03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d",
        "4578616d706c65207573696e67204543445341206b65792066726f6d20417070656e646978204c2e342e32206f6620414e53492e58392d36322d32303035",
        "03d03398bf53aa23831d7d1b2937e005fb0062cbefa06796579f2a1fc7e7b8c667d" <>
          "091c00b0f5c3619d10ecea44363b5a599cadc5b2957e223fec62e81f7b4825fc79" <>
          "9a771a3d7334b9186bdbee87316b1",
        "90871e06da5caa39a3c61578ebb844de8635e27ac0b13e829997d0d95dd98c19"
      )
    end
  end

  describe "constants" do
    test "expose suite id and lengths" do
      assert VrfP256.suite() == 0x01
      assert VrfP256.secret_key_len() == 32
      assert VrfP256.public_key_len() == 33
      assert VrfP256.proof_len() == 81
      assert VrfP256.output_len() == 32
    end
  end

  describe "keypair / derivation" do
    test "generate_keypair returns base64 %{secret_key, public_key}" do
      assert %{secret_key: sk, public_key: pk} = VrfP256.generate_keypair()
      assert byte_size(Base.decode64!(sk)) == 32
      assert byte_size(Base.decode64!(pk)) == 33
    end

    test "public_key/1 re-derives the keypair's public key" do
      %{secret_key: sk, public_key: pk} = VrfP256.generate_keypair()
      assert {:ok, ^pk} = VrfP256.public_key(sk)
    end
  end

  describe "prove / verify" do
    test "roundtrip: a fresh proof verifies and yields the output" do
      %{secret_key: sk, public_key: pk} = VrfP256.generate_keypair()
      alpha = Base.encode64("directory identity index")
      assert {:ok, pi} = VrfP256.prove(sk, alpha)
      assert {:ok, beta} = VrfP256.verify(pk, alpha, pi)
      assert {:ok, ^beta} = VrfP256.proof_to_hash(pi)
    end

    test "tampered alpha is a cryptographic reject (:invalid)" do
      %{secret_key: sk, public_key: pk} = VrfP256.generate_keypair()
      {:ok, pi} = VrfP256.prove(sk, Base.encode64("original"))
      assert :invalid = VrfP256.verify(pk, Base.encode64("tampered"), pi)
    end

    test "wrong key is a cryptographic reject (:invalid)" do
      %{secret_key: sk} = VrfP256.generate_keypair()
      %{public_key: other_pk} = VrfP256.generate_keypair()
      alpha = Base.encode64("msg")
      {:ok, pi} = VrfP256.prove(sk, alpha)
      assert :invalid = VrfP256.verify(other_pk, alpha, pi)
    end

    test "tampered proof is a cryptographic reject (:invalid)" do
      %{secret_key: sk, public_key: pk} = VrfP256.generate_keypair()
      alpha = Base.encode64("msg")
      {:ok, pi} = VrfP256.prove(sk, alpha)
      raw = Base.decode64!(pi)
      # Flip a byte in the s component (past Gamma(33) || c(16)).
      i = 33 + 16
      <<pre::binary-size(^i), b, rest::binary>> = raw
      bad = Base.encode64(pre <> <<Bitwise.bxor(b, 0x01)>> <> rest)
      assert :invalid = VrfP256.verify(pk, alpha, bad)
    end
  end

  describe "structural errors vs cryptographic rejects" do
    test "wrong-length proof is {:error, _}, not :invalid" do
      %{public_key: pk} = VrfP256.generate_keypair()
      short = Base.encode64(<<0::size(80)-unit(8)>>)
      assert {:error, _} = VrfP256.verify(pk, Base.encode64("m"), short)
    end

    test "invalid base64 is {:error, _}" do
      %{public_key: pk} = VrfP256.generate_keypair()
      assert {:error, _} = VrfP256.verify(pk, Base.encode64("m"), "not valid base64!!!")
    end
  end
end
