defmodule MetamorphicCrypto.VrfTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.Vrf

  # Hex -> base64 (the NIF wire encoding). RFC 9381 vectors are published in hex.
  defp b64(hex), do: hex |> Base.decode16!(case: :lower) |> Base.encode64()

  # RFC 9381 known-answer vectors for ECVRF-EDWARDS25519-SHA512-TAI, reused
  # value-for-value from the Rust core's locked vectors so parity is proven
  # across native Rust / WASM / NIF. Pins PK derivation, prove, proof_to_hash,
  # and verify (which returns the same beta).
  defp kat(sk, pk, alpha, pi, beta) do
    sk_b = b64(sk)
    pk_b = b64(pk)
    alpha_b = b64(alpha)
    pi_b = b64(pi)
    beta_b = b64(beta)

    assert {:ok, ^pk_b} = Vrf.public_key(sk_b)
    assert {:ok, ^pi_b} = Vrf.prove(sk_b, alpha_b)
    assert {:ok, ^beta_b} = Vrf.proof_to_hash(pi_b)
    assert {:ok, ^beta_b} = Vrf.verify(pk_b, alpha_b, pi_b)
  end

  describe "RFC 9381 known-answer tests (Edwards25519)" do
    test "example 16 (empty alpha)" do
      kat(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f" <>
          "26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab126" <>
          "8a1b0db10836d9826a528ca76567805",
        "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff" <>
          "66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"
      )
    end

    test "example 17 (one-byte alpha)" do
      kat(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593" <>
          "3bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da" <>
          "3ef39226bbc355bdc9850112c8f4b02",
        "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb" <>
          "5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"
      )
    end

    test "example 18 (two-byte alpha)" do
      kat(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf80" <>
          "96bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2" <>
          "d41b00b05081ed0f58ee5e31b3a970e",
        "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c45" <>
          "2118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f"
      )
    end
  end

  describe "constants" do
    test "expose suite id and lengths" do
      assert Vrf.suite() == 0x03
      assert Vrf.secret_key_len() == 32
      assert Vrf.public_key_len() == 32
      assert Vrf.proof_len() == 80
      assert Vrf.output_len() == 64
    end
  end

  describe "keypair / derivation" do
    test "generate_keypair returns base64 %{secret_key, public_key}" do
      assert %{secret_key: sk, public_key: pk} = Vrf.generate_keypair()
      assert byte_size(Base.decode64!(sk)) == 32
      assert byte_size(Base.decode64!(pk)) == 32
    end

    test "public_key/1 re-derives the keypair's public key" do
      %{secret_key: sk, public_key: pk} = Vrf.generate_keypair()
      assert {:ok, ^pk} = Vrf.public_key(sk)
    end
  end

  describe "prove / verify" do
    test "roundtrip: a fresh proof verifies and yields the output" do
      %{secret_key: sk, public_key: pk} = Vrf.generate_keypair()
      alpha = Base.encode64("directory identity index")
      assert {:ok, pi} = Vrf.prove(sk, alpha)
      assert {:ok, beta} = Vrf.verify(pk, alpha, pi)
      assert {:ok, ^beta} = Vrf.proof_to_hash(pi)
    end

    test "is deterministic (same key + input => same proof)" do
      %{secret_key: sk} = Vrf.generate_keypair()
      alpha = Base.encode64("x")
      assert Vrf.prove(sk, alpha) == Vrf.prove(sk, alpha)
    end

    test "tampered alpha is a cryptographic reject (:invalid)" do
      %{secret_key: sk, public_key: pk} = Vrf.generate_keypair()
      {:ok, pi} = Vrf.prove(sk, Base.encode64("original"))
      assert :invalid = Vrf.verify(pk, Base.encode64("tampered"), pi)
    end

    test "wrong key is a cryptographic reject (:invalid)" do
      %{secret_key: sk} = Vrf.generate_keypair()
      %{public_key: other_pk} = Vrf.generate_keypair()
      alpha = Base.encode64("msg")
      {:ok, pi} = Vrf.prove(sk, alpha)
      assert :invalid = Vrf.verify(other_pk, alpha, pi)
    end

    test "tampered proof is a cryptographic reject (:invalid)" do
      %{secret_key: sk, public_key: pk} = Vrf.generate_keypair()
      alpha = Base.encode64("msg")
      {:ok, pi} = Vrf.prove(sk, alpha)
      <<b, rest::binary>> = Base.decode64!(pi)
      bad = Base.encode64(<<Bitwise.bxor(b, 0x01)>> <> rest)
      assert :invalid = Vrf.verify(pk, alpha, bad)
    end
  end

  describe "structural errors vs cryptographic rejects" do
    test "wrong-length proof is {:error, _}, not :invalid" do
      %{public_key: pk} = Vrf.generate_keypair()
      short = Base.encode64(<<0::size(79)-unit(8)>>)
      assert {:error, _} = Vrf.verify(pk, Base.encode64("m"), short)
    end

    test "invalid base64 is {:error, _}" do
      %{public_key: pk} = Vrf.generate_keypair()
      assert {:error, _} = Vrf.verify(pk, Base.encode64("m"), "not valid base64!!!")
    end
  end
end
