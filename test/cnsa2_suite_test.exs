defmodule MetamorphicCrypto.Cnsa2SuiteTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.{Hash, Hybrid, Seal, Sign}

  # Cross-language wire-format pins, mirroring
  # metamorphic-crypto/tests/cnsa2_vectors.rs. The derived signature public keys
  # are fully deterministic, so we pin their SHA3-512 digest to assert the NIF
  # produces byte-identical output to the Rust core.
  @sig_sk_pure "ECAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/"
  @sig_sk_matched_cat3 "EwABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3OGRlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKD"
  @sig_sk_matched_cat5 "FAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQcjJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn"

  defp sha3_512_hex(b64_bytes) do
    b64_bytes
    |> Hash.sha3_512!()
    |> Base.decode64!()
    |> Base.encode16(case: :lower)
  end

  # ── KEM / seal (#311) ───────────────────────────────────────────────────────

  describe "PureCnsa2 KEM (ML-KEM-1024 + AES-256-GCM, Cat-5)" do
    test "keypair sizes: combined pk is ML-KEM-1024 ek only" do
      assert {:ok, {pk, sk}} = Hybrid.generate_keypair_suite(:pure_cnsa2, :cat5)
      assert byte_size(Base.decode64!(pk)) == 1568
      assert byte_size(Base.decode64!(sk)) == 32
    end

    test "seal structure, version tag 0x10, and roundtrip" do
      {:ok, {pk, sk}} = Hybrid.generate_keypair_suite(:pure_cnsa2, :cat5)
      pt = "32-byte symmetric context key!!!"

      assert {:ok, ct} = Hybrid.seal_suite(pt, pk, :pure_cnsa2, :cat5)
      raw = Base.decode64!(ct)
      assert <<0x10, _rest::binary>> = raw
      # tag(1) || ML-KEM-1024 ct(1568) || nonce(12) || aead(pt + 16-byte tag)
      assert byte_size(raw) == 1 + 1568 + 12 + byte_size(pt) + 16
      assert {:ok, ^pt} = Hybrid.open(ct, sk)
    end

    test "nondeterministic ciphertext, empty plaintext roundtrip" do
      {:ok, {pk, sk}} = Hybrid.generate_keypair_suite(:pure_cnsa2, :cat5)
      {:ok, ct1} = Hybrid.seal_suite("x", pk, :pure_cnsa2, :cat5)
      {:ok, ct2} = Hybrid.seal_suite("x", pk, :pure_cnsa2, :cat5)
      assert ct1 != ct2
      assert {:ok, ct} = Hybrid.seal_suite("", pk, :pure_cnsa2, :cat5)
      assert {:ok, ""} = Hybrid.open(ct, sk)
    end

    test "below Cat-5 is rejected" do
      assert {:error, _} = Hybrid.generate_keypair_suite(:pure_cnsa2, :cat3)
      assert {:error, _} = Hybrid.generate_keypair_suite(:pure_cnsa2, :cat1)
    end

    test "wrong key fails" do
      {:ok, {pk, _sk}} = Hybrid.generate_keypair_suite(:pure_cnsa2, :cat5)
      {:ok, {_pk2, sk2}} = Hybrid.generate_keypair_suite(:pure_cnsa2, :cat5)
      {:ok, ct} = Hybrid.seal_suite("secret", pk, :pure_cnsa2, :cat5)
      assert {:error, _} = Hybrid.open(ct, sk2)
    end
  end

  describe "HybridMatched KEM" do
    test "Cat-3 (ML-KEM-768 + X448) sizes, tag 0x13, roundtrip" do
      assert {:ok, {pk, sk}} = Hybrid.generate_keypair_suite(:hybrid_matched, :cat3)
      # ML-KEM-768 ek(1184) || X448 pk(56)
      assert byte_size(Base.decode64!(pk)) == 1184 + 56

      pt = "matched cat-3 key material......!"
      {:ok, ct} = Hybrid.seal_suite(pt, pk, :hybrid_matched, :cat3)
      raw = Base.decode64!(ct)
      assert <<0x13, _rest::binary>> = raw
      # tag(1) || ML-KEM-768 ct(1088) || X448 eph pk(56) || nonce(12) || aead(pt+16)
      assert byte_size(raw) == 1 + 1088 + 56 + 12 + byte_size(pt) + 16
      assert {:ok, ^pt} = Hybrid.open(ct, sk)
    end

    test "Cat-5 (ML-KEM-1024 + P-521) sizes, tag 0x14, roundtrip" do
      assert {:ok, {pk, sk}} = Hybrid.generate_keypair_suite(:hybrid_matched, :cat5)
      # ML-KEM-1024 ek(1568) || P-521 uncompressed pk(133)
      assert byte_size(Base.decode64!(pk)) == 1568 + 133

      pt = "matched cat-5 key material......!"
      {:ok, ct} = Hybrid.seal_suite(pt, pk, :hybrid_matched, :cat5)
      raw = Base.decode64!(ct)
      assert <<0x14, _rest::binary>> = raw
      assert byte_size(raw) == 1 + 1568 + 133 + 12 + byte_size(pt) + 16
      assert {:ok, ^pt} = Hybrid.open(ct, sk)
    end

    test "Cat-1 reuses the legacy 0x01 X25519 construction" do
      assert {:ok, {pk, sk}} = Hybrid.generate_keypair_suite(:hybrid_matched, :cat1)
      assert byte_size(Base.decode64!(pk)) == 832
      {:ok, ct} = Hybrid.seal_suite("matched cat1", pk, :hybrid_matched, :cat1)
      assert <<0x01, _rest::binary>> = Base.decode64!(ct)
      assert {:ok, "matched cat1"} = Hybrid.open(ct, sk)
    end
  end

  describe "context-label binding" do
    test "default label round-trips via open/2" do
      assert Hybrid.seal_context_v1() == "metamorphic/seal/v1"
      {:ok, {pk, sk}} = Hybrid.generate_keypair_suite(:pure_cnsa2, :cat5)
      {:ok, ct} = Hybrid.seal_suite("ctx", pk, :pure_cnsa2, :cat5)
      assert {:ok, "ctx"} = Hybrid.open(ct, sk)
    end

    test "custom label binds: open with matching label succeeds, mismatch fails" do
      {:ok, {pk, sk}} = Hybrid.generate_keypair_suite(:pure_cnsa2, :cat5)

      {:ok, ct} =
        Hybrid.seal_suite("tenant secret", pk, :pure_cnsa2, :cat5,
          context_label: "mosslet/seal/v1"
        )

      assert {:ok, "tenant secret"} = Hybrid.open(ct, sk, "mosslet/seal/v1")
      # Wrong label is AAD-bound and must fail authentication.
      assert {:error, _} = Hybrid.open(ct, sk, "metamorphic/seal/v1")
      assert {:error, _} = Hybrid.open(ct, sk)
    end
  end

  describe "tamper rejection" do
    test "flipping a ciphertext byte fails GCM authentication" do
      {:ok, {pk, sk}} = Hybrid.generate_keypair_suite(:pure_cnsa2, :cat5)
      {:ok, ct} = Hybrid.seal_suite("authentic", pk, :pure_cnsa2, :cat5)
      raw = Base.decode64!(ct)
      # Flip the final byte (inside the GCM tag).
      last = byte_size(raw) - 1
      <<head::binary-size(^last), b>> = raw
      tampered = Base.encode64(<<head::binary, Bitwise.bxor(b, 0xFF)>>)
      assert {:error, _} = Hybrid.open(tampered, sk)
    end
  end

  describe "Seal.seal_for_user with :suite option" do
    test "pure_cnsa2 routes through the suite seal and Hybrid.open recovers it" do
      {:ok, {pq_pk, pq_sk}} = Hybrid.generate_keypair_suite(:pure_cnsa2, :cat5)
      {classical_pk, _classical_sk} = MetamorphicCrypto.Keys.generate_keypair()

      assert {:ok, ct} =
               Seal.seal_for_user("unified secret", classical_pk,
                 pq_public_key: pq_pk,
                 suite: :pure_cnsa2,
                 level: :cat5
               )

      assert <<0x10, _rest::binary>> = Base.decode64!(ct)
      assert {:ok, "unified secret"} = Hybrid.open(ct, pq_sk)
    end
  end

  # ── Signatures (#312) ─────────────────────────────────────────────────────────

  describe "PureCnsa2 signatures (ML-DSA-87, Cat-5)" do
    test "derived public key is byte-identical to the Rust core (SHA3-512 pin)" do
      {:ok, pk} = Sign.derive_public_key(@sig_sk_pure)
      raw = Base.decode64!(pk)
      assert <<0x10, _rest::binary>> = raw
      assert byte_size(raw) == 1 + 2592

      assert sha3_512_hex(pk) ==
               "af6062b6adbb5f4bf8bee855a358673a3b5d414204f0242b1f570b05dc803927" <>
                 "ecaaff019c83e41fc54571b7c84ccc75ba68635c5a65102d20f08316cb853177"
    end

    test "sign/verify roundtrip, signature size, tamper rejection" do
      {:ok, kp} = Sign.generate_signing_keypair_suite(:pure_cnsa2, :cat5)
      ctx = Sign.sign_context_v1()
      {:ok, sig} = Sign.sign("checkpoint", ctx, kp.secret_key)
      # tag || ML-DSA-87 sig
      assert byte_size(Base.decode64!(sig)) == 1 + 4627
      assert Sign.verify("checkpoint", ctx, sig, kp.public_key)
      refute Sign.verify("tampered", ctx, sig, kp.public_key)
    end

    test "below Cat-5 is rejected" do
      assert {:error, _} = Sign.generate_signing_keypair_suite(:pure_cnsa2, :cat3)
    end
  end

  describe "HybridMatched signatures" do
    test "Cat-3 (Ed448 + ML-DSA-65) derived pubkey pin + roundtrip" do
      {:ok, pk} = Sign.derive_public_key(@sig_sk_matched_cat3)
      raw = Base.decode64!(pk)
      assert <<0x13, _rest::binary>> = raw
      # tag || Ed448 pk(57) || ML-DSA-65 pk(1952)
      assert byte_size(raw) == 1 + 57 + 1952

      assert sha3_512_hex(pk) ==
               "f0bc0effd7668196467f0eeeccd376c5337797bfdc1203f5a1e13ff6017fbbe3" <>
                 "550ed662ee7c8c9e26607410cb46e3ed19e1c52295d5863c234a5991618119d4"

      {:ok, kp} = Sign.generate_signing_keypair_suite(:hybrid_matched, :cat3)
      {:ok, sig} = Sign.sign("entry", Sign.sign_context_v1(), kp.secret_key)
      # tag || Ed448 sig(114) || ML-DSA-65 sig(3309)
      assert byte_size(Base.decode64!(sig)) == 1 + 114 + 3309
      assert Sign.verify("entry", Sign.sign_context_v1(), sig, kp.public_key)
    end

    test "Cat-5 (ECDSA-P-521 hedged + ML-DSA-87) derived pubkey pin + roundtrip" do
      {:ok, pk} = Sign.derive_public_key(@sig_sk_matched_cat5)
      raw = Base.decode64!(pk)
      assert <<0x14, _rest::binary>> = raw
      # tag || ECDSA-P-521 pk(133) || ML-DSA-87 pk(2592)
      assert byte_size(raw) == 1 + 133 + 2592

      assert sha3_512_hex(pk) ==
               "0d9125727b3ff64a9d305130e440e89d3b915c4b4738ac1a94e4348bad0d572b" <>
                 "516bead707d14abf18d07991801aaa29c756f8c0a92a6635e729fa6ff78519f3"

      {:ok, kp} = Sign.generate_signing_keypair_suite(:hybrid_matched, :cat5)
      {:ok, sig} = Sign.sign("entry", Sign.sign_context_v1(), kp.secret_key)
      # tag || ECDSA-P-521 sig(132) || ML-DSA-87 sig(4627)
      assert byte_size(Base.decode64!(sig)) == 1 + 132 + 4627
      assert Sign.verify("entry", Sign.sign_context_v1(), sig, kp.public_key)
    end
  end
end
