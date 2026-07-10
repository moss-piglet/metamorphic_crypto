defmodule MetamorphicCrypto.SignTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.Sign

  @context Sign.sign_context_v1()

  # Wire tags and the 65-byte secret-key length are part of the stable format
  # (hedged ML-DSA makes signature *bytes* non-reproducible, so we pin framing,
  # key derivation, and roundtrips — never signature bytes).
  @tags %{cat2: 0x01, cat3: 0x02, cat5: 0x03}

  describe "sign_context_v1/0" do
    test "is the documented convention label" do
      assert Sign.sign_context_v1() == "metamorphic/sign/v1"
    end
  end

  describe "generate_signing_keypair/0,1" do
    test "defaults to :cat3" do
      kp = Sign.generate_signing_keypair()
      assert <<tag, _rest::binary>> = Base.decode64!(kp.public_key)
      assert tag == @tags.cat3
    end

    test "returns a base64 %{public_key, secret_key} map" do
      kp = Sign.generate_signing_keypair()
      assert %{public_key: pk, secret_key: sk} = kp
      assert {:ok, _} = Base.decode64(pk)
      assert {:ok, _} = Base.decode64(sk)
    end

    test "each level carries its wire tag on the public and secret key" do
      for {level, tag} <- @tags do
        kp = Sign.generate_signing_keypair(level)
        assert <<^tag, _::binary>> = Base.decode64!(kp.public_key)
        assert <<^tag, _::binary>> = Base.decode64!(kp.secret_key)
      end
    end

    test "secret key is the fixed 65 bytes (tag || ed_seed(32) || ml_seed(32))" do
      for level <- [:cat2, :cat3, :cat5] do
        kp = Sign.generate_signing_keypair(level)
        assert byte_size(Base.decode64!(kp.secret_key)) == 65
      end
    end

    test "public-key sizes match each ML-DSA parameter set" do
      # 1 (tag) + 32 (ed25519 pk) + ML-DSA pk (1312 / 1952 / 2592)
      for {level, pk_len} <- [cat2: 1312, cat3: 1952, cat5: 2592] do
        kp = Sign.generate_signing_keypair(level)
        assert byte_size(Base.decode64!(kp.public_key)) == 1 + 32 + pk_len
      end
    end

    test "rejects an unknown level" do
      unknown_level = :cat9

      assert_raise FunctionClauseError, fn ->
        Sign.generate_signing_keypair(unknown_level)
      end
    end
  end

  describe "derive_public_key/1" do
    test "reproduces the keypair's public key byte-identically (recovery hook)" do
      for level <- [:cat2, :cat3, :cat5] do
        kp = Sign.generate_signing_keypair(level)
        assert {:ok, pk} = Sign.derive_public_key(kp.secret_key)
        assert pk == kp.public_key
      end
    end

    test "is deterministic across repeated calls" do
      kp = Sign.generate_signing_keypair()
      assert Sign.derive_public_key(kp.secret_key) == Sign.derive_public_key(kp.secret_key)
    end

    test "returns {:error, _} for invalid base64" do
      assert {:error, _reason} = Sign.derive_public_key("not valid base64!!!")
    end

    test "bang variant returns the key directly and raises on bad input" do
      kp = Sign.generate_signing_keypair()
      assert Sign.derive_public_key!(kp.secret_key) == kp.public_key

      assert_raise RuntimeError, ~r/signing failed/, fn ->
        Sign.derive_public_key!("not valid base64!!!")
      end
    end
  end

  describe "sign/3 and verify/4 (roundtrip)" do
    test "a fresh signature verifies for every level" do
      for level <- [:cat2, :cat3, :cat5] do
        kp = Sign.generate_signing_keypair(level)
        assert {:ok, sig} = Sign.sign("hello transparency log", @context, kp.secret_key)
        assert Sign.verify("hello transparency log", @context, sig, kp.public_key)
      end
    end

    test "verifies an empty message and empty context" do
      kp = Sign.generate_signing_keypair()
      assert {:ok, sig} = Sign.sign("", "", kp.secret_key)
      assert Sign.verify("", "", sig, kp.public_key)
    end

    test "signature framing: tag || ed25519_sig(64) || ml_dsa_sig" do
      # 1 (tag) + 64 (ed25519 sig) + ML-DSA sig (2420 / 3309 / 4627)
      for {level, sig_len} <- [cat2: 2420, cat3: 3309, cat5: 4627] do
        kp = Sign.generate_signing_keypair(level)
        {:ok, sig} = Sign.sign("x", @context, kp.secret_key)
        raw = Base.decode64!(sig)
        assert <<tag, _::binary>> = raw
        assert tag == @tags[level]
        assert byte_size(raw) == 1 + 64 + sig_len
      end
    end
  end

  describe "hedged ML-DSA (non-reproducible signature bytes)" do
    test "two signatures over the same message differ but both verify" do
      kp = Sign.generate_signing_keypair()
      {:ok, s1} = Sign.sign("msg", @context, kp.secret_key)
      {:ok, s2} = Sign.sign("msg", @context, kp.secret_key)
      assert s1 != s2
      assert Sign.verify("msg", @context, s1, kp.public_key)
      assert Sign.verify("msg", @context, s2, kp.public_key)
    end
  end

  describe "verify/4 negative cases" do
    test "tampered message fails" do
      kp = Sign.generate_signing_keypair()
      {:ok, sig} = Sign.sign("original", @context, kp.secret_key)
      refute Sign.verify("tampered", @context, sig, kp.public_key)
    end

    test "different context fails (domain separation)" do
      kp = Sign.generate_signing_keypair()
      {:ok, sig} = Sign.sign("msg", @context, kp.secret_key)
      refute Sign.verify("msg", "metamorphic/other/v1", sig, kp.public_key)
    end

    test "wrong public key fails" do
      kp1 = Sign.generate_signing_keypair()
      kp2 = Sign.generate_signing_keypair()
      {:ok, sig} = Sign.sign("msg", @context, kp1.secret_key)
      refute Sign.verify("msg", @context, sig, kp2.public_key)
    end

    test "cross-level (Cat-3 signature vs Cat-5 key) fails" do
      kp3 = Sign.generate_signing_keypair(:cat3)
      kp5 = Sign.generate_signing_keypair(:cat5)
      {:ok, sig3} = Sign.sign("msg", @context, kp3.secret_key)
      refute Sign.verify("msg", @context, sig3, kp5.public_key)
    end

    test "strict AND: corrupting either component fails verification" do
      kp = Sign.generate_signing_keypair()
      {:ok, sig} = Sign.sign("msg", @context, kp.secret_key)
      raw = Base.decode64!(sig)

      # Flip a byte inside the Ed25519 component (offset 1).
      <<head::binary-size(1), ed_byte, ed_tail::binary>> = raw
      bad_ed = Base.encode64(head <> <<Bitwise.bxor(ed_byte, 0xFF)>> <> ed_tail)
      refute Sign.verify("msg", @context, bad_ed, kp.public_key)

      # Flip a byte inside the ML-DSA component (well past the 1 + 64 prefix).
      i = 1 + 64 + 10
      <<pre::binary-size(^i), ml_byte, ml_tail::binary>> = raw
      bad_ml = Base.encode64(pre <> <<Bitwise.bxor(ml_byte, 0xFF)>> <> ml_tail)
      refute Sign.verify("msg", @context, bad_ml, kp.public_key)
    end

    test "malformed (invalid base64) inputs return false, never raise" do
      kp = Sign.generate_signing_keypair()
      {:ok, sig} = Sign.sign("msg", @context, kp.secret_key)
      refute Sign.verify("msg", @context, "not valid base64!!!", kp.public_key)
      refute Sign.verify("msg", @context, sig, "not valid base64!!!")
    end
  end

  describe "sign/3 error path" do
    test "returns {:error, _} for an invalid secret key" do
      assert {:error, _reason} = Sign.sign("msg", @context, "not valid base64!!!")
    end

    test "bang variant signs and raises on bad input" do
      kp = Sign.generate_signing_keypair()
      assert is_binary(Sign.sign!("msg", @context, kp.secret_key))

      assert_raise RuntimeError, ~r/signing failed/, fn ->
        Sign.sign!("msg", @context, "not valid base64!!!")
      end
    end
  end

  describe "signature_posture/1 and signature_posture_from_signature/1" do
    test "public key reports {suite, level} for the default hybrid keypair" do
      for level <- [:cat2, :cat3, :cat5] do
        kp = Sign.generate_signing_keypair(level)
        assert {:ok, {:hybrid, ^level}} = Sign.signature_posture(kp.public_key)
      end
    end

    test "signature reports {suite, level}" do
      kp = Sign.generate_signing_keypair(:cat3)
      {:ok, sig} = Sign.sign("checkpoint", @context, kp.secret_key)
      assert {:ok, {:hybrid, :cat3}} = Sign.signature_posture_from_signature(sig)
    end

    test "reports the CNSA 2.0 suites (pure_cnsa2, hybrid_matched)" do
      {:ok, pure} = Sign.generate_signing_keypair_suite(:pure_cnsa2, :cat5)
      assert {:ok, {:pure_cnsa2, :cat5}} = Sign.signature_posture(pure.public_key)

      {:ok, matched} = Sign.generate_signing_keypair_suite(:hybrid_matched, :cat3)
      assert {:ok, {:hybrid_matched, :cat3}} = Sign.signature_posture(matched.public_key)
      {:ok, sig} = Sign.sign("m", @context, matched.secret_key)
      assert {:ok, {:hybrid_matched, :cat3}} = Sign.signature_posture_from_signature(sig)
    end

    test "declared == observed round-trips between key and signature" do
      {:ok, kp} = Sign.generate_signing_keypair_suite(:hybrid_matched, :cat5)
      {:ok, sig} = Sign.sign("m", @context, kp.secret_key)

      assert Sign.signature_posture(kp.public_key) ==
               Sign.signature_posture_from_signature(sig)
    end

    test "malformed / wrong-length input is a structural {:error, _}" do
      assert {:error, _} = Sign.signature_posture("not valid base64!!!")
      # A valid-base64 but truncated blob is rejected on length, not misreported.
      kp = Sign.generate_signing_keypair(:cat3)
      truncated = kp.public_key |> Base.decode64!() |> binary_part(0, 10) |> Base.encode64()
      assert {:error, _} = Sign.signature_posture(truncated)
    end
  end

  # Regression guard for the ML-DSA dirty-CPU stack overflow (SIGBUS). ML-DSA
  # signing / keygen allocate large intermediate lattice matrices on the stack
  # inside the upstream ml-dsa crate; on the BEAM dirty-CPU scheduler's ~320 KB
  # default stack that overflows and takes the whole VM down with SIGBUS. The
  # NIF now runs these on schedule = "DirtyCpu" AND borrows a 32 MiB worker stack
  # (metamorphic_crypto::on_signing_stack). If that guard regressed, the calls
  # below would crash the emulator rather than return — so a real result here is
  # the assertion. We drive keygen -> derive -> sign -> verify from a spawned
  # process (a distinct scheduler context) at Cat-3 AND Cat-5 (ML-DSA-87, the
  # heaviest parameter set that motivated the fix).
  describe "dirty-CPU large-stack signing (SIGBUS regression)" do
    for level <- [:cat3, :cat5] do
      test "keygen/derive/sign/verify survive and return real results at #{level}" do
        level = unquote(level)

        result =
          Task.async(fn ->
            kp = Sign.generate_signing_keypair(level)
            derived = Sign.derive_public_key!(kp.secret_key)
            {:ok, sig} = Sign.sign("checkpoint payload", @context, kp.secret_key)
            verified? = Sign.verify("checkpoint payload", @context, sig, kp.public_key)
            {kp.public_key, derived, verified?}
          end)
          |> Task.await(30_000)

        {public_key, derived, verified?} = result
        assert derived == public_key
        assert verified? == true
      end
    end
  end
end
