defmodule MetamorphicCrypto.HashTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.Hash

  # base64("abc") — shared input for the SHA KAT vectors below.
  @abc Base.encode64("abc")

  describe "known-answer vectors (base64 in, base64 out)" do
    test "sha3_512/1 matches the NIST/native/WASM vector for \"abc\"" do
      assert {:ok,
              "t1GFCxpXFopWk82SS2sJbgj2IYJ0RPcNiE9dAkDScS4Q4RbpGSrzyRp+xXZH45NAVzQLTPQI1aVlkvgnTuxT8A=="} =
               Hash.sha3_512(@abc)
    end

    test "sha3_256/1 matches the vector for \"abc\"" do
      assert {:ok, "Ophdp0/iJbIEXBcta9OQvYVfCG4+nVJbRr/iRRFDFTI="} = Hash.sha3_256(@abc)
    end

    test "sha256/1 matches the vector for \"abc\"" do
      assert {:ok, "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="} = Hash.sha256(@abc)
    end

    test "sha512/1 matches the vector for \"abc\"" do
      assert {:ok,
              "3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw=="} =
               Hash.sha512(@abc)
    end
  end

  describe "sha3_512_with_context/2 (domain separation)" do
    test "matches the locked native/WASM parity vector" do
      assert {:ok,
              "y/pbnlfUE85DjRUSFYNCJR1B19NFtpK8eJvoO6Ig2tsKOaknFLYbmUg5KWjtaiQn98nBDCI7X2Su8xFT0xQJng=="} =
               Hash.sha3_512_with_context(
                 "mosslet/key-fingerprint/v1",
                 Base.encode64("public key bytes")
               )
    end

    test "different context over the same data yields a different digest" do
      data = Base.encode64("public key bytes")
      {:ok, fp} = Hash.sha3_512_with_context("mosslet/key-fingerprint/v1", data)
      {:ok, log} = Hash.sha3_512_with_context("mosslet/log-entry/v1", data)
      assert fp != log
    end

    test "differs from bare sha3_512 of the same data (length-prefixed framing)" do
      data = Base.encode64("public key bytes")
      {:ok, contextual} = Hash.sha3_512_with_context("", data)
      {:ok, bare} = Hash.sha3_512(data)
      assert contextual != bare
    end
  end

  describe "output sizes" do
    test "sha3_512/1 and sha512/1 are 64 bytes" do
      {:ok, d1} = Hash.sha3_512(@abc)
      {:ok, d2} = Hash.sha512(@abc)
      assert byte_size(Base.decode64!(d1)) == 64
      assert byte_size(Base.decode64!(d2)) == 64
    end

    test "sha3_256/1 and sha256/1 are 32 bytes" do
      {:ok, d1} = Hash.sha3_256(@abc)
      {:ok, d2} = Hash.sha256(@abc)
      assert byte_size(Base.decode64!(d1)) == 32
      assert byte_size(Base.decode64!(d2)) == 32
    end
  end

  describe "determinism" do
    test "same input produces same digest" do
      assert Hash.sha3_512(@abc) == Hash.sha3_512(@abc)
    end
  end

  describe "error path" do
    test "invalid base64 input returns {:error, _}" do
      assert {:error, _reason} = Hash.sha3_512("not valid base64!!!")
    end

    test "invalid base64 with context returns {:error, _}" do
      assert {:error, _reason} =
               Hash.sha3_512_with_context("ctx", "not valid base64!!!")
    end
  end

  describe "bang variants" do
    test "return the digest directly on success" do
      assert is_binary(Hash.sha3_512!(@abc))
      assert is_binary(Hash.sha3_256!(@abc))
      assert is_binary(Hash.sha256!(@abc))
      assert is_binary(Hash.sha512!(@abc))
      assert is_binary(Hash.sha3_512_with_context!("ctx", @abc))
    end

    test "raise on invalid input" do
      assert_raise RuntimeError, ~r/hashing failed/, fn ->
        Hash.sha3_512!("not valid base64!!!")
      end

      assert_raise RuntimeError, ~r/hashing failed/, fn ->
        Hash.sha3_512_with_context!("ctx", "not valid base64!!!")
      end
    end
  end

  describe "facade delegation" do
    test "MetamorphicCrypto.sha3_512/1 delegates to Hash" do
      assert MetamorphicCrypto.sha3_512(@abc) == Hash.sha3_512(@abc)
    end

    test "MetamorphicCrypto.sha3_512_with_context/2 delegates to Hash" do
      data = Base.encode64("public key bytes")

      assert MetamorphicCrypto.sha3_512_with_context("mosslet/key-fingerprint/v1", data) ==
               Hash.sha3_512_with_context("mosslet/key-fingerprint/v1", data)
    end
  end
end
