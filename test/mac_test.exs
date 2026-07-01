defmodule MetamorphicCrypto.MacTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.Mac

  # Hex -> base64 (the NIF wire encoding). RFC vectors are published in hex.
  defp b64(hex), do: hex |> Base.decode16!(case: :lower) |> Base.encode64()

  describe "hmac_sha256_len/0" do
    test "is 32 (a SHA-256 digest)" do
      assert Mac.hmac_sha256_len() == 32
    end
  end

  # RFC 4231 known-answer vectors for HMAC-SHA-256. Reused value-for-value with
  # the Rust core / WASM so parity is proven across all three targets.
  describe "RFC 4231 known-answer tests" do
    test "case 1" do
      key = b64("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
      # "Hi There"
      data = b64("4869205468657265")
      assert {:ok, tag} = Mac.hmac_sha256(key, data)

      assert Base.decode16!(
               "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
               case: :lower
             ) == Base.decode64!(tag)
    end

    test "case 2 (short ASCII key, ASCII message)" do
      key = Base.encode64("Jefe")
      data = Base.encode64("what do ya want for nothing?")
      assert {:ok, tag} = Mac.hmac_sha256(key, data)

      assert Base.decode16!(
               "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
               case: :lower
             ) == Base.decode64!(tag)
    end

    test "case 3" do
      key = b64(String.duplicate("aa", 20))
      data = b64(String.duplicate("dd", 50))
      assert {:ok, tag} = Mac.hmac_sha256(key, data)

      assert Base.decode16!(
               "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
               case: :lower
             ) == Base.decode64!(tag)
    end

    test "case 6 (key longer than the block size is hashed first)" do
      key = b64(String.duplicate("aa", 131))
      data = Base.encode64("Test Using Larger Than Block-Size Key - Hash Key First")
      assert {:ok, tag} = Mac.hmac_sha256(key, data)

      assert Base.decode16!(
               "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
               case: :lower
             ) == Base.decode64!(tag)
    end
  end

  describe "properties" do
    test "distinct keys give distinct tags" do
      msg = Base.encode64("msg")
      {:ok, t1} = Mac.hmac_sha256(Base.encode64("k1"), msg)
      {:ok, t2} = Mac.hmac_sha256(Base.encode64("k2"), msg)
      assert t1 != t2
    end

    test "distinct messages give distinct tags" do
      key = Base.encode64("k")
      {:ok, t1} = Mac.hmac_sha256(key, Base.encode64("a"))
      {:ok, t2} = Mac.hmac_sha256(key, Base.encode64("b"))
      assert t1 != t2
    end

    test "is deterministic" do
      key = Base.encode64("k")
      msg = Base.encode64("m")
      assert Mac.hmac_sha256(key, msg) == Mac.hmac_sha256(key, msg)
    end

    test "empty key and message is defined (32-byte tag)" do
      assert {:ok, tag} = Mac.hmac_sha256("", "")
      assert byte_size(Base.decode64!(tag)) == 32
    end
  end

  describe "error / bang paths" do
    test "invalid base64 returns {:error, _}" do
      assert {:error, _} = Mac.hmac_sha256("not valid base64!!!", Base.encode64("m"))
    end

    test "bang variant returns the tag directly and raises on bad input" do
      assert is_binary(Mac.hmac_sha256!(Base.encode64("k"), Base.encode64("m")))

      assert_raise RuntimeError, ~r/HMAC failed/, fn ->
        Mac.hmac_sha256!("not valid base64!!!", Base.encode64("m"))
      end
    end
  end
end
