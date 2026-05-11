defmodule Mix.Tasks.MetamorphicCrypto.Gen.Key do
  @shortdoc "Generate a random 32-byte encryption key"

  @moduledoc """
  Generates a random 32-byte encryption key for use with MetamorphicCrypto.

      $ mix metamorphic_crypto.gen.key

  The output is a base64-encoded key suitable for:

  - `config :metamorphic_crypto, :secret_key` (Ecto encrypted fields)
  - `config :metamorphic_crypto, :hmac_key` (blind indexes)
  - Any `MetamorphicCrypto.SecretBox` operation

  ## Options

  - `--count` or `-n` — number of keys to generate (default: 1)

  ## Example

      $ mix metamorphic_crypto.gen.key
      Generated key:
      xK7m2Fq9+PnNz3v...

      Add to your config/runtime.exs:
          config :metamorphic_crypto, :secret_key, System.fetch_env!("METAMORPHIC_CRYPTO_KEY")

  """

  use Mix.Task

  @impl true
  def run(args) do
    {opts, _, _} = OptionParser.parse(args, aliases: [n: :count], strict: [count: :integer])
    count = Keyword.get(opts, :count, 1)

    # Start the NIF application so we can call generate_key
    Mix.Task.run("app.start")

    keys = for _ <- 1..count, do: MetamorphicCrypto.Keys.generate_key()

    case keys do
      [key] ->
        Mix.shell().info("""

        Generated key:
            #{key}

        Add to your environment:
            export METAMORPHIC_CRYPTO_KEY="#{key}"

        Then in config/runtime.exs:
            config :metamorphic_crypto, :secret_key, System.fetch_env!("METAMORPHIC_CRYPTO_KEY")
        """)

      keys ->
        Mix.shell().info("\nGenerated #{count} keys:\n")

        Enum.each(keys, fn key ->
          Mix.shell().info("    #{key}")
        end)

        Mix.shell().info("")
    end
  end
end
