defmodule Mix.Tasks.MetamorphicCrypto.Release do
  @shortdoc "Guided local release to Hex (regenerate NIF checksums, then publish)"

  @moduledoc """
  Publishes `metamorphic_crypto` to Hex from your machine, in the correct order
  for a precompiled-NIF package.

      $ mix metamorphic_crypto.release

  Hex has no OIDC/trusted-publishing, so this is intentionally a *local*,
  one-command flow rather than CI automation: your `HEX_API_KEY` never has to
  live in GitHub secrets. The command refuses to publish unless every
  precondition is met.

  ## What it does

  1. Verifies the working tree is clean.
  2. Verifies a git tag `v<version>` exists for the current `mix.exs` version.
  3. Verifies the GitHub Release for that tag exists and carries the
     precompiled NIF assets (built by `.github/workflows/release.yml`).
  4. Runs `mix rustler_precompiled.download MetamorphicCrypto.Native --all`
     to regenerate `#{"checksum-Elixir.MetamorphicCrypto.Native.exs"}` against
     those published assets.
  5. Stops so you can commit the regenerated checksum file.
  6. After you re-run with `--publish`, runs `mix hex.publish`.

  ## Typical sequence

      # 1. bump @version in mix.exs, update CHANGELOG.md, commit
      # 2. git tag vX.Y.Z && git push origin main --tags
      # 3. wait for the "Build Precompiled NIFs" workflow to finish
      $ mix metamorphic_crypto.release          # regenerates checksums
      $ git add checksum-*.exs && git commit -m "Update NIF checksums for vX.Y.Z" && git push
      $ mix metamorphic_crypto.release --publish # mix hex.publish

  ## Options

    * `--publish` — run `mix hex.publish` (step 6). Without it, the task stops
      after regenerating checksums so you can review and commit them.
    * `--yes` — pass `--yes` through to `mix hex.publish` (non-interactive).
  """

  use Mix.Task

  @native_module "MetamorphicCrypto.Native"
  @checksum_file "checksum-Elixir.MetamorphicCrypto.Native.exs"
  @repo "moss-piglet/metamorphic_crypto"

  @impl true
  def run(args) do
    {opts, _, _} =
      OptionParser.parse(args, strict: [publish: :boolean, yes: :boolean])

    version = Mix.Project.config()[:version]
    tag = "v#{version}"

    ensure_clean_tree!()
    ensure_tag_exists!(tag)
    ensure_release_assets!(tag)

    if opts[:publish] do
      ensure_checksums_committed!()
      publish!(opts[:yes])
    else
      regenerate_checksums!()
    end
  end

  defp ensure_clean_tree! do
    case System.cmd("git", ["status", "--porcelain"]) do
      {"", 0} ->
        :ok

      {out, 0} ->
        Mix.raise("""
        Working tree is not clean. Commit or stash first:

        #{out}
        """)

      {_, code} ->
        Mix.raise("git status failed (#{code}). Are you in the repo root?")
    end
  end

  defp ensure_tag_exists!(tag) do
    case System.cmd("git", ["tag", "--list", tag]) do
      {out, 0} ->
        if String.trim(out) == "" do
          Mix.raise("""
          No git tag #{tag} found for the current mix.exs version.

          Bump @version in mix.exs (and CHANGELOG.md), commit, then:
            git tag #{tag} && git push origin main --tags
          """)
        end

      {_, code} ->
        Mix.raise("git tag --list failed (#{code}).")
    end
  end

  # The Hex package's NIF loader downloads artifacts from
  # https://github.com/#{@repo}/releases/download/<tag>/...
  # so that GitHub Release (built by CI on tag push) must exist *before* we
  # regenerate checksums or publish.
  defp ensure_release_assets!(tag) do
    Mix.shell().info("→ Checking GitHub Release #{tag} for NIF assets...")

    case System.cmd("gh", ["release", "view", tag, "--repo", @repo, "--json", "assets"],
           stderr_to_stdout: true
         ) do
      {out, 0} ->
        if String.contains?(out, "nif-") do
          Mix.shell().info("  ✓ Release #{tag} has precompiled NIF assets")
        else
          Mix.raise("""
          Release #{tag} exists but has no precompiled NIF assets yet.

          Wait for the "Build Precompiled NIFs" workflow to finish, then retry.
          """)
        end

      {out, _code} ->
        Mix.raise("""
        Could not read GitHub Release #{tag} via `gh`:

        #{out}

        Ensure the tag is pushed, CI has finished, and `gh` is authenticated
        (https://cli.github.com). You can also verify manually at:
          https://github.com/#{@repo}/releases/tag/#{tag}
        """)
    end
  end

  defp regenerate_checksums! do
    Mix.shell().info("→ Regenerating #{@checksum_file} from published NIFs...")
    Mix.Task.run("rustler_precompiled.download", [@native_module, "--all"])

    Mix.shell().info("""

    #{IO.ANSI.green()}✓ Checksums regenerated.#{IO.ANSI.reset()}

    Next:
      git add #{@checksum_file}
      git commit -m "Update NIF checksums"
      git push
      mix metamorphic_crypto.release --publish
    """)
  end

  defp ensure_checksums_committed! do
    case System.cmd("git", ["status", "--porcelain", @checksum_file]) do
      {"", 0} ->
        :ok

      {_, 0} ->
        Mix.raise("""
        #{@checksum_file} has uncommitted changes.

        Commit the regenerated checksums before publishing:
          git add #{@checksum_file} && git commit -m "Update NIF checksums" && git push
        """)

      {_, code} ->
        Mix.raise("git status failed (#{code}).")
    end
  end

  defp publish!(yes?) do
    publish_args = if yes?, do: ["--yes"], else: []

    Mix.shell().info("→ Publishing to Hex (mix hex.publish #{Enum.join(publish_args, " ")})...")
    Mix.Task.run("hex.publish", publish_args)
  end
end
