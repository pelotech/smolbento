# nix

A smolbento mixin kit with Nix (flakes on), direnv with nix-direnv, and xz, for any agent. Nothing
is downloaded when a sandbox is created: Nix ships in the kit's image layer.

```sh
sbt create claude . --kit nix
sbt create docker.io/sbx/antigravity:latest . --kit nix
```

`nix` is a bare name for `ghcr.io/pelotech/smolbento/kits/nix:latest`. Needs smolbento 0.26.0 or
newer (the first release with the kit's defaults and alias).

## What it does

- **Nix:** a multi-user store owned by root. `nix-daemon` starts with the sandbox and runs builds
  as root, with no build users; you run `nix` as yourself. `trusted-users = root *`, so a flake's
  own binary caches (`nixConfig`) are honoured; the sandbox user already has sudo.
- **PATH:** Nix's default profile and `~/.nix-profile/bin` (for `nix profile add`) come first.
- **direnv:** a workspace `.envrc` is allowed at each start (direnv keeps that record under
  `~/.local/share/direnv`, not in the repo). Agents run commands in shells that don't load it, so
  the kit tells them to use `direnv exec . <cmd>` or `nix develop -c <cmd>`. nix-direnv caches
  `use flake`/`use nix` environments.
- **Network:** allows the Nix caches and GitHub (for flake inputs), for policies other than
  `balanced`, which already has them.
- **The layer** holds `/nix`, `/etc/nix/nix.conf` and `/etc/direnv/direnvrc` only, so it never
  replaces a file of the agent's image.

## Versions

The kit is versioned on its own (release-please, tags `nix-kit-v*`) and published as
`ghcr.io/pelotech/smolbento/kits/nix:<version>` and `:latest`, for `linux/amd64` and
`linux/arm64`. While it's 0.x, a release may change what it holds; pin a version or a digest in
environment files.

Releases are signed keylessly by smolbento's release workflow, which smolbento trusts by default
(`kit.trustedSigners`): issuer `https://token.actions.githubusercontent.com`, identity
`https://github.com/pelotech/smolbento/.github/workflows/release-please.yaml@refs/heads/main`.

## Limits

- The store is on the sandbox's disk (smolvm's 10 GiB overlay by default), which smolbento can't
  size yet. Very large dev shells may run out of space.
- On an image without `runuser` or `su`, `.envrc` isn't allowed at start; run `direnv allow` once.
