# nix

A smolbento mixin kit with Nix (flakes on), direnv with nix-direnv, and xz, for any agent. Nothing
is downloaded when a sandbox is created: Nix ships in the kit's image layer.

```sh
sbt create claude . --kit nix
sbt create docker.io/sbx/antigravity:latest . --kit nix
```

`nix` is a bare name for `ghcr.io/pelotech/smolbento/kits/nix:latest`. It needs smolbento 0.26.0
or newer. What it does in a sandbox, and its limits: [Usage](../../docs/usage.md#the-nix-kit).

## Versions

The kit is versioned on its own (release-please, tags `nix-kit-v*`) and published as
`ghcr.io/pelotech/smolbento/kits/nix:<version>` and `:latest`, for `linux/amd64` and
`linux/arm64`. While it's 0.x, a release may change what it holds; pin a version or a digest in
environment files.

Releases are signed by smolbento's release workflow, which smolbento trusts by default; the signer
is listed under [Kit signatures](../../docs/configuration.md#kit-signatures).

## Changing it

`nix.yaml` builds one layer that holds only `/nix`, `/etc/nix/nix.conf` and
`/etc/direnv/direnvrc`, so it never replaces a file of the agent's image. Keep it that way: a file
the image already has (such as `/etc/passwd`) would be replaced whole. `just e2e 2 nix_kit` builds
and checks it.
