# Install

## Requirements

- macOS on Apple Silicon, or Linux (x86_64 or arm64) with KVM. Windows is planned.
- smolvm 1.34.4 or newer: `brew install smol-machines/tap/smolvm`, or a release tarball from
  [smol-machines/smolvm](https://github.com/smol-machines/smolvm/releases).
- On Linux, read/write access to `/dev/kvm` (usually through the `kvm` group).
- A normal user account. smolbento refuses to run as root (see [Security](SECURITY.md)).

Docker isn't needed on the host. smolvm pulls agent images itself.

## Install with Homebrew

```sh
# smolvm, installed as a dependency
brew tap smol-machines/tap
# Homebrew 7+ only loads trusted third-party taps
brew trust pelotech/tap smol-machines/tap
brew install pelotech/tap/smolbento
```

This installs `smolbento` and links `sbt` and `bento` to it. `sbx` isn't linked, so it can't clash
with Docker's `sbx`. Add `alias sbx=sbt` to your shell to use that name. `brew upgrade` picks up new
releases. Run `brew tap` before `brew trust`, as above. Homebrew rejects tapping a tap that is
already trusted (see [pelotech/homebrew-tap](https://github.com/pelotech/homebrew-tap)).

!!! note "Linux"
    If smolvm fails to install from `smol-machines/tap` on Linux (1.32.3 did), install smolvm
    from its release tarball and smolbento with
    `brew install --ignore-dependencies pelotech/tap/smolbento`, or use a release tarball below.

## Install from source

With [Nix](https://nixos.org) and [direnv](https://direnv.net), from a checkout:

```sh
direnv allow
just install
```

This installs `smolbento` into `~/.cargo/bin` and links `sbt`, `sbx` and `bento` to it. With Nix
only, `nix build` produces the same names in `result/bin/`.

!!! warning "Docker's `sbx`"
    If Docker Sandboxes is also installed, the `sbx` link can shadow Docker's `sbx`, or be shadowed
    by it, depending on your `PATH` order. To use both, run `sbt` or `bento`, or delete
    `~/.cargo/bin/sbx`.

## Install a release

Release tarballs for `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu` are attached to each GitHub release. Each one is signed with a Sigstore
bundle (`.sigstore.json`). Verify it, unpack it, and put the directory on your `PATH`:

```sh
cosign verify-blob --bundle smolbento-<target>.tar.gz.sigstore.json \
  --certificate-identity-regexp 'https://github.com/pelotech/smolbento/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  smolbento-<target>.tar.gz
tar xzf smolbento-<target>.tar.gz
```

Linux binaries need glibc 2.28 or newer.

## Upgrading sandboxes from an older smolbento

Sandboxes made by an older smolbento can't start. `sbt` fails with `was created by an older
smolbento`. Remove each one with `sbt rm NAME`, then create it again. Saved templates keep working.

To keep what's inside a sandbox (installed tools, agent logins), save it as a template first. A
stopped sandbox is saved without starting it:

```sh
sbt stop NAME
sbt template save NAME NAME-saved:v1
sbt rm NAME
sbt create AGENT PATH --name NAME -t NAME-saved:v1
```

## Check your setup

```sh
sbt diagnose
```

Every line should start with `ok`. It checks the smolvm version, hypervisor access (`/dev/kvm` on
Linux, smolvm's hypervisor entitlement on macOS) and your config file. If a line says `FAIL`, see
[Troubleshooting](troubleshooting.md).

## Shell completions

```sh
# also: bash, fish, powershell
sbt completion zsh > "${fpath[1]}/_sbt"
```

Run as `sbx` or `bento`, it generates completions for that name (`sbx completion zsh`).
