# Install

## Requirements

- **macOS on Apple Silicon**, or **Linux** (x86_64 or arm64) with KVM. Windows is planned.
- **smolvm 1.32.2 or newer**: `brew install smol-machines/tap/smolvm`, or a release tarball from
  [smol-machines/smolvm](https://github.com/smol-machines/smolvm/releases).
- On Linux, your user needs read/write access to `/dev/kvm` (usually membership of the `kvm` group).
- A normal user account. smolbento refuses to run as root (see [Security](SECURITY.md)).

Docker is **not** needed on the host. Agent images are pulled by smolvm directly.

## Install from source

From a checkout, with [Nix](https://nixos.org) and [direnv](https://direnv.net):

```sh
direnv allow
just install
```

This installs `smolbento` into `~/.cargo/bin` and links `sbt`, `sbx` and `bento` to it.

!!! warning "Docker's `sbx`"
    If Docker Sandboxes is also installed, the `sbx` link can shadow (or be shadowed by) Docker's
    `sbx`, depending on your `PATH` order. Use `sbt` or `bento` if you want both side by side, or
    delete `~/.cargo/bin/sbx`.

With Nix only, `nix build` produces `result/bin/` with the same names.

## Install a release

Release tarballs for `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu` are attached to each GitHub release, each signed with a Sigstore bundle
(`.sigstore.json`). Verify, unpack, and put the directory on your `PATH`:

```sh
cosign verify-blob --bundle smolbento-<target>.tar.gz.sigstore.json \
  --certificate-identity-regexp 'https://github.com/pelotech/smolbento/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  smolbento-<target>.tar.gz
tar xzf smolbento-<target>.tar.gz
```

Linux binaries need glibc 2.28 or newer.

## Check your setup

```sh
sbt diagnose
```

Every line should start with `ok`. It checks the smolvm version, hypervisor access (`/dev/kvm` on
Linux, smolvm's hypervisor entitlement on macOS) and your config file. See
[Troubleshooting](troubleshooting.md) if anything says `FAIL`.

## Shell completions

```sh
sbt completion zsh > "${fpath[1]}/_sbt"     # also: bash, fish, powershell
```
