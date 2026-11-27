# Install

Install, upgrade and remove smolbento, and check your setup.

## Requirements

- macOS on Apple Silicon, or Linux (x86_64 or arm64) with KVM. Windows is planned.
- On Linux, read/write access to `/dev/kvm` (usually through the `kvm` group), and the bzip2
  library (`libbz2.so.1`, in most distributions by default).
- A normal user account. smolbento refuses to run as root (see [Security](SECURITY.md)).

Docker isn't needed on the host. smolvm pulls agent images itself.

smolvm is installed automatically: smolbento downloads the smolvm release it was tested with from
[smol-machines/smolvm](https://github.com/smol-machines/smolvm/releases) the first time you run it,
checks it against the checksum built into smolbento, and keeps it in `~/.smolbento` with your
sandboxes. To download it ahead (before going offline, say), run `bento smolvm --version`.

## Install with Homebrew

```sh
# once: Homebrew 7+ only loads trusted taps
brew tap pelotech/tap && brew trust pelotech/tap
brew install pelotech/tap/smolbento
```

This installs `smolbento` and links `bento` to it, plus `e2fsprogs` on macOS (smolvm formats
disks larger than 20 GiB with it). `sbx` and `sbt` aren't linked, so they can't clash with Docker's
`sbx` or Scala's `sbt`. To use those names, add `alias sbx=bento sbt=bento` to your shell.
`brew upgrade` picks up new releases.

## Install from source

With [Nix](https://nixos.org) and [direnv](https://direnv.net), from a checkout:

```sh
direnv allow
just install
```

This installs `smolbento` into `~/.cargo/bin` and links `bento` and `sbx` to it. With Nix
only, `nix build` produces the same names in `result/bin/`.

!!! warning "Docker's `sbx`"
    If Docker Sandboxes is also installed, the `sbx` link can shadow Docker's `sbx`, or be shadowed
    by it, depending on your `PATH` order. To use both, run `bento`, or delete
    `~/.cargo/bin/sbx`.

## Install a release

Each GitHub release has tarballs for `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu`, each signed with a Sigstore bundle (`.sigstore.json`). Verify one,
unpack it, and put the directory on your `PATH`:

```sh
TARGET=aarch64-apple-darwin
cosign verify-blob --bundle "smolbento-$TARGET.tar.gz.sigstore.json" \
  --certificate-identity-regexp 'https://github.com/pelotech/smolbento/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "smolbento-$TARGET.tar.gz"
tar xzf "smolbento-$TARGET.tar.gz"
```

Limits: Linux binaries need glibc 2.28 or newer. On macOS, `brew install e2fsprogs` for disks over
20 GiB.

## Upgrading

Before 1.0, recreate your sandboxes after upgrading smolbento: a sandbox from an older version may
not start or work fully. Settings, secrets and policies carry over. Saved templates may not: if
`create -t` refuses one, save it again from a new sandbox. To keep what's inside a sandbox
(installed tools, agent logins), save it as a template first:

```sh
bento stop NAME
bento template save NAME NAME-saved:v1
bento rm NAME
bento create AGENT PATH --name NAME -t NAME-saved:v1
```

## Uninstalling

Remove smolbento's sandboxes and files first, then smolbento:

```sh
bento reset --force
# or delete the binary and its links
brew uninstall smolbento
```

`bento reset` deletes every sandbox (including ones from before smolbento downloaded its own smolvm),
its settings, secrets and templates, and `~/.smolbento` with the smolvm in it. If smolbento is
already gone, delete `~/.smolbento` and the folders listed in
[Configuration](configuration.md#files).

## Check your setup

```sh
bento diagnose
```

Every line should start with `ok`. It checks the smolvm smolbento runs, hypervisor access
(`/dev/kvm` on Linux, smolvm's hypervisor entitlement on macOS) and your config file. If a line
says `FAIL`, see [Troubleshooting](troubleshooting.md).

## Shell completions

```sh
# also: bash, fish, powershell
bento completion zsh > "${fpath[1]}/_bento"
```

Run as `sbx` or `bento`, it generates completions for that name (`sbx completion zsh`).
