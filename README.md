# smolbento

A [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) (`sbx`) compatible CLI for running
coding agents in [smolvm](https://github.com/smol-machines/smolvm) microVMs. One binary, invoked
as `sbt`, `sbx` or `bento`; no daemon and no Docker needed on the host.

```sh
# smolvm, installed as a dependency
brew tap smol-machines/tap
# Homebrew 7+ only loads trusted third-party taps
brew trust pelotech/tap smol-machines/tap
# installs smolbento, sbt and bento
brew install pelotech/tap/smolbento
cd ~/code/myrepo
# sandbox for this directory, attach to Claude Code
sbt run claude
```

Building from source and release tarballs are covered in [Install](docs/install.md).

> Choose a network policy when asked (`balanced` suits most work), and give agents API keys with
> `sbt secret set`: they only ever see placeholders. See
> [Development status](docs/development-status.md).

## Documentation

- [Install](docs/install.md)
- [Usage](docs/usage.md)
- [Configuration](docs/configuration.md)
- [sbx compatibility](docs/sbx-compatibility.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Architecture](docs/architecture.md)
- [Security](docs/SECURITY.md)
- [Development](docs/development.md) and [Contributing](docs/CONTRIBUTING.md)
- [Development status](docs/development-status.md)
