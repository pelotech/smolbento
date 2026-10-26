# smolbento

A [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) (`sbx`) compatible CLI for running
coding agents in [smolvm](https://github.com/smol-machines/smolvm) microVMs. One binary, invoked
as `sbt`, `sbx` or `bento`; no daemon and no Docker needed on the host.

```sh
brew install smol-machines/tap/smolvm   # smolvm 1.32.2 or newer
just install                            # installs sbt, sbx and bento into ~/.cargo/bin
cd ~/code/myrepo
sbt run claude                          # sandbox for this directory, attach to Claude Code
```

> **Early days:** sandboxes currently have open network access. See
> [Development status](docs/development-status.md) for what's done and what's next.

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
