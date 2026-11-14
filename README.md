# smolbento

Run coding agents in [smolvm](https://github.com/smol-machines/smolvm) microVMs, with the command
line of Docker [Sandboxes](https://docs.docker.com/ai/sandboxes/) (`sbx`). One binary, invoked as
`sbt`, `sbx` or `bento`. It has no daemon and needs no Docker on the host.

## Install

Needs smolvm 1.34.4 or newer. Install smolbento with Homebrew, from source, or from a release. See
[Install](docs/install.md).

## First run

```sh
cd ~/code/myrepo
# create a sandbox for this directory and attach Claude Code
sbt run claude
```

Choose a network policy when asked (`balanced` suits most work). Give agents their API keys with
`sbt secret set`. They see only placeholders. When the last session ends, the sandbox stops. Run
`sbt run claude` again to pick up where you left off. See [Usage](docs/usage.md#secrets).

## Documentation

- [Usage](docs/usage.md): running agents, workspaces, files, cleaning up
- [Configuration](docs/configuration.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Full index](docs/README.md): architecture, security, development and contributing
