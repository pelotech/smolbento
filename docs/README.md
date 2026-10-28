# smolbento

smolbento runs coding agents (Claude Code, Codex, Gemini, OpenCode and others) inside
[smolvm](https://github.com/smol-machines/smolvm) microVMs, with the same command line as
Docker's [Sandboxes](https://docs.docker.com/ai/sandboxes/) (`sbx`). It's one binary, invoked as
`sbt`, `sbx` or `bento`, and it needs no daemon and no Docker on the host.

Each sandbox is a small VM with its own kernel and its own Docker engine. Your project directory is
mounted at the same path inside it, and the agent runs with permission prompts turned off, because
the VM is the boundary.

## Quick start

```sh
brew install smol-machines/tap/smolvm   # smolvm 1.32.4 or newer
just install                            # from a checkout of this repo
cd ~/code/myrepo
sbt run claude                          # create a sandbox for this directory and attach
```

When you exit the agent, the sandbox stops; run `sbt run claude` again to pick up where you left
off. See [Usage](usage.md) for everything else.

## Pages

- [Install](install.md): prerequisites, installing, checking your setup
- [Usage](usage.md): running agents, workspaces, exec, copying files, cleaning up
- [Configuration](configuration.md): settings, environment variables, where files live
- [sbx compatibility](sbx-compatibility.md): what works like sbx, what doesn't yet, what never will
- [Troubleshooting](troubleshooting.md): `sbt diagnose` and common problems
- [Architecture](architecture.md): how smolbento drives smolvm
- [Security](SECURITY.md): what a sandbox isolates today, and reporting issues
- [Development](development.md): building, testing, CI and releases
- [Development status](development-status.md): what's done and what's left
- [Contributing](CONTRIBUTING.md)
