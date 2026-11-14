# smolbento

smolbento runs coding agents (Claude Code, Codex, Cursor and others) in
[smolvm](https://github.com/smol-machines/smolvm) microVMs, with the command line of Docker
[Sandboxes](https://docs.docker.com/ai/sandboxes/) (`sbx`). Start with [Install](install.md), then
read [Usage](usage.md).

Each sandbox is a small VM with its own kernel and Docker engine. Your project directory is mounted
at the same path inside it. The agent runs with permission prompts off, because the VM is the
boundary.

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
