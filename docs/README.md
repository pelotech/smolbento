# smolbento

smolbento runs coding agents (Claude Code, Codex, Cursor and others) in
[smolvm](https://github.com/smol-machines/smolvm) microVMs, with the command line of Docker
[Sandboxes](https://docs.docker.com/ai/sandboxes/) (`sbx`). Start with [Install](install.md), then
read [Usage](usage.md).

Each sandbox is a small VM with its own kernel and Docker engine. Your project directory is mounted
at the same path inside it. The agent runs with permission prompts off, because the VM is the
boundary.

## Guides

- [Install](install.md): prerequisites, installing, checking your setup
- [Usage](usage.md): running agents, workspaces, exec, copying files, cleaning up
- [Network policy and secrets](network-and-secrets.md): what a sandbox may reach, and API keys
- [Kits, skills, MCP servers and templates](kits.md): what a sandbox is built from
- [Environment files](environments.md): `sbxenv.yaml`
- [Troubleshooting](troubleshooting.md): `bento diagnose` and common problems

## Reference

- [Configuration](configuration.md): settings, environment variables, where files live
- [sbx compatibility](sbx-compatibility.md): how smolbento differs from sbx, command by command
- [Security](SECURITY.md): what a sandbox isolates today, and reporting issues

## Contributors

- [Development](development.md): building, testing, CI and releases
- [Architecture](architecture.md): how smolbento drives smolvm
- [Contributing](CONTRIBUTING.md): the checklist for a change
