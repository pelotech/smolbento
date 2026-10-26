# Architecture

## Shape

smolbento is a single Rust binary that drives the `smolvm` command-line tool. It doesn't link
smolvm as a library: linking would mean shipping libkrun and signing our binary with Apple's
hypervisor entitlement, and the smolvm CLI already offers everything needed, with JSON output.

```
sbt ── clap CLI (mirrors sbx) ── sandbox logic ── Runner ──> smolvm ──> microVM
```

All smolvm calls go through one `Runner` trait (`src/smolvm/`). The real runner spawns
`smolvm --error-format json …` and parses its JSON output and errors; tests swap in a fake runner
and assert the exact smolvm command lines.

Interactive commands (`run`, `exec -it`) hand your terminal straight to `smolvm machine exec`, so
raw mode, window resizes and colours pass through untouched.

## State

There's no smolbento database. A sandbox is a smolvm machine named `sbx-<name>`, and everything
smolbento needs to know about it (agent, workspaces, creation time, whether it runs Docker) is stored
as labels on the machine when it's created. `sbt ls` is `smolvm machine ls --json` filtered to
machines with an `sbx.name` label. The only files smolbento writes are its settings and the session
markers described below.

## Lifecycle

**Create** builds one `smolvm machine create` call: the agent image, your workspaces mounted at the
same paths, CPU and memory, published ports, labels, and a `sleep infinity` workload that keeps the
VM up between sessions. Every sandbox uses smolvm's `virtio-net` network backend, which later phases
need to change network policy and ports on a running sandbox.

**Start** runs `smolvm machine start`, then two setup steps as root inside the VM:

1. *Identity:* the image's `agent` user is given your uid (`usermod -o -u <uid> agent`). smolvm's
   file sharing passes host uids through, so this is what lets the agent write your workspace and
   makes its files yours on the host.
2. *Docker:* for Docker-enabled sandboxes, `dockerd` is started in the background. Its data lives in
   `/var/lib/docker` and `/var/lib/containerd`, which are directories on the VM's own disk rather than
   the image's overlay filesystem, because Docker's storage can't sit on an overlay.

**Run** creates and starts as needed, then execs the agent as `agent` in the workspace. While
attached, it keeps a session file (`~/.cache/smolbento/sessions/<name>/<pid>`). When it exits it
removes that file and stops the sandbox if no other live session remains, unless the sandbox was
started with `run -d`.

## Code map

| Path | Responsibility |
|---|---|
| `src/main.rs` | Entry point: runs the CLI and maps errors to exit codes |
| `src/cli/` | Command definitions mirroring sbx, and thin handlers |
| `src/smolvm/` | `Runner`, the typed smolvm client, JSON types, the test fake |
| `src/sandbox/` | Names, labels, create plan, start steps, sessions, option parsing |
| `src/agents.rs` | Agent presets |
| `src/workspace.rs` | Workspace paths and mounts |
| `src/config.rs` | Paths and settings |

See [Development status](development-status.md) for the modules later phases add (network policy,
secrets, the git remote helper, kits, host services, MCP, the dashboard).
