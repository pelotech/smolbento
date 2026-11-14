# Architecture

## Shape

smolbento is one Rust binary that drives the `smolvm` CLI. It doesn't link smolvm as a library.
Doing so would mean shipping libkrun and signing our binary with Apple's hypervisor entitlement.

```
sbt ── clap CLI (mirrors sbx) ── sandbox logic ── Runner ──> smolvm ──> microVM
```

All smolvm calls go through the `Runner` trait in `src/smolvm/`. The real runner parses smolvm's JSON
output and errors. Tests swap in a fake runner and assert the exact smolvm command lines.

Interactive commands (`run`, `exec -it`) pass the terminal straight to `smolvm machine exec`, so raw
mode, resizes and colours work unchanged.

## State

smolbento has no database. A sandbox is a smolvm machine named `sbx-<name>`. Its agent, workspaces,
creation time and Docker flag are labels set at create. `sbt ls` is `smolvm machine ls --json`, filtered
to machines with an `sbx.name` label.

Global files are listed in [Configuration](configuration.md#files). On headless Linux and in CI, where no
OS keychain is usable, secret values go in a 0600 file.

## Lifecycle

**Create** makes one `smolvm machine create` call: agent image, workspaces at their host paths, CPU and
memory, published ports, labels, and a `sleep infinity` workload that keeps the VM up between sessions.
Every sandbox uses the `virtio-net` backend, which live policy and port changes need.

The workload user is the session user (`agent`, or a workload kit's image user). smolvm maps the
workspace to that user through an idmapped mount, so the agent can write it and its files stay yours on
the host.

**Start** runs `smolvm machine start`, then setup steps as root in the VM. Docker-enabled sandboxes get
the shipped `docker` kit (`kits/docker/docker.yaml`, or `--kit docker` on any image). Its startup hook
starts `dockerd` on every start. Its data lives in the kit volumes `/var/lib/docker` and
`/var/lib/containerd`, on the VM's own disk, since Docker's storage can't sit on an overlay. Sandboxes
created before kits (`sbx.docker=true`, no `sbx.kits`) still get `dockerd` started directly.

**Run** creates and starts as needed, then execs the agent as `agent` in the workspace. A v3 workload
kit's agent runs as its image user through `/bin/bash`. While attached, the session writes
`~/.cache/smolbento/sessions/<name>/<pid>`. On exit it removes that file and stops the sandbox if no
other session is live, unless the sandbox was started with `run -d`.

## Code map

| Path | Responsibility |
|---|---|
| `src/main.rs` | Entry point; maps errors to exit codes |
| `src/cli/` | Command definitions mirroring sbx, and their handlers; `upload_pack.rs` is the hidden `_upload-pack` that clone remotes run |
| `src/ctx.rs` | What every command gets: paths, settings, smolvm, stdio |
| `src/provision/` | Create and start: binds policy, secrets and kits; `builder.rs` is the kit builder sandbox |
| `src/smolvm/` | `Runner`, the typed client, JSON types, the test fake |
| `src/sandbox/` | Names, labels, create plan, start steps, guest identity, kit steps, sessions, options |
| `src/agents.rs` | Agent presets |
| `src/workspace/` | Workspace paths and mounts; `clone.rs` is clone mode on the host |
| `src/config.rs` | Paths and settings |
| `src/policy/` | Network rules, presets, compilation to smolvm flags |
| `src/secrets/` | Secret sources, stores, resolution at start |
| `src/kits/` | Kit files: load, resolve, compose the image, apply; registry pulls |
| `src/env/` | `sbxenv.yaml` environment files |
| `src/skills/` | The shared skills store |
| `src/templates.rs` | Saved templates |
| `src/mcp/` | Registered MCP servers, and what `--static-mcp` applies at create |
| `src/bridge/` | Host services: browser and clipboard shims, login relay, socket listener |
| `src/host_service.rs` | launchd and `systemd --user` units that own a sandbox's agent and bridge sockets and run `_serve` per connection; the orphan sweep |
| `src/ssh_agent/` | SSH agent forwarding: grants, label, filtering proxy |
| `src/util.rs` | Leaf helpers: shell quoting, hashing, size parsing |

Later phases are listed in [Development status](development-status.md).
