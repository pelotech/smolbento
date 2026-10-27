# Development status

Last updated: 2026-10-26.

smolbento is built in phases. Each phase ships on its own.

## Current state

**Phase 1 (core lifecycle) is done.** You can run any of the 11 agents in a sandbox, exec into it,
copy files, list, stop, start and clean up, with Docker inside each sandbox and your workspace
mounted at the same path. See [Usage](usage.md).

**Phase 2 (network policy, secrets, ports) is done.** Choose `balanced` or `deny-all` for untrusted
work. See [Security](SECURITY.md).

**Phase 3a (clone mode) is done.** `sbt run --clone` gives the agent its own clone of the repo;
its commits come back through `git fetch sandbox-<name>`. See [Usage](usage.md#clone-mode).

**Phase 3b (fork) is done.** `sbt fork` copies a running sandbox, memory and all, for parallel
attempts or as an undo point. See [Usage](usage.md#fork).

Upgrading from v0.1.x: starting a sandbox now needs a chosen network policy, as in sbx. Run
`sbt policy init balanced` (or answer the prompt) before your next start; scripts without a
terminal fail until you do.

## Phases

| Phase | Scope | Status |
|---|---|---|
| 0 | Spikes: what smolvm and sbx actually do | ✅ Done |
| 1 | Repo tooling and CI; `run`, `create`, `exec`, `ls`, `start`, `stop`, `rm`, `prune`, `reset`, `cp`, `version`, `completion`, `diagnose`, `settings`, `daemon` | ✅ Done |
| 2 | Network policy (`policy init/allow/deny/rm/ls/log/check`, approvals, live changes on running sandboxes), secrets (keychain, `op://` and AWS references, `--command`; the sandbox only sees placeholders), `ports` | ✅ Done |
| 3a | `--clone` (the agent works on its own clone; only commits come back, through the `sandbox-<name>` remote) | ✅ Done |
| 3b | `fork` (copy-on-write copies of a running sandbox). `checkpoint`/`restore` dropped: secrets can't work in a restored smolvm checkpoint from the CLI | ✅ Done |
| 4 | Kits (sbx kit v2 `spec.yaml`, native Smolfiles), `sbxenv.yaml`, the `docker` and `plus` kits and image, host services (e.g. a host Ollama reachable from sandboxes) | ⏭ Next |
| 5 | `template`, `setup ssh`, static MCP, `--skills`, clipboard and browser bridges | Planned |
| 6 | `tui` dashboard (bare `sbt` opens it on a terminal) | Planned |
| 7 | Warm-start pool for near-instant creates; Windows | Planned |

## Known limitations

- Workspaces are mounted read-write unless you use `--clone`.
- Published ports bind `127.0.0.1` only, and directories (not single files) can be mounted. Both are
  smolvm limits; see [sbx compatibility](sbx-compatibility.md).
- Sandboxes can't reach services on the host yet (planned with host services, Phase 4). Under
  `allow-all`, the host's LAN IP isn't blocked, so services listening on `0.0.0.0` are reachable
  through it.
- Linux uses a 0600 file for secret values where no Secret Service runs.
- Group ids aren't mapped: group-writable shared directories aren't writable through group
  membership.

## Waiting on a release or CI

Proven on GitHub: e2e on `ubuntu-latest`, and the v0.1.1 release (all three binaries; macOS binary
verified on a Mac).

## Cleanups to do

Small issues found in review and deferred; none affect normal use.

- `run --rm` deletes the sandbox even if another session is still attached.
- If `exec` itself fails inside `run`, the auto-stop and `--rm` cleanup are skipped.
- `run --name` on an existing sandbox silently ignores create options such as `--cpus`.
- If creating a sandbox fails after the machine exists, a retry says "already exists" until
  `sbt rm -f`.
- smolvm error codes aren't mapped to friendlier hints yet.
- Settings don't yet accept sbx's `DOCKER_SANDBOXES_*` and `SBX_*` environment names.
- Shell completions are generated for `sbt` only (not `sbx`/`bento`).
- Input parsing hardening: memory sizes can overflow on absurd values, malformed `.env` lines
  are dropped silently, and empty `XDG_*` variables are treated as set.
- More tests for: `cp -L`, `exec --privileged -u`, session cleanup on `rm`/`prune`/`reset`,
  `ProcessRunner` itself.
