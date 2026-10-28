# Development status

Last updated: 2026-10-28.

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

**Phase 4a (kits) is done.** `--kit` runs Docker Sandboxes kits (published v3 kits, local v3 and
v2 directories) and Smolfiles; `sbt kit inspect/validate/add` work. See [Usage](usage.md#kits).

**Phase 4b (sbxenv.yaml) is done.** `sbt env create|run|exec|rm` read Docker Sandboxes environment
files. See [Usage](usage.md#environments-sbxenvyaml).

Docker in a sandbox is now the shipped `docker` kit, so every Docker-enabled create goes through
the kit first start: if that first start fails, the sandbox is removed. Run the same command
again once the cause is fixed.

Change you may notice: every secret `command:` source (`sbt secret set --command`, and `command:` in
an environment file) now runs from a fresh temporary directory. Give helpers by absolute path or put
them on `PATH`; a path relative to your current directory no longer works.

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
| 4a | Kits: v3 capabilities, v2 `spec.yaml`, Smolfiles, `kit inspect/validate/add`, the `docker` kit, the `_builder` sandbox | ✅ Done |
| 4b | `sbxenv.yaml` core: `env create/run/exec/rm`, files, args, user defaults, secrets, kits, ports | ✅ Done |
| 4c | Host services (e.g. a host Ollama reachable from sandboxes) | Planned |
| 4d | The `plus` image and kit | Planned |
| 5 | `template`, `setup ssh`, static MCP, `--skills`, clipboard and browser bridges; the kit capabilities `host-mount@1`, `ssh-agent@1`, `agent-skills@1`/`agent-skill@1` | Planned |
| after 5 | Finish `sbxenv.yaml`: `env plan`, remembered approvals (`env.rememberHostCommands`), `lifecycle`, `bindings`, `registries`, `mcp`, `mounts`, the remaining `sandboxOptions` | Planned |
| 6 | `tui` dashboard (bare `sbt` opens it on a terminal) | Planned |
| 7 | Warm-start pool for near-instant creates; Windows | Planned |

## Known limitations

- Workspaces are mounted read-write unless you use `--clone`.
- Published ports bind `127.0.0.1` only, and directories (not single files) can be mounted. Both are
  smolvm limits; see [sbx compatibility](sbx-compatibility.md).
- Sandboxes can't reach services on the host yet (planned with host services, Phase 4c). Under
  `allow-all`, the host's LAN IP isn't blocked, so services listening on `0.0.0.0` are reachable
  through it.
- Linux uses a 0600 file for secret values where no Secret Service runs.
- Only the agent's primary group takes your gid: group-writable shared directories aren't
  writable through your other groups. Images without `groupmod` (busybox) keep their gid, so on
  Linux the agent can't create files in the workspace unless that gid already matches yours.

## Needs smolvm support (later decisions)

- **OAuth sentinel tokens and enforced method/path rules.** Both need something that reads
  decrypted HTTPS requests; smolvm's proxy only substitutes credentials. Until then, kits get
  passthrough OAuth only, and method/path rules (kits' and `policy allow --method/--path`) aren't
  enforced. Preferred: method/path matching and an OAuth sentinel mode upstream in smolvm. Only if
  that's declined: smolbento's own egress proxy, a phase of its own.
- **Registry credentials for sandboxes.** `secret set --registry --sandbox/--all-sandboxes`, a
  login for a sandbox's own `docker pull`. smolvm reads credential values only at start and
  registry tokens last minutes, so it needs smolvm to mint or refresh the token itself (the builder
  gets one fresh before each build instead).
- **`machine update --label`.** Would let `kit add`ed kits be listed without starting a stopped
  sandbox. Cosmetic.
- **Install-only credentials after install.** sbx leaves the placeholder and sends requests without
  the credential; smolbento's requests get smolvm's `502 credential unavailable`.

## sbx differences to revisit

Measured against sbx v0.49.2; [sbx compatibility](sbx-compatibility.md) has the full list. Worth
another look:

- **Secrets sent to other hosts.** sbx lets a kit send a built-in secret (e.g. GitHub) to another
  host after you approve it once per host; smolbento refuses. An approval flow would close the gap.
- **Kit volume `size`.** sbx gives the volume a block device of that size; smolbento ignores it.
- **Kit signing and publishing.** `kit pack/push/pull/sign/verify/provenance/builder` and the
  settings `kit.requireSignature`, `kit.trustedSigners`, `kit.ignoreTransparencyLog`,
  `kit.allowExtractedAgents`.
- **Sandbox variables.** smolbento leaves out sbx's fake credential values, `MCP_*`, its proxy
  settings, `GIT_CONFIG_*` and the SSH/display variables, and sets `SBX_CRED_*_MODE` only for
  `shell` and `claude` (the only agents measured).
- **Kept on purpose, recheck if sbx changes:** `kit add` applies live (sbx recreates the sandbox and
  refuses some kits), plain HTTP for loopback registries (sbx: HTTPS only), the `_builder` sandbox
  (sbx: host buildx), the built-in `docker` kit, and v3 mixins on built-in agents (sbx refuses).
- **Not measured yet:** unquoted floats in kit args, unused optional args, a v3 mixin's context
  when the workload has an agent file, the kits index after hand edits, a hanging startup step,
  `setsid` in the other `-docker` images, `git-identity` without a host identity, sbx's preamble in
  the agent file, `kit add` of the same kit twice, auto-stop timing, `policy ls --wide` columns, and
  the `kit validate` failure JSON.

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
