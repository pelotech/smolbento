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

**Phase 4c (host services) is done, as an interim.** `sbt policy allow network localhost[:PORT]`
lets sandboxes created under that rule reach your machine's localhost as `host.docker.internal`,
opened and closed live. Until smolvm can open a single host port, the rule opens every port on
your machine's `127.0.0.1` to them. See [Usage](usage.md#host-services) and
[Security](SECURITY.md#host-services-localhost-rules).

**Phase 5a (host mounts) is done.** Kits can declare `host-mount@1`: a directory on your machine
shared by the kit's sandboxes and kept after they're removed. `--mount` and `sbxenv.yaml`
`mounts:` choose your own directory, and the new `sbt inspect` shows where each one is. See
[Usage](usage.md#kit-host-mounts).

**Phase 5e (browser and clipboard) is done.** While you're attached, the sandbox can open
`https://` URLs in your browser, copy text to your clipboard, and finish browser logins that
redirect to `localhost`. Sandboxes created before it need recreating. See
[Usage](usage.md#browser-and-clipboard).

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
| 4c | Host services: `localhost[:PORT]` rules reach the host as `host.docker.internal`, live (interim: every host port, until smolvm can open one) | ✅ Done (interim) |
| 5a | Host mounts: `host-mount@1`, `--mount`, `sbxenv.yaml` `mounts:`, `inspect` | ✅ Done |
| 5e | Browser and clipboard bridge while attached (`xdg-open`, `wl-copy`/`xclip`/`xsel`/`pbcopy`, the login callback relay, `browser.enabled`) | ✅ Done |
| 5 | The other parts, easiest first: 5b SSH (`ssh-agent@1`, `setup ssh`); 5c skills (`--skills`, `skills`, `agent-skills@1`/`agent-skill@1`); 5d `template`; 5f MCP (`--static-mcp`, `mcp`) | Planned |
| 6 | Finish `sbxenv.yaml`: `env plan`, remembered approvals (`env.rememberHostCommands`), `lifecycle`, `bindings`, `registries`, `mcp`, the remaining `sandboxOptions` | Planned |
| 7 | Kit publishing: `kit pack/push/pull/sign/verify` | Planned |
| 8 | The `plus` kit, built and published with smolbento itself (an end-to-end check of everything before it) | Planned |
| 9 | `tui` dashboard (bare `sbt` opens it on a terminal) | Planned |
| 10 | Warm-start pool for near-instant creates; Windows | Planned |

## Known limitations

- Workspaces are mounted read-write unless you use `--clone`.
- Published ports bind `127.0.0.1` only, and directories (not single files) can be mounted. Both are
  smolvm limits; see [sbx compatibility](sbx-compatibility.md).
- A `localhost` rule opens every port on the host's `127.0.0.1`, not just the one it names, and
  only to sandboxes created while one of your `localhost` rules applied; others need recreating.
  Closing it in such a sandbox is best-effort until it's recreated. See
  [Security](SECURITY.md#host-services-localhost-rules). Under `allow-all`, the host's LAN IP isn't
  blocked, so services listening on `0.0.0.0` are reachable through it.
- Linux uses a 0600 file for secret values where no Secret Service runs.
- The browser and clipboard bridge works only while you're attached (`run`, `exec -it`), copies
  text only, and doesn't read your clipboard or paste images. Forks have no bridge.
- Only the agent's primary group takes your gid: group-writable shared directories aren't
  writable through your other groups. Images without `groupmod` (busybox) keep their gid, so on
  Linux the agent can't create files in the workspace unless that gid already matches yours.

## Needs smolvm support (later decisions)

Changes we'd propose to smolvm (none filed yet). What smolvm 1.32.4 lacks, and what smolbento does
meanwhile:

- **Per-port host access.** smolvm can open the host's loopback to a guest only as a whole (the
  gateway CIDR `100.96.0.1/32`). Meanwhile a `localhost:PORT` rule opens every host port to
  sandboxes created with host access (documented).
- **Live allow list with no hosts left.** A `machine update` that leaves CIDRs but no hosts
  doesn't revoke the removed hosts until restart. Meanwhile every allow list keeps the
  placeholder host `smolbento.invalid`.
- **Registry credentials for sandboxes.** `secret set --registry --sandbox/--all-sandboxes`, a
  login for a sandbox's own `docker pull`. smolvm reads credential values only at start and
  registry tokens last minutes, so it needs smolvm to mint or refresh the token itself. Meanwhile
  registry logins are host-only and the builder gets a fresh token before each build.
- **Credential hosts with a port.** `--credential` can't bind a host with a port. Meanwhile the
  builder skips logins for registries on a port (documented).
- **OAuth sentinel tokens and enforced method/path rules.** Both need something that reads
  decrypted HTTPS requests; smolvm's proxy only substitutes credentials. Meanwhile kits get
  passthrough OAuth only, and method/path rules (kits' and `policy allow --method/--path`) aren't
  enforced. Preferred: method/path matching and an OAuth sentinel mode upstream in smolvm. Only if
  that's declined: smolbento's own egress proxy, a phase of its own.
- **`machine update --label`.** Labels are create-time only. Meanwhile kits added with `kit add`
  aren't listed on a stopped sandbox without starting it. Cosmetic.
- **Guest DNS upstream order.** Guest DNS forwards to the host's first IPv4 resolver only, so a
  name that resolver refuses fails in every VM even when the host resolves it. Meanwhile nothing
  (the e2e tests avoid such names).
- **Install-only credentials after install.** smolvm answers `502 credential unavailable` when a
  binding has no value; sbx sends the request without the credential. Meanwhile a documented
  difference.

## sbx differences to revisit

Measured against sbx v0.49.2, and v0.50.1 for kit host mounts, `--mount` and `inspect`;
[sbx compatibility](sbx-compatibility.md) has the full list. Worth
another look:

- **Secrets sent to other hosts.** sbx lets a kit send a built-in secret (e.g. GitHub) to another
  host after you approve it once per host; smolbento refuses. An approval flow would close the gap.
- **Kit host mounts.** A published kit's directory is keyed on its repository (sbx's key isn't
  measured), `reset` keeps the directories (sbx deletes them), and `inspect` leaves out sbx's
  CPU, memory, uptime, digest, auth, policy, proxy, MCP and daemon rows.
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
