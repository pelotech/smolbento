# Development status

Last updated: 2026-11-13.

smolbento is built in phases. Each phase ships on its own.

## Current state

Phases 0 to 4, 5a to 5f, and 6 and 7 are done. Phases 5g, 5h, 8, 9 and 10 are planned. Each feature's
usage guide is linked from its row in the [Phases](#phases) table.

- Sandboxes created before Phase 5b, 5c or 5e need recreating.
- Docker in a sandbox is the shipped `docker` kit. If its first start fails, the sandbox is removed;
  fix the cause and run the same command again.
- Secret `command:` sources (`sbt secret set --command`, and `command:` in an environment file) run in
  a fresh temporary directory. Use absolute paths or put helpers on `PATH`. Relative paths no longer
  work.
- If you're upgrading from v0.1.x, a sandbox start needs a network policy. Run
  `sbt policy init balanced` (or answer the prompt) first. Scripts without a terminal fail until you
  do.

## Phases

| Phase | Scope | Status |
|---|---|---|
| 0 | Spikes: what smolvm and sbx actually do | Done |
| 1 | Repo tooling and CI; `run`, `create`, `exec`, `ls`, `start`, `stop`, `rm`, `prune`, `reset`, `cp`, `version`, `completion`, `diagnose`, `settings`, `daemon`. See [Usage](usage.md) | Done |
| 2 | Network policy (`policy init/allow/deny/rm/ls/log/check`, approvals, live changes), secrets (keychain, `op://` and AWS references, `--command`; the sandbox sees only placeholders), `ports`. See [Security](SECURITY.md) | Done |
| 3a | `--clone`: the agent works on its own clone; only commits come back, through the `sandbox-<name>` remote. See [Usage](usage.md#clone-mode) | Done |
| 3b | `fork`: copy-on-write copies of a running sandbox. `checkpoint`/`restore` dropped: secrets can't work in a restored smolvm checkpoint from the CLI. See [Usage](usage.md#fork) | Done |
| 4a | Kits: v3 capabilities, v2 `spec.yaml`, Smolfiles, `kit inspect/validate/add`, the `docker` kit, the `_builder` sandbox. See [Usage](usage.md#kits) | Done |
| 4b | `sbxenv.yaml` core: `env create/run/exec/rm`, files, args, user defaults, secrets, kits, ports. See [Usage](usage.md#environments-sbxenvyaml) | Done |
| 4c | Host services: `localhost[:PORT]` rules reach the host as `host.docker.internal`, live. Interim: every host port opens until smolvm can open one. See [Usage](usage.md#host-services) | Done (interim) |
| 5a | Host mounts: `host-mount@1` (kept after removal), `--mount`, `sbxenv.yaml` `mounts:`, `inspect`. See [Usage](usage.md#kit-host-mounts) | Done |
| 5b | SSH agent forwarding: `ssh-agent@1` with `sign` limits, the built-in agents' own grant, `ssh.agentForwardingEnabled`, `ssh.agentSocketPath`. See [Usage](usage.md#ssh-agent) | Done |
| 5c | Agent skills: `skills add/import/ls/rm/update` on the store in `~/.local/share/smolbento/agent-skills`, `--skills`, `skills.defaultMode`, `agent-skills@1`, `agent-skill@1`. See [Usage](usage.md#skills) | Done |
| 5d | Templates: `template save/ls/rm/load` (saves a stopped sandbox as a smolvm pack), `run/create -t`. See [Usage](usage.md#templates) | Done |
| 5e | Browser and clipboard bridge while attached (`xdg-open`, `wl-copy`/`xclip`/`xsel`/`pbcopy`, the login callback relay, `browser.enabled`). See [Usage](usage.md#browser-and-clipboard) | Done |
| 5f | Static MCP: `mcp add/ls/inspect/rm`, `run/create --static-mcp`, header secrets as smolvm credentials, Claude Code only. No gateway, OAuth, dynamic mode or live load/unload | Done |
| 5 | The rest, easiest first. 5g: `ssh-agent@1` `authenticate` limits (logins only to named servers, checked against your known hosts). 5h: `setup ssh` (`ssh NAME.sbx`, e.g. from VS Code Remote-SSH) and the `ssh.autoCreate`, `ssh.defaultAgent`, `ssh.defaultTemplate`, `ssh.workspaceRoot` settings | Planned |
| 6a | `env plan`, remembered approvals, `env.rememberHostCommands` | Done |
| 6b | `sbxenv.yaml` `lifecycle`, `registries`, `entrypoint` and `cmd`; registry logins scoped to a sandbox | Done |
| 6c | `sbxenv.yaml` `bindings`, `mcp` url servers, `fuse`, `pullPolicy: never`, `writableEnvFiles`; `gemini` retired | Done |
| 7 | Kit publishing: `kit pack/push/pull/sign/verify` and `push --sign` (v2 kits; cosign signing) | Done |
| 8 | The `plus` kit, built and published with smolbento itself (an end-to-end check of everything before it) | Planned |
| 9 | `tui` dashboard (bare `sbt` opens it on a terminal) | Planned |
| 10 | Warm-start pool for near-instant creates; Windows | Planned |

## Known limitations

- Workspaces are mounted read-write unless you use `--clone`.
- Published ports bind loopback only (`127.0.0.1`, `[::1]`). Only directories, not single files, can be
  mounted. Both are smolvm limits; see [sbx compatibility](sbx-compatibility.md).
- A `localhost` rule opens every port on the host's `127.0.0.1`, including ones it doesn't name.
  Only sandboxes created while a `localhost` rule applied get it; recreate others. Closing it is
  best-effort until recreated. See [Security](SECURITY.md#host-services-localhost-rules). Under
  `allow-all`, services on `0.0.0.0` are reachable through the host's LAN IP.
- Linux stores secret values in a 0600 file where no Secret Service runs.
- The browser and clipboard bridge works only while attached (`run`, `exec -it`). It copies text
  only, and never reads the clipboard or pastes images. Forks have no bridge.
- The SSH agent is served only while `sbt run`, `sbt exec -it` or `sbt exec` runs (no daemon).
  `ssh-agent@1` `authenticate` limits aren't supported yet (5g).
- Templates don't keep `/tmp`.
- Shared skills are linked by a start script running as `agent`. Images without that account get no
  links (a warning). A required bundled kit skill there fails the create.
- smolvm maps only a mounted directory's owner and group to the agent. A subdirectory owned by another
  of your groups keeps that group, so the agent can't write it through the group.

## Needs smolvm support (later decisions)

Changes we'd propose to smolvm. Each item says what smolvm 1.34.4 lacks and what smolbento does
meanwhile.

- **Saving a sandbox made from a template.** Packing fails in smolvm 1.34.1 ("no flattened rootfs was
  found") when the pack's machine was created with `--deny-cidr`, as every sandbox is. `--rebase-from-image`
  drops the first template's files. Meanwhile: saving is refused.
- **Per-port host access.** smolvm opens the host's loopback to a guest only as a whole (gateway CIDR
  `100.96.0.1/32`). Meanwhile: a `localhost:PORT` rule opens every host port (documented).
- **Live allow list with no hosts left.** A `machine update` that leaves CIDRs but no hosts doesn't revoke
  removed hosts until restart. Meanwhile: every allow list keeps the placeholder host `smolbento.invalid`.
- **Registry credentials for sandboxes.** `secret set --registry --sandbox/--all-sandboxes` would give a
  sandbox's own `docker pull` a login. smolvm reads credentials only at start, and registry tokens last
  minutes, so smolvm must mint or refresh the token. Meanwhile: registry logins are host-only, and the
  builder gets a fresh token before each build.
- **MCP header secrets.** They are smolvm credentials, so the server needs an `https://` host without a
  port. An MCP gateway (OAuth servers, host-run servers, dynamic mode, live `mcp load`) also needs one
  host port reachable from a sandbox, and a process that outlives the attached session.
- **Credential hosts with a port.** `--credential` can't bind a host with a port. Meanwhile: the builder
  skips logins for registries on a port (documented).
- **OAuth sentinel tokens and enforced method/path rules.** Both need to read decrypted HTTPS requests;
  smolvm's proxy only substitutes credentials. Meanwhile: kits get passthrough OAuth only, and method/path
  rules (kits' and `policy allow --method/--path`) aren't enforced. Preferred: method/path matching and
  an OAuth sentinel mode upstream in smolvm. If declined: smolbento's own egress proxy, as its own phase.
- **`machine update --label`.** Labels are create-time only. Meanwhile: kits added with `kit add` aren't
  listed on a stopped sandbox until it starts. Cosmetic.
- **Guest DNS upstream order.** Since smolvm 1.34, guest DNS moves to the host's next resolver when one
  doesn't answer. Not yet checked: a name the first resolver refuses (before 1.34 that failed in every VM,
  even when the host resolved it). Meanwhile: no workaround; the e2e tests avoid such names.
- **Copying a directory out of a sandbox.** `machine cp` uploads directories but downloads single files
  only. Meanwhile: `sbt cp SANDBOX:/dir ./dir` fails with smolvm's "is a directory".
- **Install-only credentials after install.** smolvm answers `502 credential unavailable` when a binding
  has no value; sbx sends the request without the credential. Meanwhile: a documented difference.

## sbx differences to revisit

Measured against sbx v0.49.2, and v0.50.1 for kit host mounts, `--mount` and `inspect`. The full list is
in [sbx compatibility](sbx-compatibility.md). Worth another look:

- **Secrets sent to other hosts.** sbx lets a kit send a built-in secret (e.g. GitHub) to another host
  after you approve it once per host. smolbento refuses. An approval flow would close the gap.
- **Kit host mounts.** A published kit's directory is keyed on its repository (sbx's key isn't measured).
  `reset` keeps the directories (sbx deletes them). `inspect` omits sbx's CPU, memory, uptime, digest,
  auth, policy, proxy, MCP and daemon rows.
- **Kit volume `size`.** sbx gives the volume a block device of that size. smolbento ignores it.
- **Kit signing and publishing.** Local-directory signing (`kit.sig.bundle`; sbx's directory digest isn't
  decoded, so local kits are refused under `kit.requireSignature`), keyless signing without Rekor,
  `kit provenance/builder`, push provenance, and `kit.allowExtractedAgents`.
- **Sandbox variables.** smolbento omits sbx's fake credential values, `MCP_*`, proxy settings,
  `GIT_CONFIG_*` and the SSH/display variables. It sets `SBX_CRED_*_MODE` only for `shell` and `claude`,
  the only agents measured.
- **Kept on purpose; recheck if sbx changes:** `kit add` applies live (sbx recreates the sandbox and
  refuses some kits); plain HTTP for loopback registries (sbx: HTTPS only); the `_builder` sandbox (sbx:
  host buildx); the built-in `docker` kit; v3 mixins on built-in agents (sbx refuses).
- **Not measured yet:** unquoted floats in kit args, unused optional args, a v3 mixin's context when the
  workload has an agent file, the kits index after hand edits, a hanging startup step, `setsid` in the
  other `-docker` images, `git-identity` without a host identity, sbx's preamble in the agent file,
  `kit add` of the same kit twice, auto-stop timing, `policy ls --wide` columns, and the `kit validate`
  failure JSON.

## Waiting on a release or CI

Proven on GitHub: e2e on `ubuntu-latest`, and the v0.1.1 release (all three binaries; macOS binary
verified on a Mac).

## Cleanups to do

Small issues found in review and deferred. None affect normal use.

- More tests for: `cp -L`, `exec --privileged -u`, session cleanup on `rm`/`prune`/`reset`,
  `ProcessRunner` itself.
