# Development status

Last updated: 2026-11-25.

smolbento is built in phases. Each phase ships on its own.

## Current state

Phases 0 to 4, 5a to 5h, 6 to 8, and hosted egress are done. Phases 9 and 10 are planned. Each feature's
usage guide is linked from its row in the [Phases](#phases) table.

Before 1.0, recreate sandboxes after upgrading smolbento ([Install](install.md#upgrading)).

## Phases

| Phase | Scope | Status |
|---|---|---|
| 0 | Spikes: what smolvm and sbx actually do | Done |
| 1 | Repo tooling and CI; the core sandbox commands. See [Usage](usage.md) | Done |
| 2 | Network policy, secrets (the sandbox sees only placeholders) and `ports`. See [Security](SECURITY.md) | Done |
| 3a | `--clone`: the agent works on its own clone. See [Usage](usage.md#clone-mode) | Done |
| 3b | `fork`: copy-on-write copies of a running sandbox. See [Usage](usage.md#fork) | Done |
| 4a | Kits: v3 capabilities, v2 `spec.yaml`, Smolfiles, the `docker` kit. See [Usage](kits.md#kits) | Done |
| 4b | `sbxenv.yaml` core: the `env` commands. See [Usage](environments.md#environments-sbxenvyaml) | Done |
| 4c | `localhost[:PORT]` rules reach the host. Interim: every host port opens until smolvm can open one. See [Usage](network-and-secrets.md#host-services) | Done (interim) |
| 5a | Host mounts: `host-mount@1`, `--mount`. See [Usage](kits.md#kit-host-mounts) | Done |
| 5b | SSH agent forwarding: `ssh-agent@1` with `sign` limits. See [Usage](usage.md#ssh-agent) | Done |
| 5c | Agent skills: the `skills` commands and `--skills`. See [Usage](kits.md#skills) | Done |
| 5d | Templates: save a stopped sandbox as a smolvm pack. See [Usage](kits.md#templates) | Done |
| 5e | Browser and clipboard bridge, with the login callback relay. See [Usage](usage.md#browser-and-clipboard) | Done |
| 5f | Static MCP (Claude Code only). No gateway, OAuth, dynamic mode or live load/unload. See [Usage](kits.md#mcp-servers) | Done |
| 5g | `ssh-agent@1` `authenticate` limits. See [Usage](usage.md#ssh-agent) | Done |
| 5h | `setup ssh` and `ssh NAME.sbx`. See [Usage](usage.md#ssh-into-a-sandbox). Not done: `--auto-create` and the `ssh.autoCreate`, `ssh.defaultAgent`, `ssh.defaultTemplate`, `ssh.workspaceRoot` settings (sbx doesn't document them) | Done |
| 6a | `env plan` and remembered approvals | Done |
| 6b | `sbxenv.yaml` `lifecycle`, `registries`, `entrypoint` and `cmd` | Done |
| 6c | `sbxenv.yaml` `bindings`, `mcp` url servers, `fuse`, `pullPolicy: never`, `writableEnvFiles` | Done |
| 7 | Kit publishing and cosign signing (v2 kits) | Done |
| 8 | The `nix` kit for any agent. See [Usage](kits.md#the-nix-kit) | Done |
| Egress | Hosted egress, the default `network.egress`: a per-sandbox process enforces network and request rules and swaps secrets. See [Usage](network-and-secrets.md#hosted-egress) | Done |
| 9 | `tui` dashboard (bare `bento` opens it on a terminal) | Planned |
| 10 | Warm-start pool for near-instant creates; Windows | Planned |

## Known limitations

- Workspaces are mounted read-write unless you use `--clone`.
- Where smolvm sets the limit, the difference is in [sbx compatibility](sbx-compatibility.md):
  loopback-only published ports, directory-only mounts, a `localhost` rule that opens every host
  port, templates without `/tmp`.
- The browser and clipboard bridge and the SSH agent are served by launchd or `systemd --user`
  units. Without a service manager they are served only while `bento` runs for the sandbox.
  `diagnose` reports leftover units ([Usage](usage.md#host-services)).
- Shared skills are linked at every start by a script running as root, and the links are owned by
  `agent` (uid 1000 in images without that account). A required bundled kit skill that can't be
  linked fails the create.
- smolvm maps only a mounted directory's owner and group to the agent. A subdirectory owned by another
  of your groups keeps that group, so the agent can't write it through the group.

## Needs smolvm support (later decisions)

Changes we'd propose to smolvm. Each item says what the pinned smolvm lacks and what smolbento does
meanwhile.

- **Per-port host access.** smolvm opens the host's loopback to a guest only as a whole (gateway CIDR
  `100.96.0.1/32`), so a `localhost:PORT` rule opens every host port.
- **`smolvm machine connect NAME PORT`** (stdin and stdout to a guest port). `ssh -L` forwards run
  `nc`, else bash's `/dev/tcp`, in the sandbox, so they need one of them. Meanwhile: that. Proposal
  to file upstream first, then a small PR.
- **Saving a sandbox made from a template.** Packing a machine created from a pack fails ("no flattened
  rootfs was found"), with or without `--deny-cidr`. `--rebase-from-image` drops the first template's files. Meanwhile: saving is refused.
- **Registry credentials for sandboxes.** `secret set --registry --sandbox/--all-sandboxes` would give a
  sandbox's own `docker pull` a login. smolvm reads credentials only at start, and registry tokens last
  minutes, so smolvm must mint or refresh the token. Meanwhile: registry logins are host-only, and the
  builder gets a fresh token before each build.
- **MCP gateway.** Needs one host port reachable from a sandbox and a process that outlives the
  attached session (see [sbx compatibility](sbx-compatibility.md#mcp-servers)).
- **Credential hosts with a port.** `--credential` can't bind a host with a port. Meanwhile: the builder
  skips logins for registries on a port (documented).
- **OAuth sentinel tokens.** They need to read decrypted HTTPS requests; smolvm's proxy only
  substitutes credentials. Meanwhile, sentinel OAuth binds only its API key (logins happen in the
  sandbox). Preferred: an OAuth sentinel mode upstream in smolvm.
- **Request rules: the rest.** Hosted sandboxes enforce method, path and query rules
  ([Request rules](network-and-secrets.md#request-rules)). Still to do: closing the bypasses there (a
  spoofed or missing name on a ruled host's address), plain HTTP filtered per request rather than
  refused, and request rules under `network.egress=smolvm`.
- **Guest DNS upstream order.** Not yet checked: a name the first resolver refuses while a later one
  answers. No workaround; the e2e tests avoid such names.

## sbx differences to revisit

The full list is in [sbx compatibility](sbx-compatibility.md). Worth another look:

- **Secrets sent to other hosts.** sbx lets a kit send a built-in secret (e.g. GitHub) to another host
  after you approve it once per host. smolbento refuses. An approval flow would close the gap.
- **Kit provenance.** `kit provenance`, `kit builder` and push provenance aren't implemented.
- **From sbx 0.51–0.53, for later:**
  - `kit add` installs a kit's image layers into a running v3 sandbox; smolbento says `recreate
    required` (smolvm can't add layers to a running machine).
  - `sbx df` (disk usage of images, sandboxes and volumes).
- **Kept on purpose; recheck if sbx changes:** `kit add` applies live (sbx recreates the sandbox and
  refuses some kits); plain HTTP for loopback registries (sbx: HTTPS only); the `_builder` sandbox (sbx:
  host buildx); the built-in `docker` kit; v3 mixins on built-in agents (sbx refuses).

## Cleanups to do

Small issues found in review and deferred. None affect normal use.

- russh from git (commit b541663a8838) until a release pins ssh-key 0.7.0-rc.12 or later: then switch
  to crates.io, drop the `deny.toml` allow-git entry and the flake `outputHashes`.
- More tests for: `cp -L`, `exec --privileged -u`, session cleanup on `rm`/`prune`/`reset`,
  `ProcessRunner` itself.
