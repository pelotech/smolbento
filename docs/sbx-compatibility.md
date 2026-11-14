# sbx compatibility

smolbento takes Docker Sandboxes (sbx) command lines flag for flag. The reference is sbx v0.49;
kit host mounts, `--mount` and `inspect` are checked against v0.50.1.

Anything not implemented yet still parses and exits with status **2** and prints a message, so
scripts fail clearly instead of doing something different.

## Works today

`run`, `create`, `exec`, `ls`, `inspect`, `start`, `stop`, `rm`, `prune`, `reset`, `cp`, `version`,
`completion`, `diagnose`, `settings`, `policy`, `secret`, `ports`, `env create|run|exec|rm` (see
[Environment files](#environment-files)), `run/create --deny-network`, `run/create --clone`, kits
(`--kit`, `--kit-arg`, `--kit-args-file`, `--mount`, `kit inspect|validate|add`; see [Kits](#kits)),
`mcp add|ls|inspect|rm` and `--static-mcp` (see [MCP servers](#mcp-servers)), and
`policy ls --source`.

smolbento-only:

- `fork`. sbx has none; its `template save` saves only the disk.
- `daemon`. Accepted and does nothing.

## Parses, not implemented yet (exit 2)

| Command or flag | Status |
|---|---|
| `policy refresh`, `secret import`, `secret set --oauth/--refresh`, `secret set/rm --registry` with `--sandbox`/`--all-sandboxes` | Not implemented |
| `policy ls --created-via/--type/--protocol/--include-inactive`, `policy check --protocol` other than `tcp` | Not implemented (`--decision` and `--source` work) |
| `sbxenv.yaml` fields under [Environment files](#environment-files) | Later |
| `setup ssh` | Later (Phase 5h) |
| `mcp auth`, `mcp load`, `mcp unload`; `mcp add --local`, `--dir`, `--client-id`, `--oauth-authorization-server`, `--resource`, `--skip-auth` | Not supported: no MCP gateway |
| `tui` | Later |
| `--pull always`; `--pull never` without a saved template ([Templates](#templates)) | Not implemented. `--pull missing` works, as in smolvm |
| `exec -d`, `--detach-keys` | Not supported (sbx doesn't support `exec -d` either) |

## Never (Docker Cloud only, exit 2)

`login`, `logout`, `move`, `ttl`, `attach`, `volume`, the global `--cloud` flag, and the cloud-only
`run`/`create` flags (`--allow-network`, `--image-ref`, `--platform`, `--ttl`, `--on-timeout`,
`-v/--volume`, `--new`).

## Differences you'll notice

| Area | sbx | smolbento |
|---|---|---|
| Network | Default-deny policy | Same modes and rule syntax, but looser: `*.x.com` matches any depth (sbx: one label), and wildcards inside a label (`crl*.x.com`, `?`, `[..]`) widen to `*.x.com`. Ports, methods and paths aren't enforced (`policy ls --wide` shows which). `balanced` is sbx's 195 rules plus Nix caches, on any port |
| Host deny rules | Always enforced | Not enforced under allow-all, nor where a broader allow covers the host. Only deny CIDRs are enforced (at create). A deny with a port isn't enforced, because smolvm can't filter by port. The exception: a deny with the same text as an allow cancels that allow. `policy check` and `policy deny` say so |
| Secrets | Proxy injects on the wire | smolvm substitutes on the wire. A secret's hosts and their subdomains are always reachable from sandboxes that bound it (`policy deny` of one is refused). New values apply on the next start |
| `secret set-custom --host` | Exact host, IP or wildcard pattern | Exact host, or `*.domain` for any depth (not the apex). Other wildcards and IPs are refused: smolvm substitutes secrets only for host names |
| Policy changes | Live everywhere | Live, except: switching a running sandbox between allow-all and a restricted mode applies on its next start, and deny-CIDR rules apply only to sandboxes created afterwards |
| Approvals | Queue | Derived from smolvm's blocked-request (egress) log; the host is the approval id |
| Host services | Per-port `host.docker.internal` when the policy allows `localhost:PORT`, live; a blocked request gets `403 Approval required…` | Live `host.docker.internal`, but a `localhost` rule opens **every** port on the host's `127.0.0.1` (smolvm can't open one port), not `::1`. Only sandboxes created while a `localhost` rule applied get it; others need recreating. Kit rules never grant it, and `_builder` never has it. A blocked request gets connection refused, with no approval entry. Under allow-all the host's LAN IP is reachable, so services on `0.0.0.0` are too (sbx blocks this). See [Security](SECURITY.md#host-services-localhost-rules) |
| Published ports | Any host IP | Loopback only: `127.0.0.1` and `[::1]` |
| Single-file `:ro` mounts | Supported | Directories only (smolvm mounts directories) |
| Machine names | `.` allowed | No `--`, no trailing `-` (smolvm rules) |
| Daemon | `sandboxd` | None; each command talks to smolvm directly |
| Clone transport | Git daemon in the sandbox on a published port; the remote URL changes on every start, and fetch fails while stopped | No daemon or port. The `sandbox-<name>` remote's `uploadpack` runs `smolbento _upload-pack <name>` (so `smolbento` must be on `PATH`) through `smolvm machine exec`. `git remote -v` shows a placeholder `file:///sbt/<name>` |
| Tags from the sandbox | Remote follows tags | `tagOpt = --no-tags`; only branches come back |
| Fetch on exit | None | `sbt run` fetches `sandbox-<name>` when the agent exits (`clone.fetch-on-exit`, default `true`), with `fetch.fsckObjects=true`. Manual `git fetch` is unchanged |
| Fetch from a stopped sandbox | Fails | Starts it, fetches, stops it again |
| Linked worktrees as clone source | Not supported | Supported: the branch, or the commit when detached |
| `policy ls --wide` | sbx's wide layout | Adds a NAME column; sbx's other wide columns aren't shown |
| Install-phase kit rules in `policy ls` | Not listed after create | Never listed, even while a create installs (they're in effect then) |
| `inspect` | Also CPUs, memory, uptime, image digest, auth mode, network, mount and proxy policy, runtime mounts, MCP gateway, daemon | Those are left out. The rest matches sbx's layout and JSON keys |
| `reset` | Deletes all state, kit host-mount directories included | Removes sandboxes, session state and the shared skills store. Kit host-mount directories stay: delete them yourself |
| Progress output | A line per image layer | No per-layer lines. The pull shows a percentage, and the image step reads `preparing` until smolvm reports a pull (a cached image has none). CPU and Memory print before a kit's `resources@1`. A kit's "cached" label is approximate when pulls or builds overlap. On a terminal, a step's detail stays on the step's line, and a warning follows the step's last drawn line |
| Browser and clipboard | Shims post to the daemon's proxy with `curl` and `jq`; copies work from any `exec`; image paste behind `clipboard.imagePaste`; `SBX_HOST_SESSION_ID` routes requests | Same shims and texts over a socket smolvm mounts at `/run/smolbento/bridge.sock`, with `curl` only. Served by a launchd or `systemd --user` unit whenever the sandbox runs; without a usable service manager, only while attached (`run`, `exec -it`), and then URLs print the fallback and copies fail otherwise. No image paste. sbx doesn't read clipboard text either. No `SBX_HOST_SESSION_ID`: with units each connection is served alone; attached-only serving: the first attached session. Sandboxes created before the bridge need recreating. Forks keep the parent's socket, so they use its bridge while it is served. Login relay: `curl -g --noproxy '*'` with 10-second timeouts (`wget` for a `GET`); no request body (`form_post` callbacks lose theirs); text responses only; at most 4 ports per session (with units, per connection), each for 10 minutes. See [Usage](usage.md#browser-and-clipboard) |
| Command aliases | `ls`, `rm`/`delete`, `secret ls`/`rm`/`delete`/`unset`, `settings ls`, `template ls`/`list`, `template rm`/`remove`/`delete` | Implemented. `volume` aliases come with that command |
| `--version` | `sbx version vX` | `sbt --version` prints `sbt X`; `sbt version` also shows the smolvm version |

## Skills

`skills add|import|ls|rm|update` and `--skills` follow sbx v0.50.1's output and flags, and
`sandboxOptions.skills` works too.

| Area | sbx | smolbento |
|---|---|---|
| Store path | macOS: `~/Library/Application Support/com.docker.sandboxes/sandboxes/agent-skills`. Linux: under `$XDG_STATE_HOME` | `~/.local/share/smolbento/agent-skills` (`$XDG_DATA_HOME` and `$SMOLBENTO_DATA_DIR` respected). A separate store: run `sbt skills import` to bring skills over |
| `add` | Clones the repository itself | Runs your host `git` (shallow, no prompts), so credential helpers and the SSH agent apply |
| `update` | Per-skill messages; `No repository-installed skills found` | A failing repository prints an error and the others still update. Exit code 1 (not measured in sbx) |
| Path that is both the agent's and a kit's directory | Can't happen: a v3 mixin can't join a built-in agent | Allowed; the path behaves like the agent's own directory |
| Who links | Root; links to uid 1000. Fails the create when uid 1000 can't reach the directory | Root; links to the image's `agent` account, else uid 1000. No reachability check. A skills path that goes through a symlink gets no links (the start warns; a required bundled skill fails) |
| Kits | `agent-skills@1`, `agent-skill@1` | Both, as measured. A kit directory gets the store mounted over it unless the sandbox has bundled skills; then every directory links, read-write if any directory is. `kit add` refuses kits with either |
| Other agents' directories | sbx's docs table | The same table, from the docs. Not measured for copilot, cursor, droid, opencode or devin |

## MCP servers

sbx runs an MCP gateway on the host per sandbox. The agent sees one endpoint. sbx connects it to
the registered servers, holding their OAuth tokens and running local ones on the host.

smolbento has no gateway. `mcp add|ls|inspect|rm` and `--static-mcp` take sbx's flags, and the
servers are written into the agent's own MCP config at create.

| | sbx | smolbento |
|---|---|---|
| `--command` server runs | On the host | Inside the sandbox; the command must exist in the image |
| Header secrets (`${name}`, `sbx secret set mcp:<server>:<name>`) | Added by the gateway | Same syntax. The config holds smolvm's placeholder, replaced on HTTPS requests to the server's host. Needs an `https://` host without a port; one secret header per server |
| OAuth servers | Authorized by `sbx` on the host | Not supported |
| Without `--static-mcp` | Dynamic mode: the agent can find and attach registered servers | No MCP servers |
| `mcp load` / `mcp unload` | Work on a running sandbox | Not supported; the set is fixed at create |
| Agents | Any whose kit registers the gateway | `claude` only so far |
| `localhost` server URLs | Reach the host through the gateway | Refused at `mcp add` |
| `mcp ls` / `mcp inspect` output | `GATEWAY` column and each server's state | `NAME`, `TYPE`, `TARGET`; JSON and YAML have `name`, `type`, `url`/`command`, `headers`, `args`, `secrets`. sbx's reference has no sample to match |
| `MCP_GATEWAY_URL`, `MCP_SENTINEL_TOKEN_NAME` | Set in the sandbox | Not set |

## Templates

`template save|ls|rm|load` and `run/create -t` follow sbx's flags.

| Area | sbx | smolbento |
|---|---|---|
| `save --output` and `load` | A `docker save` tar | A smolbento archive; the two don't read each other's files |
| `ls` | Docker images and saved templates | Saved templates only. FLAVOR is the agent |
| Agent mismatch | Fails in the kit step (`failed to apply kit to sandbox`) | Refused up front |
| `/tmp` | Kept | Not kept |
| Saving a sandbox made from a template | Not measured; sbx adds a layer per save | Refused (smolvm limit; see [Development status](development-status.md#needs-smolvm-support-later-decisions)) |
| Saving a kit workload sandbox | Not measured | Refused: a template of one can't be used with `-t` yet |
| `-t` with `--kit` | Not measured | Refused when a kit adds image layers (a template's disk is saved whole) |
| `save` of a running sandbox, no terminal | Suggests a nonexistent `--force` | Says to `sbt stop` it first |
| `inspect` | Needs `--cloud`; local templates are Docker images | Not supported |
| `--pull never` | Default for saved local snapshots; an uncached image fails (`not cached locally and pull_policy=never`) | Accepted only with a saved template; exit 2 otherwise |

## Environment files

`env plan|create|run|exec|rm` read `sbxenv.yaml` as sbx does, for the fields smolbento supports.
Measured on sbx v0.49.2 (v0.50.1 for `mounts`; v0.53.0 for the plan, approvals, `lifecycle`,
`registries`, `entrypoint`, `cmd`, `bindings` and `mcp`). Everything not listed below matches.

Unsupported fields exit 2 and name the field. They are `sandboxOptions.profile|display|gpu|usb`
and `pullPolicy: always`.

| Area | sbx | smolbento |
|---|---|---|
| Approval | Remembered per environment until the plan changes | Kept in smolbento's own file; sbx's records aren't read |
| Lifecycle timeouts | Go durations (`90s`, `1m30s`). A background child that holds output five seconds after exit fails the command | Ctrl-C ends the running command and what it started (sbx not measured) |
| Lifecycle in the plan of an existing sandbox | Lists unchanged `postCreate`/`preRemove` as `○ … — unchanged` | Unchanged commands aren't listed. A changed one shows `command: old -> new` and its changed fields |
| Removal plan after `preRemove` | Regenerated; removal stops if the commands changed it (documented, not measured) | Not regenerated |
| `registries` | Stored for the sandbox | Resolved once at create and stored as a value; used ahead of a host-wide login for that sandbox's pulls. sbx's stored form wasn't examined |
| `PROVISION` output | Ends with `✓ environment — provisioned` | Line not printed |
| Plan against the last apply | Lists applied items: `! NAME — unchanged, needs your approval`, `recorded as applied, no longer present, waits for the next create`, `○ NAME — unchanged` | Compares with what was approved and asks smolvm whether the sandbox exists. A change shows as `~` (outside `ENV`: `— waits for the next create`) until approved. Unchanged resources aren't listed |
| `--clone` in the plan | A `GIT REMOTE` section | `clone: true` on the workspace |
| Ports | `tcp4`, or `tcp6` for an IPv6 `hostIP` | smolvm publishes on both `127.0.0.1` and `::1`, so `tcp4`/`tcp6`/`udp4`/`udp6` all publish on both. Any other `hostIP` is refused |
| Environment files in the sandbox | Mounted at their host path, read-only unless `writableEnvFiles` | Files in a writable mounted workspace are made read-only in the guest at each start (unless `writableEnvFiles`); root in the guest can undo it. Files outside the workspaces aren't mounted (smolvm mounts directories only). No plan line for a writable one |
| `sandboxOptions.fuse: false` | `/dev/fuse` absent, no `SYS_ADMIN` | `/dev/fuse` removed at each start |
| `bindings` | Merged into the global `credentials.yaml`; `--prune-bindings` removes the service's entry; an unknown service is accepted by `env plan` | Stored in smolbento's secrets file; `--prune-bindings` works the same. An unknown service is refused at create, with the `sbt secret set` error |
| `mcp` url servers | Registered for the host, after an OAuth discovery that fails the create if the server is unreachable | Registered in `mcp.toml` and written into the agent's config (`claude` only). Create fails before anything is made when nothing answers at the URL (any HTTP answer counts; no OAuth discovery) |
| `mcp` command servers | Run on the host, approved like lifecycle commands | Refused (exit 2) |
| Plan after a plain `rm` | Lines end `— recorded as applied, no longer present` | A bare `+` |
| A local kit's contents | Not measured | Not part of the approval; the plan names the kit's path |
| `refresh`, `backend` on a secret | Used | Accepted, no effect: smolbento resolves at every start |
| `secret ls` with registry credentials | `SECRET` shows the first characters | A separate `SCOPE TYPE NAME SECRET` table; `SECRET` is always `(stored)`. No `--json` on `secret ls` yet |
| Workload kit as `agent` | The kit whose name equals `agent` | A local kit matches by directory name; a registry kit by the last part of its repository name |
| Secret `command:` source | Runs on the host | Runs from a fresh temporary directory, so a relative helper path fails (also for `secret set --command`) |
| `mounts:` path no kit declares | Error includes `remove this environment's sandbox and provisioned secrets` and `try: sbx env rm`; checked after the kit image is prepared | First sentence only (secrets are stored by then, and `env rm` removes them); checked before a registry kit's image is prepared |
| Kits that can't be loaded | Checked before secrets are stored | A missing local path, a `.zip` or a `git+` source is refused before secrets are stored. An unpullable registry kit fails after they're stored; `env rm` removes them |

## Sandbox environment

Every sandbox gets the variables below, the same set sbx sets. They are passed with `-e` at create
so every process sees them. Your own `-e` wins. None holds a secret value.

- `SANDBOX_NAME`, `SANDBOX_VM_ID` (the name), `SANDBOX_ID` (a new UUID per create). A `fork`
  gets its own name and id.
- `WORKSPACE_DIR`: the host path of the primary workspace (the guest workdir when mountless).
- `SBX_AGENT`: the preset or kit name. `IS_SANDBOX=1` for the `claude` preset.
- `SBX_CRED_<SVC>_MODE`: `apikey` when the service's secret is bound at create, else `none`. `shell`
  gets all eight services and `claude` only `ANTHROPIC`. Other presets and kits get none, even one
  named `claude` or `shell`.
- `TZ`: from the host, in TTY sessions (`run`, `exec -it`), when set. sbx derives one when unset.
- `TERM_PROGRAM`, `TERM_PROGRAM_VERSION`, `COLORTERM`: from the host in TTY sessions, so agents know
  your terminal shows clickable links.
- `BROWSER=xdg-open` in `run` and `exec` of a sandbox with the browser bridge. A Linux agent without
  a display would otherwise only print the URL. sbx sets `WAYLAND_DISPLAY` instead.

Left out: `*_API_KEY=proxy-managed` and the `GH_TOKEN` sentinel (smolvm uses its own placeholders);
`MCP_*`; `GIT_CONFIG_*`; the proxy variables (`PROXY_CA_CERT_B64`, `JAVA_TOOL_OPTIONS`,
`NODE_USE_ENV_PROXY`); `CLAUDE_ENV_FILE`; `SSH_AUTH_SOCK_GATEWAY` (`SSH_AUTH_SOCK` is set with an
[SSH agent](#ssh-agent) grant); `WAYLAND_DISPLAY`; `XDG_RUNTIME_DIR`; the PAM-style startup-hook
environment; and `LC_ALL=C` for startup hooks. Kits that rely on these see them unset.

## SSH agent

Built-in agent sandboxes get your SSH agent at runtime when you have one, as sbx does. Kits ask
with `ssh-agent@1`. `SSH_AUTH_SOCK` is `/run/ssh-agent.sock`. Only listing keys and signing reach
your agent (`ssh-add -D` fails with `Failed to remove all identities.`). The settings are sbx's:
`ssh.agentForwardingEnabled` and `ssh.agentSocketPath`.

| Area | sbx | smolbento |
|---|---|---|
| Serving | The daemon, whenever the sandbox runs | A launchd or `systemd --user` unit owns the socket and runs `sbt _serve agent` per connection, whenever the sandbox runs (no smolbento daemon). The create's install steps serve an `install` grant themselves. Without a usable service manager, and for sandboxes made before units, only while `sbt` runs for the sandbox (`run`, `exec -it`, plain `exec`), and agent connections fail at other times |
| Sessions | Every session reaches the agent | Every connection is served alone. Attached-only serving: the first session serves it and a concurrent second uses it |
| Which agent | The sbx client's `SSH_AUTH_SOCK` | `ssh.agentSocketPath`, else the user session's `SSH_AUTH_SOCK` (launchd supplies macOS's; on Linux, that of the last `sbt` that wrote the unit). Attached-only serving: the serving `sbt`'s |
| `SSH_AUTH_SOCK_GATEWAY` | `gateway.docker.internal:3129` | Not set (no TCP gateway) |
| `authenticate` limits | Logins only to the named servers | Supported. Host keys come from `ssh.knownHostsFile` (smolbento-only setting, default `~/.ssh/known_hosts`), read at each login. A server known only through `@cert-authority`, or by a wildcard or negated pattern, is refused, as is a `[host]:port` entry; hashed names work |
| `setup ssh` | `ssh NAME.sbx` into sandboxes | Not yet (Phase 5h) |
| Forks | No forks | No agent or units of its own, but it keeps the parent's socket mount, so it can use the agent (with the parent's grant) while the parent is served |
| `kit add` of an `ssh-agent@1` kit | Recreates the container | `recreate required: … SSH agent` |
| Sandboxes from before | n/a | Created before smolbento had the agent, so they have none. Recreate them |

Docker's kit-spec conformance suite checks this capability through `tests/conformance/smolbento-adapter`
(`just conformance`, pinned to sandbox-kit-spec `06ac386`). Ten `ssh-agent@1` checks pass
(`agent-reachable`, `operations-restricted`, `signatures-bounded`, `logins-bounded`,
`binding-verified`, `destination-keys-outside-sandbox`, `absent-without-grant`, `every-boot`,
`unavailable-refuses-required`, `unavailable-skips-optional`); `phase-scoped` is
skipped (needs `lifecycle@1`). Two other checks fail in the run, neither about the agent:
`host-mount@1/unadvertised-is-unmet` and `SPEC-v3 §7.1.2/exact-version`. The suite's isolated
setup needs the units' socket path under 104 bytes (a short `SMOLBENTO_TCK_HOME`); a longer one
falls back to attached-only serving and the boot-time checks fail.

## Kits

smolbento implements the [sandbox kit spec](https://github.com/docker/sandbox-kit-spec) at commit
`198d50b5fd57b216b511fd7200010a3636cb3f01` (`SPEC_COMMIT` in the code). v3 is still experimental
upstream. v2 `spec.yaml` kits and smolvm Smolfiles work too.

A kit that **requires** a capability marked "no" or "later" fails, with its `type@version`, before
anything is created. An optional one is skipped with a warning.

| Capability | sbx (local) | smolbento |
|---|---|---|
| `network-policy@1`, `@2` | Yes | Yes, source `kit`. Install-phase rules last through the first start's install steps only. An install-phase CIDR deny stays enforced for the sandbox's life (smolvm takes CIDR denies only at create; create prints a note), though `policy ls` doesn't show it. `@2` method and path rules aren't enforced, so a kit requiring them is refused. Optional: allow rules cover the whole host, and deny rules with methods or paths are dropped (the skipped line says how many) |
| `credential@1` | Yes | API keys: yes, through your secrets. OAuth with `passthrough: true`: yes (the agent's own login keeps its tokens in the sandbox). OAuth without passthrough: no |
| `port@1` | Yes | Yes, on `127.0.0.1` |
| `volume@1` | Yes, removed with the sandbox | Yes, on the sandbox's disk. Removed with the sandbox (`rm`, `reset`, recreate); kept across stop and start; each fork gets a copy |
| `resources@1` | Limited (no GPU) | CPUs and memory. GPU ignored |
| `lifecycle@1` | Yes | Yes: install steps on first start, startup steps on every start. `interactive` ignored |
| `agent-context@1`, `@2` | Yes | Yes, in the same places (see below) |
| `sbx@1` | Yes | Yes: the workload's command is the agent (see below) |
| `git-identity@1` | Yes | Yes: your `git config user.name/email` |
| `long-running@1` | Yes | Yes: no auto-stop when the last session ends |
| `privileged@1` | Yes | Yes |
| `agent-sessions@1` | Declaration only | Declaration only |
| `host-mount@1` | Yes | Yes: a directory on your machine, shared by the kit's sandboxes and kept after `rm` (see below) |
| `ssh-agent@1` | Yes | Yes, with `sign` and `authenticate` limits, served by a service unit ([SSH agent](#ssh-agent)) |
| `agent-skills@1`, `agent-skill@1` | Yes | Yes ([Skills](#skills)). `kit add` refuses a kit with either, as it does `host-mount@1`. `agent-skill@1` with `name: null` means no name |
| `kit-registry@1` | Approved builder kits only | No |
| `agent-interactive-sessions@1`, `usb-device@1` | No | No |

### What works as in sbx

- A workload kit's command runs as the image's `USER` (root if none), under `/bin/bash` so
  `BASH_ENV` is sourced, in the workspace path rather than `WORKDIR`. `sbt exec` uses the same
  user. Without `/bin/bash` the error is `executable file '/bin/bash' not found` (exit 127).
  smolvm maps the workspace to the image user so it can write it. An image with no `ENTRYPOINT`
  or `CMD` is refused at create and by `kit validate`.
- A v3 workload's `ENTRYPOINT` + `CMD` also run at every boot, as the image user, as the kit
  spec's default launch mode says (the machine's command; smolvm keeps the machine up after it
  exits). Not measured against sbx. `sbt run` is unchanged: an interactive session through `exec`.
- Install steps run as root in the image `WORKDIR` (`/` otherwise). Startup steps and kit files
  default to `agent`. v3 install steps get a clean environment: `PATH`, `HOME`, `USER`, `TERM`,
  the proxy and CA variables, and the step's own `env`. v3 startup steps and all v2 steps get the
  full sandbox environment.
- Startup steps block, in kit order. A failure fails the start (`kit startup exited with code N`).
  `background: true` steps start in place and are only logged if they fail. A blocking step that
  never ends holds the start (no timeout). The log is `/var/log/sbx-kit-startup.log`. A step that
  fails during create still creates the sandbox (with sbx's `StartRuntime after create failed`
  warning), which is left stopped; later starts fail until the step succeeds.
- An optional kit argument used with no value and no default is an error
  (`create-phase kit arg "x" has no resolved value`). `--kit-arg x=` sets it empty. `--kit-arg`
  without a kit is an error. A `KIT.NAME` value for a kit not in the set is ignored. Unquoted
  numbers and booleans in `default:` and `enum:` become strings. A v3 argument with `env:` is
  exported under that name whenever it has a value (defaults and empty values count; no value
  exports nothing). The name may be `PATH`. A later kit's value and your own `-e` still win.
- For `create REF`, a bare or dotted word is an agent name even when a directory of that name
  exists: `sbt create alpine` fails with `unknown agent "alpine"`, `sbt create .hidden` with
  `unknown agent ".hidden"`. `a/b` is a registry reference even if the directory exists. For
  `--kit`, `kit validate|inspect|add` and an environment file's `kits:`, an existing path is a
  local kit without `./` (in an environment file, relative to the file). Otherwise a local kit is
  a path (`.`, `..`, `./kit`, `../kit`, `/abs/kit`), and a registry reference has a `/`. With no
  such directory, `--kit alpine` fails with
  `kit reference "alpine": not a local path and does not look like a registry reference`. ZIP kits
  and `git+` sources are refused. All measured on v0.53.0.
- Versions in `provides: [name@1.2.0]` and `requires: ["name >= 1.0"]` follow the spec's version
  grammar. Agent presets provide their name at their image tag's version, so
  `requires.agent: claude` works on `claude`.
- Composition errors use sbx's texts, with kits named as typed. They are
  `resolve: the kit set is not coherent:` with one `  - <problem>` line each,
  `resolve: dependency cycle among ./a, ./b`, and `kit ./x is listed more than once`.
- A required credential with no secret warns
  `WARN: required credential not found for service SERVICE`, and the requests go out without it.
  The warning adds the `sbt secret set` command to run.
- `kit inspect` and `kit validate` print sbx's summary (`Name:`, `Kind:`, `Schema:`, `Policies:`,
  `Credentials:`, `Commands:`) and `✓ <ref> — valid`. `kit inspect --format json` is the
  v2-shaped descriptor; `kit validate --json` is `{reference, kind, valid, warnings}`.
- `policy ls` shows kit rules as one `kit:<sandbox>` row per sandbox (source `kit`). `policy rm`
  can't remove them; deny a host instead.
- Agent context goes in the agent's file in the workspace's parent directory, inside the sandbox
  only: `CLAUDE.md` (claude), `GEMINI.md` (gemini), `AGENTS.md` (others), or the file a workload
  kit's `agent-context` names, with its text appended. A v2 mixin's text goes to
  `kits-agent-context/<kit>.md` beside it, listed between `<!-- sbx:kits-section start -->` and
  `<!-- sbx:kits-section end -->`.
- The settings are `kit.allowedSources` and `kit.allowLocalKits`
  ([Configuration](configuration.md#settings)).
- A `host-mount@1` directory is `kit-host-mounts/<sha256(kit)>/<sha256(path)>` under
  `~/.local/share/smolbento`, keyed on the kit that declares it (a mixin's own, not the workload's;
  a local kit's key is its canonical directory). Parents are `0700`; the directory takes the kit's
  `mode` (default `0755`) and an existing one is reused. Sandboxes of the same kit share it, and
  `rm` keeps it. `--mount HOST:SANDBOX_PATH` and `sbxenv.yaml` `mounts:` replace it, at create
  only, with sbx's errors (`--mount "X" requires HOST:SANDBOX_PATH`,
  `HOST "X" does not exist on the host`, `no kit declares host-mount@1 at "PATH"`). Two kits
  declaring storage at one path fail with
  `kits A and B both declare storage at PATH; a host mount has one owner`.

### Differences

| Area | sbx | smolbento |
|---|---|---|
| Building local v3 kits | BuildKit on your machine | BuildKit in a hidden `_builder` sandbox; no Docker needed locally. It never gets your secrets. Base images that need a login pull with `secret set --registry` credentials: the builder gets a short-lived pull token for the `HOST/<repo>` references in the descriptor, reaches those registries whatever the policy, and is recreated when the registry set changes. A build reaching a stored-login registry without naming `HOST/<repo>` fails with `502 credential unavailable`. Docker Hub logins don't apply yet |
| Where a kit sends a secret | Any host the kit names, after you approve | A built-in service's secret goes only to that service's hosts (else the kit is refused). A custom service's can go anywhere, with a note at `create` and `kit add` |
| Install-only credentials | Not injected after install; requests go out without the credential | The sandbox restarts once after install without them; later requests to their hosts get `502` |
| OAuth credentials | Passthrough and sentinel tokens | Passthrough only (sentinel tokens need smolvm support) |
| Method and path rules | Enforced (`403` outside the rule) | Not enforced (as with `policy allow --method/--path`); a kit requiring them is refused |
| `kit validate` on registry references | Refused: "OCI references are not supported for validation" | Pulled and validated |
| `kit add` | Recreates the container; refuses v2 kits with files and v3 mixins on a v3 workload; asks before opening network access, no skip flag | Applies to the running sandbox, files and deny rules included. Image layers, credentials, ports, volumes, resources, environment variables and `long-running` need a recreate (`recreate required`). Asks before opening network access; `-y/--yes` skips it. A new startup step that fails only warns |
| `--offline` on `kit inspect`/`validate` | Skips the daemon policy; local directory or ZIP only; v3 source directories refused | Skips the source policy (`kit.allowLocalKits` included). Local v2 kits and Smolfiles only. Registry references and v3 source directories are refused. `validate` of a v2 workload whose command comes from its image is refused too. No ZIP or git references |
| `kit inspect` output | Summary table; `--format json` is the v2-shaped descriptor | Same shape, plus `--format yaml` and `--json`. The table adds `Capabilities:`, Source, Digest, Provides, Requires, Integrates, Conflicts, Credentials (each service and where its secret goes), and Args when present; JSON and YAML carry these under a `smolbento` key. `--kit-arg` is checked but not substituted into the output |
| `kit pack`, `kit push` | v1 and v2; v3 refused (`unsupported schemaVersion "3" (supported: [1 2])`) | v2 only (v1 isn't loaded); v3 refused with sbx's message. A kit with `files/workspace` is refused (sbx's mapping isn't measured) |
| Kit archives | `kit pack`'s ZIP and pushed layer are byte-stable | Deterministic but not byte-identical (Go and Rust deflate differ), so each tool gives the same kit a different digest. The ZIP stores entries uncompressed |
| `kit push` | HTTPS only; every push attaches a provenance referrer | Plain HTTP for loopback registries. No provenance yet. Prints `Pushed REF (sha256:…)`. Needs a tag. Logs in with `sbt secret set --registry` credentials, else the host's docker login |
| `kit pull` | Saves the files layer as `<repo>-<tag>.tar.gz` | With a digest, the default name is `<repo>-<first 12 hex>.tar.gz` (sbx's not measured). Other artifacts, including v3 image kits, are refused (`… is not a v2 kit artifact`). `kit.allowedSources` applies to `pull`, not `push` |
| `kit sign`, `kit verify`, `kit push --sign` | Sigstore bundles as `application/vnd.docker.sandbox.kit.signature.v1` referrers; keyless (Fulcio and Rekor) or `--key` (unencrypted PEM, no Rekor upload) | Same bundles and referrers, made and checked by `cosign` (must be on PATH; `--key` PEM is imported into a private temp directory). Registries without the referrers API get the `sha256-<hex>` tag index, which sbx reads. A local directory (`kit.sig.bundle`) and `--tlog-upload=false` are refused (exit 2). `verify --key` checks no transparency log entry. `push --sign` attaches no provenance. `sign` prints `Signed REF`; keyless `verify` prints the identity and issuer you gave, not the certificate's |
| `kit validate` output | `✓ <ref> — valid`; `--json` is `{reference, kind, valid, warnings}` | Adds `--format table\|json\|yaml`. A failure with `--json` or `--format json\|yaml` prints the object with `valid: false` and `errors: [...]` on stdout and exits 1; table output prints the plain error |
| The name `docker` | A registry ref (the `docker` image) | The shipped Docker kit. Write `docker.io/library/docker` for the image |
| Docker in the sandbox | Run by the `-docker` images | The shipped `docker` kit comes first, before your kits (added to Docker-enabled images, or `--kit docker`). Its `dockerd` step runs in the background: a failure is only logged (`/var/log/dockerd.log`) |
| v3 mixins on built-in agents | Allowed since sbx 0.53 (earlier: `no workload kit in the set`) | Allowed |
| v2 and v3 kits in one sandbox | Refused: `cannot mix v3 kits with v1/v2 kits in one sandbox; compositions are single-format (v3: …; v1/v2: …)` | Same message, at create and by `kit add`. A sandbox created before 0.20 has no recorded format, so `kit add` doesn't check it |
| v2 mixins on built-in agents | Refused, since the agents are v3 kits (sbx 0.53) | Allowed. Presets, the shipped `docker` kit and Smolfiles have no kit format |
| Published v2 kits | OCI artifact: config is the spec, one layer is `files/` as tar.gz under `home/agent/` | A files-layer entry outside `home/agent/` is refused (other mappings unmeasured). The agent is named after the reference (`gemini-kit`), not the kit |
| Retired agents | `gemini` (0.53) refused for new sandboxes, pointing to `antigravity` and `docker.io/sbx/gemini-kit` | Same wording. Sandboxes created with `gemini` earlier keep working (not measured on sbx) |
| Self-referencing kit variable | `PATH: /opt/kit/bin:$PATH` gets the image's PATH | Same for `$NAME` and `${NAME}` in NAME's own value (read at create; smolvm doesn't expand variables yet). `${PATH}` in another variable stays as written; sbx substitutes the kit's unexpanded PATH |
| `--mount` with a file as `HOST` | Not measured | `workspace X is a file; …` (smolvm mounts directories only) |
| `--mount` path no kit declares | `request failed: 400 Bad Request: no kit declares host-mount@1 at "PATH"`, after the image is prepared | Same text without the prefix. A local kit is still built first; a published kit's image isn't prepared |
| Host-mount location | `~/Library/Application Support/com.docker.sandboxes/sandboxes/kit-host-mounts/` on macOS | Under smolbento's data directory, so sbx's directories aren't shared |
| Loopback registries | HTTPS only | Plain HTTP for `localhost`, `127.0.0.0/8` and `::1`, as in Docker |
| Smolfile kits | None | A Smolfile defines its own workload; one without a command keeps the shell agent's |
| Agent context file | Starts with a long platform preamble | No preamble: kit text and the index only |
| Mixin context with no agent file in the workload | Dropped silently | Dropped with a warning |
| Startup log lines | `ok /etc/durable-startup.d/…` | `ok /etc/smolbento/startup.d/NN-<kit>.sh hook N`, one per step and start |
| v2 kits' `requires.agent` | A base-agent name | A capability name with no version, so any version meets it (v2 has no versioned provides) |
| `kit add` and earlier kits | Recreates with the whole set | Checks the new kit against the provides recorded at create, with versions. Older records hold bare names, which meet only unconstrained requires. A preset's own name counts as `claude@0`, so a versioned require can pass at create and fail at `kit add`. Errors name kits by kit name. Earlier kits' requires and conflicts aren't rechecked |
| Kit settings | Also `kit.requireSignature`, `kit.trustedSigners`, `kit.ignoreTransparencyLog`, `kit.allowExtractedAgents` | All but `kit.allowExtractedAgents` (built-in agents aren't kits) |
| `kit.requireSignature` | Enforced wherever a kit loads (not `kit pull` or `--offline`): a registry or local kit needs a signature verifying against `kit.trustedSigners` (`{"key": PATH}`, or keyless `issuer`/`identity`, each also `…Regexp`). Success: `✓ REF — signature verified (IDENTITY via ISSUER)` on stderr | Registry kits only, checked on the resolved digest. Presets and shipped kits (`claude`, `docker`) are exempt. Local directories and Smolfiles are refused (`… is not signed`, or `… isn't supported yet` with a `kit.sig.bundle`). The success line names the matching signer entry, not the certificate's identity |

### Not measured against sbx yet

- How float or unusual literals (`1.0`, `0x10`, `True`) become argument strings (smolbento writes
  `1.0` as `1`).
- A v2 or startup step run as a non-root user keeps the sandbox environment, except `HOME`, `USER`,
  `LOGNAME` and `SHELL`, which are that user's (via `runuser`, or `su` without `-`, which resets
  them).
- A v3 mixin's agent context: smolbento writes it to `kits-agent-context/<kit>.md`, as for v2.
- `integrates` and `conflicts` error texts, and a published kit whose provides have no version.
- An optional argument a kit declares but doesn't use, with no value and no default.
- A published kit's host-mount identity: keyed on `<registry>/<repository>`; sbx's choice isn't
  measured.
- The kits index after hand edits (a removed or duplicated marker, or text inside the block).
- Inferred, not measured: `kind` values other than `directory` (smolbento uses `file`, `registry`,
  `builtin`); `Schema:` for registry, builtin and Smolfile kits; network rule counts; the init-file
  count; the JSON layout under sandbox, permissions, credentials and setup; the failure object; and
  `Template:`, shown only for a built local v3 kit.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error (the message says why) |
| 2 | Not implemented yet, Docker Cloud only, or a usage error |
| other | `run` and `exec` return the agent's or command's own status |
