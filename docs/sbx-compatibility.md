# sbx compatibility

smolbento takes Docker Sandboxes (sbx) command lines flag for flag. The reference is sbx v0.49;
kit host mounts, `--mount` and `inspect` are checked against v0.50.1, and commands, flags, aliases
and `--json` output against v0.53.

Anything not implemented yet still parses and exits with status **2** and prints a message, so
scripts fail clearly instead of doing something different.

What this page says about sbx is measured on those versions or read in Docker's documentation,
which is the authority. It can be out of date. Items marked "not measured" are our best guess.
Corrections are welcome as [issues](https://github.com/pelotech/smolbento/issues).

## Works today

`run`, `create`, `exec`, `ls`, `inspect`, `start`, `stop`, `rm`, `prune`, `reset`, `cp`, `version`,
`completion`, `diagnose`, `settings`, `policy`, `secret`, `ports`, `env create|run|exec|rm` (see
[Environment files](#environment-files)), `run/create --deny-network`, `run/create --clone`, kits
(`--kit`, `--kit-arg`, `--kit-args-file`, `--mount`, `kit inspect|validate|add`; see [Kits](#kits)),
`mcp add|ls|inspect|rm` and `--static-mcp` (see [MCP servers](#mcp-servers)), and
`policy ls --source`.

smolbento-only:

- `start` and `exec --privileged`. sbx 0.53 dropped them; smolbento keeps them.
- `fork`. sbx has none; its `template save` saves only the disk.
- `daemon`. Accepted and does nothing.
- `kit mounts ls|rm`. Lists and removes the directories kept for kits' host mounts. sbx keeps
  them too, with no command to see or remove them.
- `smolvm ARGS…`. Runs the smolvm smolbento uses (the pinned release it downloads) on its own
  state (`~/.smolbento`), passing ARGS through. sbx has no `smolvm` command.
- `SMOLBENTO_LOG`. Logs smolbento's steps and their times on stderr
  ([Troubleshooting](troubleshooting.md#logs-and-timings)). `-D, --debug` (sbx: "Enable debug
  logging") prints each smolvm call and turns this log on at `info`.

## Parses, not implemented yet (exit 2)

| Command or flag | Status |
|---|---|
| `policy refresh`, `secret import`, `secret set --oauth/--refresh`, `secret set/rm --registry` with `--sandbox`/`--all-sandboxes` | Not implemented |
| `sbxenv.yaml` fields under [Environment files](#environment-files) | Later |
| `setup ssh --auto-create` (desktop app connections) | Not supported |
| `mcp auth`, `mcp load`, `mcp unload`; `mcp add --local`, `--dir`, `--client-id`, `--oauth-authorization-server`, `--resource`, `--skip-auth` | Not supported: no MCP gateway |
| `create/run --profile`, `policy ls --profile`, `template ls -a/--digests/--no-trunc`, `template save\|load --capture-mode/--description`, `secret set-custom --no-verify/--show-error/--refresh`, `mcp add --disable-http2/--skip-ssrf-check/--callback-port/--scope/--no-scope` | Not implemented |
| `diagnose --upload` | Never: sbx sends the report to Docker support, and smolbento has no support service. Nothing is sent |
| `tui` | Later |
| `--pull never` without a saved template ([Templates](#templates)) | Not implemented |
| `exec -d`, `--detach-keys` | Not supported (sbx doesn't support `exec -d` either) |
| `secret set-custom --placeholder` | Not supported: smolvm chooses the placeholder |
| `secret rm --all-sandboxes` | Not implemented |
| `policy allow\|deny --protocol` other than `tcp`; `policy log --type filesystem` | Not supported: smolbento has TCP network rules only |

## Never (Docker Cloud only, exit 2)

`login`, `logout`, `move`, `ttl`, `attach`, `volume`, `template inspect`, `policy init --sandbox`,
the global `--cloud` flag, and the cloud-only `run`/`create` flags (`--allow-network`, `--image-ref`,
`--platform`, `--ttl`, `--on-timeout`, `-v/--volume`, `--new`; `env create` and `env run` take
`--ttl` and `--on-timeout` too).

## SSH

`bento setup ssh` and `ssh NAME.sbx` follow sbx's documented behaviour (sbx's own reference page for
`setup ssh` was empty when this was written, so none of it is measured against a real sbx).

| | sbx | smolbento |
|---|---|---|
| Config block | `# >>> docker sandboxes (managed) >>>` in `~/.ssh/config`, `ProxyCommand "sbx" ssh proxy %n`, `KnownHostsCommand`, `UserKnownHostsFile ~/.ssh/sbx_known_hosts`, `StrictHostKeyChecking yes` | Own markers `# >>> smolbento (managed) >>>`, so it never edits sbx's block (`setup ssh` warns when both exist: the first `Host *.sbx` wins). More below. |
| `--auto-create` | Adds desktop app connections | Not supported |
| Sessions | The daemon terminates SSH; an unknown sandbox is an error; a stopped one is started | Same, in the `ProxyCommand` process. The shell is the session user's login shell in the workspace, on a pty from your terminal |
| Local forwarding (`ssh -L`) | To the sandbox's loopback | Same, `localhost`, `127.0.0.0/8` and `::1` only. Each connection runs `nc` in the sandbox, else bash's `/dev/tcp`; with neither, the forward fails with a message |
| SFTP, `scp`, agent forwarding, X11, remote forwarding | Not documented | Refused |
| Signals, exit signals | Not documented | A signal sent over SSH isn't delivered; a command killed by signal `n` exits with `128+n` |

- **Config block:** Added at the top of the file, ending with `Host *` so your own top-level options
  keep their scope. The options are sbx's, except that `StrictHostKeyChecking no`,
  `UserKnownHostsFile /dev/null` and `LogLevel ERROR` replace the known-hosts ones. The server is
  `bento ssh proxy`, a child process of `ssh` on a pipe, so there is no network path to impersonate
  and a host key protects nothing. There is no `ssh known-hosts` command and no host key file; each
  connection uses a new key. `ProxyCommand` uses absolute paths (with `env SMOLBENTO_SMOLVM=…
  SMOLBENTO_SMOLVM_HOME=…` for the ones you set), found when `setup ssh` runs, because an IDE
  started from the Dock has a minimal PATH. Run it again after moving either. No `IdentityAgent
  none` (IDEs such as IntelliJ warn about it; `IdentityFile /dev/null` and `IdentitiesOnly yes`
  already keep keys out). `setup ssh remove` touches nothing outside our markers.

## Differences you'll notice

| Area | sbx | smolbento |
|---|---|---|
| Network | Default-deny policy | Same modes and rule syntax. A hosted sandbox (the default) enforces host rules and ports for each connection that names its host (TLS SNI or HTTP `Host:`), and method, path and query rules per request ([Hosted egress](network-and-secrets.md#hosted-egress), [Request rules](network-and-secrets.md#request-rules)). A denied request gets sbx's `403`; a denied connection is reset after it opens. A flow that isn't TLS or HTTP is judged by address and port only; a TLS or HTTP flow with no name needs an IP or CIDR allow. With `network.egress=smolvm`, and for unnamed connections, rules are looser: `*.x.com` matches any depth (sbx: one label), wildcards inside a label (`crl*.x.com`, `?`, `[..]`) widen to `*.x.com`, and ports aren't enforced (`policy ls --wide` shows which, in STATUS). With `network.egress=smolvm`, request rules aren't enforced either, and a request deny acts on its whole host. `balanced` is sbx's 195 rules plus Nix caches, on any port |
| Host deny rules | Always enforced | A hosted sandbox enforces them by name, under allow-all and inside a broader allow too, ports included; IP and CIDR denies apply live. With `network.egress=smolvm`: not enforced under allow-all, nor where a broader allow covers the host. Only deny CIDRs are enforced (at create). A deny with a port isn't enforced, because smolvm can't filter by port. The exception: a deny with the same text as an allow cancels that allow. `policy check` and `policy deny` say so |
| Secrets | Proxy injects on the wire | The sandbox's egress process (smolvm with `network.egress=smolvm`) substitutes on the wire. A secret's hosts and their subdomains are always reachable from sandboxes that bound it (`policy deny` of one is refused). A new value applies to a running sandbox at once and to a stopped one at its next start. A service a sandbox was created without needs a recreate on a hosted sandbox (`secret set` says so); with `network.egress=smolvm` it applies to a running sandbox at once, and to one that booted with no secrets at all from its next start. A removed value stops being sent by running sandboxes at once: they get the entry that still applies (the global one, or a fork's original's), else a fixed non-secret value |
| `secret set-custom --host` | Exact host, IP or wildcard pattern | Exact host, or `*.domain` for any depth (not the apex). Other wildcards and IPs are refused: smolvm substitutes secrets only for host names |
| Policy changes | Live everywhere | Live, except: switching a running sandbox between allow-all and a restricted mode reaches smolvm's allow list on its next start (a hosted sandbox's egress process applies the new mode to named connections at once), and with `network.egress=smolvm` deny-CIDR rules apply only to sandboxes created afterwards |
| Approvals | Queue | Derived from smolvm's blocked-request (egress) log; the host is the approval id. A connection a hosted sandbox's egress process denies is in its `egress.log`, not in `policy log` or approvals |
| Host services | Per-port `host.docker.internal` when the policy allows `localhost:PORT`, live; a blocked request gets `403 Approval required…` | Per-port and live for a hosted sandbox. With `network.egress=smolvm` a `localhost` rule opens **every** port on the host's `127.0.0.1` (smolvm can't open one port). Never `::1`. More below. |
| Published ports | Any host IP | Loopback only: `127.0.0.1` and `[::1]` |
| Automatic publishing | None: ports are published on request (`sbx ports --publish`) | None. smolvm's `--auto-ports` (publish every port a guest listens on) isn't used: sbx publishes on request, and auto-publishing would open ports without the user asking |
| `cp` of a directory out of a sandbox | As `docker cp`: into an existing directory, merging | Placed the same way, but refused if the copy's target already exists: it's unpacked whole and moved into place, never merged |
| Single-file `:ro` mounts | Supported | Directories only (smolvm mounts directories) |
| Machine names | `.` allowed | No `--`, no trailing `-` (smolvm rules) |
| Daemon | `sandboxd` | None; each command talks to smolvm directly |
| Clone transport | Git daemon in the sandbox on a published port; the remote URL is set at each start, and a fetch needs the sandbox running | No daemon or port. The `sandbox-<name>` remote's `uploadpack` runs `smolbento _upload-pack <name>` (so `smolbento` must be on `PATH`) through `smolvm machine exec`. `git remote -v` shows a placeholder `file:///sbt/<name>` |
| Tags from the sandbox | Remote follows tags | `tagOpt = --no-tags`; only branches come back |
| Fetch on exit | None | `bento run` fetches `sandbox-<name>` when the agent exits (`clone.fetch-on-exit`, default `true`), with `fetch.fsckObjects=true`. Manual `git fetch` is unchanged |
| Fetch from a stopped sandbox | Needs the sandbox running | Starts it, fetches, stops it again |
| Linked worktrees as clone source | Not supported | Supported: the branch, or the commit when detached |
| `inspect` | Also `id`, CPUs, memory, uptime, image digest, auth mode, network, mount and proxy policy, runtime mounts, MCP gateway, daemon | Those are left out (a sandbox is known by its name; smolvm has no other ID). The rest matches sbx's layout and JSON keys, `created_at` and `created_version` (`Created with:`) included; sandboxes from before 0.27 have no `created_version` |
| Default name held by another directory | `create` refuses (`sandbox name … is already used by workspace …; pass --name …`); `run` reattaches to the current directory's sandbox (0.53) | Same, and the refusal suggests a name (`such as --name <agent>-<parent>-<directory>`). smolbento-only `sandbox.autoName` takes it instead of refusing. `run` finds this directory's sandbox by its workspace and agent |
| `reset` | Resets to a freshly installed state: stops and deletes sandboxes, clears the image cache, policy, the managed SSH config, secrets (unless `--preserve-secrets`), and all state, cache and config directories; also signs out, stops the daemon and clears Gordon's history | Same: sandboxes (and smolbento's leftovers in smolvm's default location, never machines without its labels), `~/.smolbento` (smolvm's state, images and the downloaded smolvm), the SSH config block, background services, and smolbento's config, cache and data directories (kit host-mount directories included). More below. |
| Progress output | A line per image layer | No per-layer lines. The pull shows a percentage, and the image step reads `preparing` until smolvm reports a pull (a cached image has none). CPU and Memory print before a kit's `resources@1`. A kit's "cached" label is approximate when pulls or builds overlap. On a terminal, a step's detail stays on the step's line, and a warning follows the step's last drawn line |
| Browser and clipboard | Shims post to the daemon's proxy with `curl` and `jq`; copies work from any `exec`; image paste behind `clipboard.imagePaste`; `SBX_HOST_SESSION_ID` routes requests | Same shims and texts over a socket smolvm mounts at `/run/smolbento/bridge.sock`, with `curl` only. Copying is off until `clipboard.textCopy` is `true`, as in sbx 0.51. More below. |
| Command aliases | `ls`, `rm`/`delete`, `secret ls`/`rm`/`delete`/`unset`, `settings ls`, `template ls`/`list`, `template rm`/`remove`/`delete`, `policy ls`/`list`, `policy rm`/`remove`/`delete`, `mcp rm`/`remove`/`delete` | Implemented. `volume` aliases come with that command |
| `--version` | `sbx version vX <revision>` | `bento version vX` (no revision); `bento version` also shows the smolvm version |
| `settings ls` | `KEY VALUE TYPE SOURCE RESTART DESCRIPTION`, sorted, cells cut; `--no-trunc` prints a block per setting | Same. `RESTART` is always empty (no daemon); `TYPE` is `bool` or `string` |
| `policy ls` layout | 0.53: one row per policy (`POLICY SOURCE APPLIES TO SUMMARY`); `--wide` a row per rule in 14 columns; `--json` and `--format yaml` are `{"rules":[…]}`; `policy ls SANDBOX` a summary (`Policy for sandbox:`, `NETWORK`, `FILESYSTEM`) | Same layouts, texts and JSON key order. The differences are the rows below |
| `policy ls`: the mode | No mode line. The `default-deny-all` policy (`network: deny when no rule decides`) is the fallback | Same: no `Mode:` line. `balanced` and `deny-all` show `default-deny-all` (`balanced` also lists its preset groups in `local-policy`). `allow-all`, and a policy with no mode chosen yet, show `default-allow-all` (`network: allow when no rule decides`) instead: smolbento-only |
| `policy ls`: policy and rule IDs | UUIDs; sandbox-scoped rules are in a policy with its own UUID | Rule IDs are `r-<hash>`. Policies are named `local-policy` (global rules), `sandbox:<name>` (a sandbox's rules), `kit:<name>` (its kit rules) and `mcp:<name>` (its `--static-mcp` hosts, source `mcp`) |
| `policy ls`: filesystem rules | `default-fs-read-allow-all`, `default-fs-write-allow-all`; a `FILESYSTEM` section in `policy ls SANDBOX` | None: smolbento has no filesystem policy. `--type filesystem` prints `No policies match the selected filters`, and the sandbox summary has no `FILESYSTEM` section |
| `policy ls`: resources | Preset hosts carry `:443` | Shown as stored: the preset's hosts have no port (they're allowed on any port), and `balanced` has the `smolbento-nix` group too |
| `policy ls`: STATUS and `reason` | `active`; a reason only on the fallback | A rule smolvm enforces more loosely than sbx also has a reason (`--wide`: `active — <resource>: port 8080 not enforced by smolvm (all ports allowed; enforced for hosted sandboxes)`; JSON `reason`). So does a rule with a method, path or query (`method GET, path /v1/** enforced for hosted sandboxes`). The table and the sandbox summary count such rules in a note on stderr |
| `policy ls`: rules with a method, a path or a query | Type `http` | Type `http` with METHOD and PATH filled in, actions `net:connect:tcp`. A query shows in STATUS only, as sbx 0.53's 14 columns have no QUERY. A sandbox's kit rules are one `kit:<sandbox>` rule of type `network`, as in sbx 0.49. sbx 0.53's JSON for kit and `http` rules wasn't observed: smolbento uses `layer: "kit"`, `created_via: "provisioned"` |
| `policy ls` filters | `--source local\|org\|kit`, `--include-inactive`, `--profile` | `--source` also takes `mcp`; `org` matches nothing. `--include-inactive` changes nothing (every rule is active). `--profile` is refused. A bad `--decision` or `--source` value has smolbento's own error text |
| `policy approval ls`, `inspect` | 0.53: `APPROVAL SANDBOX TITLE DETAIL OPTIONS`; JSON keys `created_at`, `detail`, `id`, `options`, `sandbox_name`, `title`; the ID is `network:<hash>`, the title `host:port`, the detail `Protocol: TCP`, `Resource type: domain` and the reason | Same layout, keys and options (`allow`, `dismiss`). The ID and the title are the blocked host: smolvm's log has no port or protocol, so the detail has no `Protocol:` line. `created_at` is the oldest of the last 200 blocked requests read, in UTC. `inspect` of a host blocked in several sandboxes shows one of them, a pending one first |
| `policy approval respond` | 0.53: `APPROVAL-ID --option OPTION-ID` prints `Recorded answer Allow`; `allow` adds a rule for the approval's sandbox, `dismiss` adds none | Same, and the same errors (no `--option`, an unknown option, `is not pending`). An allow that reached a running sandbox adds `Updated N running sandbox(es)`, and an allow of `localhost` warns as `policy allow` does. One host blocked in several sandboxes is one ID: the answer goes to each of them, or to `--sandbox NAME` (smolbento only). A dismissed host is asked about again when it is next blocked |
| `policy rm network --method/--path/--query` | Pick one HTTP rule of the resource | `--method` (the same methods, in any order), `--path` and `--query` (the same parameters, in any order) pick among the resource's rules. sbx's errors: `--method requires --resource` (assumed for `--path` and `--query`, which weren't measured), and `remove network rule: remove-resource: not found; …` when no rule has the resource. An empty `--method` is refused (`--method names no HTTP method`). `--id` alone says `no matching rules` |
| `policy check network` output | A block: `Denied:`/`Governance:`/`Context:`/`Reason:`; `-v` adds `Action:`, `Resource:`, `Deny kind:` | Same block. `Reason:` is printed for an allowed target too. The verdict is the connection's, whatever request rules apply on the host. `Allowed:` and `Deny kind: explicit` (a deny rule) weren't measured in sbx |
| Bounded allows on a secret's host | A bound secret admits its host before any rule, so a bounded allow there bounds nothing (assumed from the connection verdict; not measured) | The secret makes the host reachable, and its bounded allows still bound its requests, as the kit spec requires (`network-policy@2` `http-method-enforced`, `http-path-enforced`) |
| `policy check network` targets | 0.54: a URL is read as `host:port` (`http` 80, `https` 443; another scheme needs a port: `target URL scheme "ftp" must include an explicit port`); a path without a scheme is refused; the host is lowercased and `host.docker.internal` read as `localhost`; `resource_value` drops IPv6 brackets | Same, with the same errors (without sbx's request prefix). The host's loopback (`localhost`, `127.0.0.0/8`, `::1`, the gateway) is an implicit denial unless the sandbox has host access: smolbento denies it at create whatever the mode (`--sandbox` reads the sandbox's record; without it, what a create would get) |
| `policy check network --protocol udp` | Rules are per protocol: a UDP target needs a UDP rule | With `network.egress=smolvm`, smolvm's allow list admits UDP wherever it admits TCP, so the same rules decide (a host sbx denies over UDP can be allowed here). A hosted sandbox sends no UDP but DNS, whatever the rules: the verdict still follows the rules, and an allowed one adds `not from hosted sandboxes, which send no UDP but DNS` (it doesn't read the sandbox's egress mode). Port 53 is denied even where the rules allow it: smolvm answers DNS itself. `policy allow\|deny --protocol udp` is still refused |
| `kit inspect --resolved` | Merges the kit's `extends:` parent into the output | Accepted; prints the same as without it. smolbento's loader accepts `extends:` and ignores it, so there is no parent to merge |
| `diagnose --format github-issue` | A Markdown report for a GitHub issue: OS, architecture, `DS Version`, a `Check \| Status \| Message` table, and the JSON in a `<details>` block | Same shape over smolbento's checks, with `smolbento Version`. Statuses are `✓` and `✗` (`✗` wasn't measured in sbx). Messages are the ones `bento diagnose` prints, paths included: read it before posting |
| `df` | Disk usage of images, containers and volumes | Not implemented (`unrecognized subcommand`) |
| `--format`, `--json` | On every command that prints something | The same flags on every command that prints something, except `template inspect` (refused: sbx has it for cloud templates only). Differences in the output: [Output formats](#output-formats) |

- **Host services:** Only sandboxes created while a `localhost` rule applied get it; others need
  recreating. Kit rules never grant it, and `_builder` never has it. A blocked request gets
  connection refused, with no approval entry. Under allow-all the host's LAN IP is reachable, so
  services on `0.0.0.0` are too (sbx blocks this). See
  [Security](SECURITY.md#host-services-localhost-rules)
- **`reset`:** No sign-out, daemon or Gordon
- **Browser and clipboard:** Served by a launchd or `systemd --user` unit whenever the sandbox runs.
  Without a service manager, only while attached (`run`, `exec -it`). No image paste (sbx doesn't
  read clipboard text either) and no `SBX_HOST_SESSION_ID`. Forks keep the parent's socket, so they
  use its bridge while it is served. Login-relay limits: [Usage](usage.md#browser-and-clipboard)

### Output formats

`--json` and `--format json|yaml` print sbx's shapes, in sbx's key order (measured on 0.53).
Where they differ:

| Command | sbx | smolbento |
|---|---|---|
| `version` | `client` and `server` | `client` and `smolvm` (there is no daemon) |
| `diagnose` | `checks` with `name`, `status`, `message`, `detail`, `hint`; `summary` with `pass`, `warn`, `fail`, `skip` | Same keys; `detail` and `hint` are empty, `status` is `pass` or `fail`, and `warn` and `skip` are 0 |
| `settings ls`, `settings get` | `type` is `bool`, `int` or `string`, among others | `type` is `bool` or `string` |
| `policy check network` | `action`, `allowed`, `context`, `governance`, `resource_type`, `resource_value`, `target`, `type`; a denial adds `deny_kind` and `reason` | Same, and `reason` (the rule or default that decided) is there for an allowed target too |
| `prune --dry-run` | `would_remove` rows with `name`, `agent`, `stopped_at`, `mounts`, `workspaces`; `skipped_unknown_stop` | No `stopped_at` (smolvm doesn't record it); `skipped_unknown_stop` is always empty; adds `host_services`, the leftover units it would remove |
| `prune` without `--dry-run` | Refused: `--format` describes the dry-run listing | Same error |
| `ports --publish`, `--unpublish` | Not measured | The ports this call published, as the listing shows them |
| `secret ls` | `secrets`, `custom_secrets`, `shadowed_services`, `env_only_count` | Registry logins are `secrets` rows of type `registry`; the other three are always empty |

- `-q` wins over `--json`.
- A `stop` or `rm` that fails partway still prints what it did.
- Confirmation prompts go to stderr, so piped JSON stays clean.

## Skills

`skills add|import|ls|rm|update` and `--skills` follow sbx v0.50.1's output and flags, and
`sandboxOptions.skills` works too.

| Area | sbx | smolbento |
|---|---|---|
| Store path | macOS: `~/Library/Application Support/com.docker.sandboxes/sandboxes/agent-skills`. Linux: under `$XDG_STATE_HOME` | `~/.local/share/smolbento/agent-skills` (`$XDG_DATA_HOME` and `$SMOLBENTO_DATA_DIR` respected). A separate store: run `bento skills import` to bring skills over |
| `add` | Clones the repository itself | Runs your host `git` (shallow, no prompts), so credential helpers and the SSH agent apply |
| `update` | Per-skill messages; `No repository-installed skills found` | A failing repository prints an error and the others still update. Exit code 1 (not measured in sbx) |
| Path that is both the agent's and a kit's directory | Can't happen: a v3 mixin can't join a built-in agent | Allowed; the path behaves like the agent's own directory |
| Who links | Root; links to uid 1000. Fails the create when uid 1000 can't reach the directory | Root; links to the image's `agent` account, else uid 1000. No reachability check. A skills path that goes through a symlink gets no links (the start warns; a required bundled skill fails) |
| Kit `mode` | A built-in agent's kit omits it and still gets your skills | An omitted `mode` is `off` (spec): a kit's directory gets bundled skills but nothing from the store; the widest mode at a path wins. A built-in agent's own directories follow `--skills` alone, as in sbx (the spec would make them `off`) |
| Kits | `agent-skills@1`, `agent-skill@1` | Both, as measured. smolvm mounts the store once, at `/run/sbx/skills-shared`, read-write if any directory is. A kit directory gets that mount bound over it unless the sandbox has bundled skills; then every directory links. A required bundled skill named like a stored skill is refused before anything is made; one that clashes with image content fails the first start, which fails the create. `kit add` refuses kits with either |
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
| What a template keeps | The disk | The disk, and the sandbox's kits by pinned ref with their args. A create from it loads them again (from the kit cache when they're there) and reruns their install and startup steps. The sandbox runs the command its source sandbox ran. A template without kit records or a command is refused: save it again |
| `-t` with `--kit` | Not measured | Refused when a kit adds image layers (a template's disk is saved whole) |
| Kit args | Not measured where sbx keeps them | Kept with the sandbox (`sbx.kits`), in its templates and their archives, defaults included |
| `-t IMAGE` with a workload kit | Only for `shell` | Any workload kit, built-in agents included: the image replaces the kit's, its capabilities and command stay |
| `save` of a running sandbox, no terminal | Suggests a nonexistent `--force` | Says to `bento stop` it first |
| `save` of a sandbox created with `--static-mcp` | Not measured | Refused: a sandbox made from the template would list those servers without their secrets or network access |
| `inspect` | Needs `--cloud`; local templates are Docker images | Not supported |
| `--pull never` | Default for saved local snapshots; an uncached image fails (`not cached locally and pull_policy=never`) | Accepted only with a saved template, whose kits must be in the kit cache; exit 2 otherwise |
| `--pull` default, `always`, `missing` | Not measured | A cached kit's tag (`sbx/claude:latest`) is asked at the registry again once a day. `--pull always` asks every time; `--pull missing` doesn't while the kit is cached. A digest-pinned kit never asks |

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
| Disk sizes (`sandboxOptions.rootSize`, `dockerSize`, `clonedWorkspaceSize`; `sandbox.disk.dockerVolume`) | Separate root, Docker and clone volumes; `dockerVolume` defaults to `10g`, and `DOCKER_SANDBOXES_DOCKER_SIZE` sets one create | smolvm has two disks: `rootSize` sizes the overlay; `dockerSize`, `clonedWorkspaceSize` and the setting size the storage disk, which also holds image layers (the larger wins). Unset keeps smolvm's 20 GiB storage and 10 GiB overlay. One create: `SMOLBENTO_SANDBOX_DISK_DOCKER_VOLUME` |
| `bindings` | Merged into the global `credentials.yaml`; `--prune-bindings` removes the service's entry; an unknown service is accepted by `env plan` | Stored in smolbento's secrets file; `--prune-bindings` works the same. An unknown service is refused at create, with the `bento secret set` error |
| `bindings` domains | `env plan` accepts any string: schemes, ports, commas, IPs, `*.com`, `*example.com` (v0.54.0) | Checked as `secret set --host` hosts are: a bare host name or a leading `*.` below the top level, lowercased, trailing dot dropped. Anything else fails the load, because smolvm substitutes for host names only and a comma or colon would change its `--credential` argument. Only `apiKey.domains` get the key; `oauth.domains` are stored but unused (smolbento has no OAuth credentials) |
| `mcp` url servers | Registered for the host, after an OAuth discovery that fails the create if the server is unreachable | Registered in `mcp.toml` and written into the agent's config (`claude` only). Create fails before anything is made when nothing answers at the URL (any HTTP answer counts; no OAuth discovery) |
| `mcp` command servers | Run on the host, approved like lifecycle commands | Refused (exit 2) |
| Plan after a plain `rm` | Lines end `— recorded as applied, no longer present` | A bare `+` |
| A local kit's contents | Not measured | Not part of the approval; the plan names the kit's path |
| `refresh`, `backend` on a secret | Used | Accepted, no effect: smolbento resolves at every start |
| `secret ls` with registry credentials | `SECRET` shows the first characters | A separate `SCOPE TYPE NAME SECRET` table; `SECRET` is always `(stored)`. In `--json` they are `secrets` rows of type `registry` |
| Workload kit as `agent` | The kit whose name equals `agent` | A local kit matches by directory name; a registry kit by the last part of its repository name |
| Secret `command:` source | Runs on the host | Runs from a fresh temporary directory, so a relative helper path fails (also for `secret set --command`) |
| `mounts:` path no kit declares | Error includes `remove this environment's sandbox and provisioned secrets` and `try: sbx env rm`; checked after the kit image is prepared | First sentence only (secrets are stored by then, and `env rm` removes them); checked before a registry kit's image is prepared |
| Kits that can't be loaded | Checked before secrets are stored | A missing local path, a `.zip` or a `git+` source is refused before secrets are stored. An unpullable registry kit fails after they're stored; `env rm` removes them |

## Sandbox environment

Every sandbox gets the variables below, the set sbx sets plus `IS_SANDBOX`. They are passed with
`-e` at create so every process sees them. None holds a secret value.

- `SANDBOX_NAME`, `SANDBOX_ID`, `WORKSPACE_DIR` and `IS_SANDBOX=1` are runtime-owned (spec
  `sbx@1/environment-authoritative`). The sandbox's values win over the image's `Env`, kit exports,
  and every `-e` or `--env-file` value of `create`, `exec` and `run` (an environment file's `env:`
  too, empty values included). A value you give for one is ignored with a warning naming it. sbx
  0.54 lets yours win, and sets `IS_SANDBOX` only from the `claude` kit's image.
- `SANDBOX_ID` is a UUID made at create and kept in the `sbx.id` label: the same after a restart,
  new for a new sandbox (also one created after `rm` under the same name). A `fork` gets its own
  name and id. `${{ kit.env.* }}` expands the four to the sandbox's values, at create and on `kit add`.
- `WORKSPACE_DIR`: the host path of the primary workspace (the guest workdir when mountless: that
  is still an assigned workspace, so it's always set).
- A v3 kit's install and startup hooks get the four only when the hook lists them in its `env`
  (spec `sbx@1/environment-hooks`). sbx 0.54 gives startup hooks the whole container environment.
  A v2 kit's hooks, which can't list them, still get them.
- `SANDBOX_VM_ID` (the name), as sbx sets it.
- `SBX_AGENT`: the agent or kit name. Your own `-e` wins for this and the variables below.
- `SBX_CRED_<SVC>_MODE`: one per service a kit in the sandbox declares a credential for: `apikey`
  when the service's secret is bound at create, else `none`. Not for an inject-only credential
  (`inject` rules, no `name`, no OAuth), which the spec gives no variable at all. As measured in sbx 0.53, `claude` gets
  `ANTHROPIC` and `shell` none. A `-` in a service name becomes `_` (`my-api` gives
  `SBX_CRED_MY_API_MODE`): sbx 0.54 keeps it (`SBX_CRED_MY-API_MODE`), but smolvm's guest agent
  refuses an environment name with anything but letters, digits and `_`.
- Each secret's own variables (`ANTHROPIC_API_KEY`, `GITHUB_TOKEN`…), holding smolvm's
  placeholder. Not for a service whose key a kit takes without naming a variable: `claude` reads
  its key through the `apiKeyHelper` its kit seeds, and would ask about an unknown
  `ANTHROPIC_API_KEY`. sbx 0.53 sets none of these: a secret reaches an agent only as its kit
  declares (measured with `anthropic` in `claude` and `shell` sandboxes).
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
| Serving | The daemon, whenever the sandbox runs | A launchd or `systemd --user` unit owns the socket and runs `bento _serve agent` per connection, whenever the sandbox runs (no smolbento daemon). The create's install steps serve an `install` grant themselves. Without a usable service manager, and for sandboxes made before units, only while `bento` runs for the sandbox (`run`, `exec -it`, plain `exec`), and agent connections fail at other times |
| Sessions | Every session reaches the agent | Every connection is served alone. Attached-only serving: the first session serves it and a concurrent second uses it |
| Which agent | The sbx client's `SSH_AUTH_SOCK` | `ssh.agentSocketPath`, else the user session's `SSH_AUTH_SOCK` (launchd supplies macOS's; on Linux, that of the last `bento` that wrote the unit). Attached-only serving: the serving `bento`'s |
| `SSH_AUTH_SOCK_GATEWAY` | `gateway.docker.internal:3129` | Not set (no TCP gateway) |
| `authenticate` limits | Logins only to the named servers | Supported. Host keys come from `ssh.knownHostsFile` (smolbento-only setting, default `~/.ssh/known_hosts`), read at each login. A server known only through `@cert-authority`, or by a wildcard or negated pattern, is refused, as is a `[host]:port` entry; hashed names work |
| Forks | No forks | No agent or units of its own, but it keeps the parent's socket mount, so it can use the agent (with the parent's grant) while the parent is served |
| `kit add` of an `ssh-agent@1` kit | Recreates the container | `recreate required: … SSH agent` |

Docker's kit-spec conformance suite (`just conformance`, at `SPEC_COMMIT`) checks this capability
through `tests/conformance/smolbento-adapter`. The adapter claims `ssh-agent@1`, `host-mount@1`,
`lifecycle@1`, `network-policy@1`/`@2`, `agent-context@1`/`@2`, `long-running@1`, `privileged@1`,
`resources@1` and `sbx@1`, under the `balanced` mode. All 11 `ssh-agent@1` checks pass. Not claimed:
`dockerd@1`, `volume@1`, `git-identity@1`, `agent-skills@1`, `agent-skill@1` and `credential@1` (each
needs `recreate`, selection records or retained volumes that smolbento doesn't have). The known
failing checks, with the reasons, are in [tests/conformance](../tests/conformance/README.md).

## Kits

smolbento implements the [sandbox kit spec](https://github.com/docker/sandbox-kit-spec) at commit
`a4d6ca06175f2d9cac57428b8c254ba7f5f36570` (`SPEC_COMMIT` in the code; `just conformance` runs the
spec's suite at the same commit). v3 is still experimental upstream. v2 `spec.yaml` kits and smolvm Smolfiles work too.

The spec is followed with hosted egress, the default. A sandbox on smolvm egress
(`network.egress=smolvm`, or a fallback to it) doesn't enforce the spec's network rules: smolvm has
no port, method or path rules, so an optional kit rule it can't enforce is widened to its host or
dropped, where the spec skips it. Use hosted egress for a sandbox that has to follow the spec.

A kit that **requires** a capability marked "no" or "later" fails, with its `type@version`, before
anything is created. An optional one is skipped, with a warning when `kit.showWarnings` is on (or
with `-D`).

A required `credential@1` whose secret isn't set fails the create (or `kit add`) too, naming the
`bento secret set` command to run, as the spec requires. sbx warns
(`WARN: required credential not found for service SERVICE`) and the kit's requests go out without
it. Docker's published agent kits mark their credentials optional, so this doesn't stop them.

Capability groups (spec §7.1.1) are applied whole or not at all. smolbento rejects a group when one
of its members is a capability marked "no" or "later", or, for a sandbox that won't be hosted, a
`network-policy@2` entry with method or path rules. A rejected optional group is skipped, and its warning names the member. A rejected
required group refuses the kit, naming the member the same way. That static list is smolbento's
only selection answer. A member that is accepted but can't be applied later is skipped on its own,
not with its group: an optional credential with no secret set, an `agent-context` version the
sandbox doesn't use, or a skill with no skills directory. smolbento doesn't keep selection records,
so the spec's `selection` observation isn't available. `declarationBlocks` are accepted and not
used.

Each declared capability version is its own request (spec §7.1.2). A kit declaring both
`network-policy@1` and `@2`, anywhere in its descriptor, is refused: the spec makes them exclusive.
The spec's own validator accepts the pair and merges it. `agent-sessions@1` and `@2` are exclusive
too, within a kit and across the kits of a sandbox. For `agent-context`, smolbento uses one version
per sandbox, the explicit "accept one version" policy §7.1.2 allows: `@2` unless a kit requires
`@1`. An optional request for the other version is skipped; a required one refuses the kit. A
capability `type` must read `<namespace>/<name>@<version>` (spec §7), or the kit is refused, even
for an optional entry.

| Capability | sbx (local) | smolbento |
|---|---|---|
| `network-policy@1`, `@2` | Yes | Yes, source `kit`. Install-phase rules apply while they're in the policy: from create (or `kit add`) until its install steps are done, when they're removed, before the workload's entrypoint starts. A start removes any an interrupted create or `kit add` left. An install-phase CIDR deny stays enforced for the sandbox's life (smolvm takes CIDR denies only at create; create prints a note), though `policy ls` doesn't show it after install. `@2` method and path rules are enforced on hosted sandboxes ([Request rules](network-and-secrets.md#request-rules)), with paths matched in exact case. Where a sandbox won't be hosted (`network.egress=smolvm`, install-only credentials, no service manager), a kit requiring them is refused. Optional ones there: allow rules cover the whole host, and deny rules with methods or paths are dropped (the skipped line says how many) |
| `credential@1` | Yes | API keys: yes, through your secrets. OAuth with `passthrough: true`: yes (the agent's own login keeps its tokens in the sandbox). OAuth without passthrough: its API key part binds; logins happen inside the sandbox. An inject-only credential (no `name`) adds no variable on a hosted sandbox; with `network.egress=smolvm`, and during install for an install-only one, `SBX_KIT_<SERVICE>` holds smolvm's placeholder (smolvm's CLI gives every credential a variable) |
| `port@1` | Yes | Yes, on `127.0.0.1` |
| `volume@1` | Yes, removed with the sandbox; no retained volume storage to list or remove | Differs from the spec, which keeps volumes across delete and create: smolbento keeps them on the sandbox's disk, so `rm` and `reset` remove them, and `size` is ignored. Kept across stop and start; each fork gets a copy. The path is cleaned (`.`, `..`, doubled `/`); one holding `:` is refused, because smolvm reads it as host:guest (the spec allows it) |
| `resources@1` | Limited (no GPU) | CPUs and memory: the largest any kit states, so a mixin never lowers the workload's; your `--cpus` and `--memory` still win. GPU ignored |
| `lifecycle@1` | Yes | Yes: install steps on first start, startup steps on every start. `interactive` ignored, but two entries declaring it are refused, as are two writing one file path (`kit A … and kit B … both declare file PATH`, naming each entry; spec `lifecycle@1/shared-paths-avoided`, selected groups included). A v3 install step's clean environment also keeps `USER`, the proxy variables and the CA-bundle variables (when set), as sbx's does, so downloads work behind a proxy and with smolvm's CA; the spec's baseline (`lifecycle@1/hook-env-restricted`) has only `PATH`, `HOME`, `HOSTNAME`, `TERM`, `PWD`, `OLDPWD`, `SHLVL` and `_` |
| `agent-context@1`, `@2` | Yes. In 0.54 a mixin's `@2` text is listed in the index, as for `@1` | Yes, in the same places (see below) |
| `sbx@1` | Yes | Yes: the workload's command is the agent (see below) |
| `git-identity@1` | Yes | Yes: your `git config user.name/email` |
| `long-running@1` | Yes | Yes: no auto-stop when the last session ends |
| `privileged@1` | Yes | Accepted, with no effect of its own: a kit's steps can already run as root (`user: "0"`), so smolbento passes no extra flag |
| `dockerd@1` | Yes | Yes: dockerd starts before startup steps, waited for up to 60 s. Elevation needs nothing extra: smolbento starts dockerd as root, and a kit's steps can run as root (`user: "0"`). Granted without asking while `docker.enabled` is on (`tck: dockerd@1/explicit-consent` is a SHOULD); with it off, a required one is refused and an optional one skipped |
| `agent-sessions@1`, `@2` | Declaration only (`@2` not measured) | Declaration only; the two are exclusive |
| `host-mount@1` | Yes | Yes: a directory on your machine, shared by the kit's sandboxes and kept after `rm` (see below). A path holding `:` is refused, because smolvm reads it as host:guest (the spec allows it) |
| `ssh-agent@1` | Yes | Yes, with `sign` and `authenticate` limits, served by a service unit ([SSH agent](#ssh-agent)) |
| `agent-skills@1`, `agent-skill@1` | Yes | Yes ([Skills](#skills)). `kit add` refuses a kit with either, as it does `host-mount@1`. `agent-skill@1` with `name: null` means no name |
| `kit-registry@1` | Approved builder kits only | No |
| `agent-interactive-sessions@1`, `usb-device@1` | No | No |
| `kvm@1`, `auto-restart@1`, `open-url@1`, `docker-auth@1` | Not measured | No |

### What works as in sbx

- A workload kit's command runs as the image's `USER` (root if none), under `/bin/bash` so
  `BASH_ENV` is sourced, in the workspace path rather than `WORKDIR`. A sandbox without a workspace
  works in the image's `WORKDIR` (spec `sbx@1/workspace-at-workdir`), else `/home/agent/workspace`. `bento exec` uses the same
  user. Without `/bin/bash` the error is `executable file '/bin/bash' not found` (exit 127).
  smolvm maps the workspace to the image user so it can write it. An image with no `ENTRYPOINT`
  or `CMD` is refused at create and by `kit validate`.
- A v3 workload's `ENTRYPOINT` + `CMD` also run at every boot, as the image user, as the kit
  spec's default launch mode says (the machine's command; smolvm keeps the machine up after it
  exits). It waits, in `sh`, until the start's install steps, files, agent context and startup
  steps are done. Not measured against sbx. `bento run` is unchanged: an interactive session through `exec`.
- `${{ kit.env.HOME }}` is the image's `ENV HOME`, else root's `/root` or `agent`'s `/home/agent`.
  For any other image user it's an error: the spec expands it at create, on the host, and that
  user's home is only in the image's passwd file, which smolvm reads in the guest. sbx not measured.
- Install steps run as root in the image `WORKDIR` (`/` otherwise); one that names no user gets
  the image user's `HOME` (spec `sbx@1/honors-image-user`; sbx not measured). After the steps, kit files
  and agent context, at create and `kit add`, files owned by root in that home go to the image user and its group (not
  for a root image user, nor for a home the user doesn't own, such as `nobody`'s `/`), so a step's
  `~/.npm` or `~/.cache` stays writable. Startup steps and kit
  files default to `agent`. v3 install steps get a clean environment: `PATH`, `HOME`, `USER`, `TERM`,
  the proxy and CA variables, and the step's own `env`. v3 startup steps and all v2 steps get the
  full sandbox environment, except that no install step sees a runtime-only credential's variable,
  a v2 kit's included (v2 credentials are runtime-only), as spec `credential@1/phase-scoped` says
  (sbx not measured).
- Startup steps block, in kit order. A failure is a warning with the log's last lines
  (`a kit startup step failed (kit startup exited with code N); starting anyway`), and the start,
  create or `kit add` goes on, as in sbx 0.51 (sbx's wording not measured). `background: true`
  steps start in place and are only logged if they fail. A blocking step that never ends holds the
  start (no timeout). The log is `/var/log/sbx-kit-startup.log`; sbx 0.51 also keeps install logs at
  `/var/log/sbx-kits/<kit>/install-<n>.log`, which smolbento doesn't.
- An optional kit argument used with no value and no default is an error
  (`create-phase kit arg "x" has no resolved value`). `--kit-arg x=` sets it empty. `--kit-arg`
  without a kit is an error. A `KIT.NAME` value for a kit not in the set is ignored. Unquoted
  numbers and booleans in `default:` and `enum:` become strings. A v3 argument with `env:` is
  exported under that name whenever it has a value (defaults and empty values count; no value
  exports nothing). The name may be `PATH`. A later kit's value and your own `-e` still win.
  A `buildSecret` argument is the build's alone (spec §6.2): `--kit-arg` and references to it fail
  as for an undeclared argument, and nothing is exported for it. A local kit's build gets no
  secrets yet, so a recipe step that requires one fails.
- References in a capability's config are replaced before the config is read (spec §6), so they
  work in every field, numbers included. Every such config is replaced and checked at create, an
  optional one too, even when the capability is then skipped, as the spec says. So a reference
  with no value fails the create there as well. Capabilities of types smolbento doesn't support
  are left as written.
- For `create REF`, a bare or dotted word is an agent name even when a directory of that name
  exists: `bento create alpine` fails with `unknown agent "alpine"`, `bento create .hidden` with
  `unknown agent ".hidden"`. `a/b` is a registry reference even if the directory exists. For
  `--kit`, `kit validate|inspect|add` and an environment file's `kits:`, an existing path is a
  local kit without `./` (in an environment file, relative to the file). Otherwise a local kit is
  a path (`.`, `..`, `./kit`, `../kit`, `/abs/kit`), and a registry reference has a `/`. With no
  such directory, `--kit alpine` fails with
  `kit reference "alpine": not a local path and does not look like a registry reference`. ZIP kits
  and `git+` sources are refused. All measured on v0.53.0.
- Versions in `provides: [name@1.2.0]` and `requires: ["name >= 1.0"]` follow the spec's version
  grammar. sbx's agent kits provide their name at their version, so `requires: [claude]` works on
  `claude`.
- Composition errors use sbx's texts, with kits named as typed. They are
  `resolve: the kit set is not coherent:` with one `  - <problem>` line each,
  `resolve: dependency cycle among ./a, ./b`, and `kit ./x is listed more than once`.
- `kit inspect` and `kit validate` print sbx's summary (`Name:`, `Kind:`, `Schema:`, `Policies:`,
  `Credentials:`, `Commands:`) and `✓ <ref> — valid`. `kit inspect --format json` is the
  v2-shaped descriptor; `kit validate --json` is `{reference, kind, valid, warnings}`.
- `policy ls` shows kit rules as one `kit:<sandbox>` policy per sandbox (source `kit`), holding one
  `kit:<sandbox>` rule. `policy rm`
  can't remove them; deny a host instead.
- Agent context goes in the agent's file in the workspace's parent directory, inside the sandbox
  only: `CLAUDE.md` (claude), `GEMINI.md` (gemini), `AGENTS.md` (others). When kits name files
  with `directory` and `filename`, it goes in each of those instead, a mixin's too, following
  the spec. `kit add` of a kit that names a file needs a recreate. Both layouts match sbx 0.54
  ([Kits](kits.md#agent-instructions-from-kits)).
- A kit's network hosts follow the spec: `*` means everything, as `**` does, a v2 kit's
  `permissions.network` too (only `bento policy allow` refuses a bare `*`, as sbx does). A v2
  kit's resources, network, ports and volumes are read as their v3 capabilities, so their errors
  use v3's names (`transport` for a port's `protocol`).
- A credential's `inject` `scheme` is presented by smolvm, in v2 and v3 kits alike: `bearer` is
  `Authorization: Bearer %s`, and `basic` (which needs a `username`) sends the credential as the
  basic-auth password. smolvm can't present other schemes, so a kit naming one is refused when it
  loads, as is one setting both `scheme` and `format`. A `network-policy@2` entry is a host string or an object,
  and its objects are checked as the spec says: an empty `methods` or `paths` list, `paths` without
  `methods`, a lowercase method, `ANY` beside another method, a path not starting with `/`, or a
  pattern in a bounded allow entry is an error.
- Docker's published agent kits offer both `agent-context` versions as optional, so they get `@2`;
  `docker.io/sbx/amp` requires `@1` and gets that.
- Every agent file starts with smolbento's own short guidance (sbx's is a long platform preamble)
  and is written even when no kit has text. The spec's size budget applies to the combined text: a
  warning above 64 KiB, a refusal above 512 KiB. smolbento counts the kits' text bytes, as it
  builds no descriptor. A file that would land in a mounted workspace is refused when a required
  `agent-context` asks for it (an undirected ask counts toward the first file), else skipped with
  a warning. A kit's `agent-context` is refused at load for a `directory` without a
  single-component `filename`, an `@2` entry with neither a `filename` nor a nonempty `content`,
  and (v3 kits) a mixin's `filename` without a `directory`; Docker's published agent kits meet
  all three.
- A `host-mount@1` directory is made under `~/.local/share/smolbento/kit-host-mounts/`, keyed on the
  kit that declares it (a mixin's own, not the workload's) and the path
  ([Kits](kits.md#kit-host-mounts)). Sandboxes of the same kit share it, and `rm` keeps it.
  `--mount HOST:SANDBOX_PATH` and `sbxenv.yaml` `mounts:` replace it, at create only, with sbx's
  errors (`--mount "X" requires HOST:SANDBOX_PATH`, `HOST "X" does not exist on the host`,
  `no kit declares host-mount@1 at "PATH"`). Two kits declaring storage at one path fail with
  `kits A and B both declare storage at PATH; a host mount has one owner`.

### Differences

| Area | sbx | smolbento |
|---|---|---|
| Building local v3 kits | BuildKit on your machine | BuildKit in a hidden `_builder` sandbox; no Docker needed locally. It never gets your secrets. Base images that need a login pull with `secret set --registry` credentials: the builder gets a short-lived pull token for the `HOST/<repo>` references in the descriptor, reaches those registries whatever the policy, and is recreated when the registry set changes. A build reaching a stored-login registry without naming `HOST/<repo>` fails with `502 credential unavailable`. Docker Hub logins don't apply yet |
| Where a kit sends a secret | Any host the kit names, after you approve | A built-in service's secret goes only to that service's hosts (else the kit is refused). A custom service's can go anywhere, with a note at `create` and `kit add` |
| Install-only credentials | Not injected after install; requests go out without the credential | The sandbox restarts once after install without them; later requests to their hosts get `502` |
| OAuth credentials | Passthrough and sentinel tokens | Passthrough. A sentinel-token credential (`claude`'s claude.ai login) binds its API key; without one, the login happens inside the sandbox and its tokens stay there (sentinel tokens need smolvm support) |
| Method and path rules | Enforced (`403` outside the rule) | Enforced on hosted sandboxes, with the caveats in [Request rules](network-and-secrets.md#request-rules) (HTTP/1.1 only, plain HTTP refused). A sandbox that won't be hosted refuses a kit requiring them |
| `kit validate` on registry references | Refused: "OCI references are not supported for validation" | Pulled and validated |
| `kit add` | Recreates the container; refuses v2 kits with files and v3 mixins on a v3 workload; asks before opening network access, no skip flag | Applies to the running sandbox, files and deny rules included. Image layers, credentials, ports, volumes, resources, environment variables and `long-running` need a recreate (`recreate required`). Asks before opening network access; `-y/--yes` skips it. A new startup step that fails only warns |
| `--offline` on `kit inspect`/`validate` | Skips the daemon policy; local directory or ZIP only; v3 source directories refused | Skips the source policy (`kit.allowLocalKits` included). Local v2 kits and Smolfiles only. Registry references and v3 source directories are refused. `validate` of a v2 workload whose command comes from its image is refused too. No ZIP or git references |
| `kit inspect` output | Summary table; `--format json` is the v2-shaped descriptor | Same shape, plus `--format yaml` and `--json`. The table adds `Capabilities:`, Source, Digest, Provides, Requires, Integrates, Conflicts, Credentials (each service and where its secret goes), and Args when present; JSON and YAML carry these under a `smolbento` key. `--kit-arg` is checked but not substituted into the output |
| `kit pack`, `kit push` | v1 and v2; v3 refused (`unsupported schemaVersion "3" (supported: [1 2])`) | v2 only (v1 isn't loaded); v3 refused with sbx's message. A kit with `files/workspace` is refused (sbx's mapping isn't measured) |
| Kit archives | `kit pack`'s ZIP and pushed layer are byte-stable | Deterministic but not byte-identical (Go and Rust deflate differ), so each tool gives the same kit a different digest. The ZIP stores entries uncompressed |
| `kit push` | HTTPS only; every push attaches a provenance referrer | Plain HTTP for loopback registries. No provenance yet. Prints `Pushed REF (sha256:…)`. Needs a tag. Logs in with `bento secret set --registry` credentials, else the host's docker login |
| `kit pull` | Saves the files layer as `<repo>-<tag>.tar.gz` | With a digest, the default name is `<repo>-<first 12 hex>.tar.gz` (sbx's not measured). Other artifacts, including v3 image kits, are refused (`… is not a v2 kit artifact`). `kit.allowedSources` applies to `pull`, not `push` |
| `kit sign`, `kit verify`, `kit push --sign` | Sigstore bundles as `application/vnd.docker.sandbox.kit.signature.v1` referrers; keyless (Fulcio and Rekor) or `--key` (unencrypted PEM, no Rekor upload) | Same bundles and referrers, made and checked by `cosign` (must be on PATH; `--key` PEM is imported into a private temp directory). Registries without the referrers API get the `sha256-<hex>` tag index, which sbx reads. More below. |
| `kit validate` output | `✓ <ref> — valid`; `--json` is `{reference, kind, valid, warnings}` | Adds `--format table\|json\|yaml`. A failure with `--json` or `--format json\|yaml` prints the object with `valid: false` and `errors: [...]` on stdout and exits 1; table output prints the plain error |
| The name `docker` | A registry ref (the `docker` image) | The shipped Docker kit. Write `docker.io/library/docker` for the image |
| Docker in the sandbox | Run by the `-docker` images | The shipped `docker` kit, one `dockerd@1` request, is added to Docker-enabled images (or `--kit docker`). smolbento starts dockerd before startup steps and fails the start if it doesn't answer within 60 s (`/var/log/dockerd.log`). smolvm's Docker Engine API (`smolvm engine`) isn't used: its containers are host machines that can bind any host path |
| A kit providing `docker` | n/a | Doesn't replace the shipped `docker` kit or stand in for the engine: declare `dockerd@1` (`autoStart: false` to start dockerd yourself) |
| v3 mixins on built-in agents | Allowed since sbx 0.53 (earlier: `no workload kit in the set`) | Allowed |
| v2 and v3 kits in one sandbox | Refused: `cannot mix v3 kits with v1/v2 kits in one sandbox; compositions are single-format (v3: …; v1/v2: …)` | Same message, at create and by `kit add`. |
| v2 mixins on built-in agents | Refused, since the agents are v3 kits (sbx 0.53) | Refused, the same way. The shipped `docker` kit and Smolfiles go with either format |
| Published v2 kits | OCI artifact: config is the spec, one layer is `files/` as tar.gz under `home/agent/` | A files-layer entry outside `home/agent/` is refused (other mappings unmeasured). The agent is named after the reference (`gemini-kit`), not the kit |
| Retired agents | `gemini` (0.53) refused for new sandboxes, pointing to `antigravity` and `docker.io/sbx/gemini-kit` | Same wording |
| Self-referencing kit variable | `PATH: /opt/kit/bin:$PATH` gets the image's PATH | Same for `$NAME` and `${NAME}` in NAME's own value (read at create; smolvm doesn't expand variables yet). `${PATH}` in another variable stays as written; sbx substitutes the kit's unexpanded PATH |
| `--mount` with a file as `HOST` | Not measured | `workspace X is a file; …` (smolvm mounts directories only) |
| `--mount` path no kit declares | `request failed: 400 Bad Request: no kit declares host-mount@1 at "PATH"`, after the image is prepared | Same text without the prefix. A local kit is still built first; a published kit's image isn't prepared |
| Host-mount location | `~/Library/Application Support/com.docker.sandboxes/sandboxes/kit-host-mounts/` on macOS | Under smolbento's data directory, so sbx's directories aren't shared |
| Loopback registries | HTTPS only | Plain HTTP for `localhost`, `127.0.0.0/8` and `::1`, as in Docker |
| Smolfile kits | None | A Smolfile defines its own workload; one without a command keeps the shell agent's |
| Agent context file | Starts with a long platform preamble | Starts with a one-line sandbox note, then kit text and the index |
| Mixin context with no agent file in the workload | Dropped silently | Dropped, with a warning when `kit.showWarnings` is on |
| Startup log lines | `ok /etc/durable-startup.d/…` | `ok /etc/smolbento/startup.d/NN-<kit>.sh hook N`, one per step and start |
| v2 kits' `requires.agent` | A base-agent name | A capability name with no version, so any version meets it (v2 has no versioned provides) |
| `kit add` and earlier kits | Recreates with the whole set | Checks the new kit against the provides recorded at create, with versions. Older records hold bare names, which meet only unconstrained requires. Errors name kits by kit name. Earlier kits' requires and conflicts aren't rechecked |
| Kit settings | Also `kit.requireSignature`, `kit.trustedSigners`, `kit.ignoreTransparencyLog`, `kit.allowExtractedAgents` | All but `kit.allowExtractedAgents` (not implemented) |
| Default kit sources and signers | `kit.allowedSources` `["docker.io/","dhi.io/"]` (0.53); `kit.trustedSigners` `*@docker.com` | `kit.allowedSources` is `["docker.io/","ghcr.io/pelotech/smolbento/"]`: `ghcr.io/pelotech/smolbento/` replaces `dhi.io/`. `kit.trustedSigners` also has smolbento's release workflow (GitHub OIDC), so smolbento's own kits load and verify with default settings |
| Bare kit names | None for published kits | `nix` names `ghcr.io/pelotech/smolbento/kits/nix:latest` and loads as a registry kit (source and signature checks apply). `docker` is the shipped kit |
| `kit.requireSignature` | Enforced wherever a kit loads (not `kit pull` or `--offline`): a registry or local kit needs a signature verifying against `kit.trustedSigners` (`{"key": PATH}`, or keyless `issuer`/`identity`, each also `…Regexp`). Success: `✓ REF — signature verified (IDENTITY via ISSUER)` on stderr | Registry kits only, checked on the resolved digest. Built-in agents' kits (`claude`: sbx publishes them unsigned) and shipped kits (`docker`) are exempt. More below. |

- **`kit sign`, `kit verify`, `kit push --sign`:** A local directory (`kit.sig.bundle`) and
  `--tlog-upload=false` are refused (exit 2). `verify --key` checks no transparency log entry. `push
  --sign` attaches no provenance. `sign` prints `Signed REF`; keyless `verify` prints the identity
  and issuer you gave, not the certificate's
- **`kit.requireSignature`:** Local directories and Smolfiles are refused (`… is not signed`, or `…
  isn't supported yet` with a `kit.sig.bundle`). The success line names the matching signer entry,
  not the certificate's identity

### Not measured against sbx yet

- How float or unusual literals (`1.0`, `0x10`, `True`) become argument strings (smolbento writes
  `1.0` as `1`).
- A v2 or startup step run as a non-root user keeps the sandbox environment, except `HOME`, `USER`,
  `LOGNAME` and `SHELL`, which are that user's (via `runuser`, or `su` without `-`, which resets
  them).
- Which `agent-context` version sbx applies when kits offer both, and its layout for inline
  `@2` text.
- `integrates` and `conflicts` error texts, and a published kit whose provides have no version.
- An optional argument a kit declares but doesn't use, with no value and no default.
- A v2 kit's `files/home` and `files/workspace` are copied as they are: `${{ kit.args.* }}` and
  `${{ kit.env.* }}` in them stay text. In `setup` hooks and files, and in resources, network
  hosts, ports and volumes, they're replaced. In
  `setup.files`, `${WORKDIR}` in the content and a relative path mean the workspace.
- A published kit's host-mount identity: keyed on `<registry>/<repository>`; sbx's choice isn't
  measured.
- The kits index after hand edits (a removed or duplicated marker, or text inside the block).
- Also: a v3 mixin's context when the workload has an agent file, a hanging startup step, `setsid`
  in the other `-docker` images, `git-identity` without a host identity, `kit add` of the same kit
  twice, auto-stop timing, `policy ls --wide` columns, and the `kit validate` failure JSON.
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
