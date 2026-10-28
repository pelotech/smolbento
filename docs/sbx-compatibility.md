# sbx compatibility

smolbento accepts Docker Sandboxes command lines flag for flag (sbx v0.49 reference). Anything not
implemented yet still parses, then exits with status **2** and a message saying so, so scripts fail
clearly rather than doing something different.

## Works today

`run`, `create`, `exec`, `ls`, `start`, `stop`, `rm`, `prune`, `reset`, `cp`, `version`,
`completion`, `diagnose`, `settings`, `policy`, `secret`, `ports`, `env create|run|exec|rm`
(see [Environment files](#environment-files)), `run/create --deny-network`
(per-sandbox deny rules, as in sbx), `run/create --clone`, kits (`run/create --kit`, `--kit-arg`,
`--kit-args-file`, `kit inspect`, `kit validate`, `kit add`; see [Kits](#kits)) and
`policy ls --source`.
`fork` is a smolbento extension: sbx has no fork (its `template save` saves the disk only).
`daemon` is accepted and does nothing: smolbento has no daemon.

## Parses, not implemented yet (exit 2)

| Command or flag | Planned |
|---|---|
| `policy refresh`, `secret import`, `secret set --oauth/--refresh`, `secret set/rm --registry` with `--sandbox`/`--all-sandboxes` | Not implemented |
| `policy ls --created-via/--type/--protocol/--include-inactive`, `policy check --protocol` other than `tcp` | Not implemented (`policy ls --decision` and `--source` work) |
| `kit pack`, `kit push`, `kit pull`, `kit sign`, `kit verify` | Not implemented |
| `env plan` and the `sbxenv.yaml` fields listed under [Environment files](#environment-files) | Later |
| `template`, `setup ssh`, `mcp`, `--static-mcp`, `--skills`, `skills` | Later |
| `tui` | Later |
| `--pull always\|never` | `--pull missing` works (it's what smolvm does) |
| `exec -d`, `--detach-keys` | Not supported (sbx doesn't support `exec -d` either) |

## Never (Docker Cloud only, exit 2)

`login`, `logout`, `move`, `ttl`, `attach`, `volume`, the global `--cloud` flag, and the cloud-only
`run`/`create` flags (`--allow-network`, `--image-ref`, `--platform`, `--ttl`, `--on-timeout`,
`-v/--volume`, `--new`).

## Differences you'll notice

| Area | sbx | smolbento |
|---|---|---|
| Network | Default-deny policy | Same three modes and rule syntax. Looser: `*.x.com` matches any depth (sbx: one label); wildcards inside a label (`crl*.x.com`, `?`, `[..]`) widen to `*.x.com`; ports, methods and paths aren't enforced (`policy ls --wide` shows which). `balanced` is sbx's 195 rules plus Nix caches, on any port |
| Host deny rules | Always enforced | Under allow-all, host deny rules aren't enforced (only deny CIDRs are, at create), and a host deny that a broader allow still covers isn't either; `sbt policy check` says "isn't enforced". A deny with a port isn't enforced at all (smolvm can't filter by port, and denying the host would block its other ports), except that one with exactly the same text as an allow cancels that allow; `sbt policy deny` notes this on stderr |
| Secrets | Proxy injects on the wire | smolvm substitutes on the wire; a secret's hosts, and their subdomains, are always reachable from sandboxes that bound it (`policy deny` of one is refused); new values apply on the next start |
| `secret set-custom --host` | Exact host, IP or wildcard pattern | Exact host names, or `*.domain` for every subdomain of it (not the domain itself; any depth); other wildcards are refused, and so are IPs: smolvm only substitutes secrets for host names |
| Policy changes | Live everywhere | Live, except switching a running sandbox between allow-all and a restricted mode, which applies on its next start, and deny-CIDR rules, which apply only to sandboxes created afterwards (`policy check` says so) |
| Approvals | Queue | Derived from smolvm's blocked-request (egress) log; the host is the approval id |
| Host services | Reachable per port as `host.docker.internal` when the policy allows `localhost:PORT`, live; a blocked request gets `403 Approval required…` | Works, as `host.docker.internal`, live. Differences: a `localhost` rule opens **every** port on the host's `127.0.0.1` (smolvm can't open one port yet), not `::1`; only sandboxes created while one of your `localhost` rules applied get it (others need recreating; kit rules never grant it, and `_builder` never has it); an allow-all sandbox with host access keeps it until recreated; a blocked request gets connection refused (no proxy), so no approval entry. See [Security](SECURITY.md#host-services-localhost-rules). Under allow-all the host's LAN IP is reachable, so services listening on `0.0.0.0` are reachable through it (sbx blocks it) |
| Published ports | Any host IP | `127.0.0.1` only (smolvm publishes on loopback) |
| Single-file `:ro` mounts | Supported | Directories only (smolvm mounts directories) |
| Machine names | `.` allowed | Names can't contain `--` or end in `-` (smolvm rules) |
| Daemon | `sandboxd` | None; each command talks to smolvm directly |
| Clone transport | A git daemon in the sandbox on a published port; the remote URL changes on every start, and fetch fails while the sandbox is stopped | No daemon or port: the `sandbox-<name>` remote's `uploadpack` runs `smolbento _upload-pack <name>` (so `smolbento` must be on `PATH`), which runs `git-upload-pack` in the sandbox through `smolvm machine exec`. `git remote -v` shows a placeholder `file:///sbt/<name>` URL |
| Tags from the sandbox | The `sandbox-<name>` remote follows tags | The remote has `tagOpt = --no-tags`; only branches come back |
| Fetch on exit | None | `sbt run` fetches `sandbox-<name>` when the agent exits (setting `clone.fetch-on-exit`, default `true`) |
| Object checking | Plain `git fetch` | The fetch on exit runs with `fetch.fsckObjects=true`; manual `git fetch` is unchanged, and your repo config isn't touched beyond the remote |
| Fetch from a stopped sandbox | Fails | Starts the sandbox, fetches, stops it again |
| Linked worktrees as the clone source | Not supported | Supported; the clone checks out the worktree's branch, or its commit when detached |
| `policy ls --wide` | sbx's wide layout | Columns differ: a NAME column is added; sbx's other wide columns aren't shown |
| Install-phase kit rules in `policy ls` | Not listed after create | Never listed, also while a create is still installing (they're in effect then, but `policy ls` doesn't show them) |
| `--version` | `sbx version vX` | `sbt --version` prints `sbt X`; `sbt version` also shows the smolvm version |

## Environment files

`env create`, `env run`, `env exec` and `env rm` read `sbxenv.yaml` as sbx v0.49.2 does, for the
fields smolbento supports. These exit 2 and name the field or command: `env plan`, `lifecycle`,
`bindings`, `registries`, `mcp`, `mounts`, `sandboxOptions.profile|skills|display|gpu|usb|
writableEnvFiles`, and `pullPolicy` other than `missing`.

| Area | sbx | smolbento |
|---|---|---|
| Approval | Asks until you approve once, then remembers | Nothing is remembered: `env create` and `env run` ask on every call; `--force` approves one call (scripts, no terminal) |
| Plan diffs | The summary shows changes against the last apply | No diff; the summary lists what the call will do |
| `refresh`, `backend` on a secret | Used | Accepted, no effect: smolbento resolves at every start |
| `--skip-host-commands`, `--prune-bindings` | Skip lifecycle and MCP commands; remove bindings | Accepted, no effect (there are no lifecycle commands or bindings yet). Secret `command:` sources run either way, as in sbx |
| Unknown secret service | Accepted by `env plan` | Refused at create, with the error `sbt secret set` gives |
| `secret ls` with registry credentials | `SECRET` shows the first characters | A separate `SCOPE TYPE NAME SECRET` table; `SECRET` is always `(stored)`, never part of a value. No `--json` on `secret ls` yet |
| Workload kit as `agent` | The kit whose name equals `agent` | A local kit is matched by its directory name, a registry kit by the last part of its repository name |
| Secret `command:` source | Runs on the host | Runs from a fresh temporary directory, so a relative helper path fails (also for `secret set --command`) |
| `env run` on an existing sandbox | Passes `env`, applies nothing else | Same |
| Kits that can't be loaded | Checked before secrets are stored | A local kit path that doesn't exist, a `.zip` or a `git+` source is refused before secrets are stored. A registry kit isn't checked without the network: one that can't be pulled fails after the secrets were stored; `env rm` removes them |

## Sandbox environment

As in sbx, every sandbox gets these variables, set at create (`-e`, so every process sees them,
agent and `exec` alike; your own `-e` wins). None of them holds a secret value.

- `SANDBOX_NAME`, `SANDBOX_VM_ID` (the name) and `SANDBOX_ID` (a new UUID on every create). A
  `fork` gets its own name and a new id, not its parent's.
- `WORKSPACE_DIR`: the host path of the primary workspace; the guest workdir when mountless.
- `SBX_AGENT`: the preset or kit name. `IS_SANDBOX=1` for the `claude` preset.
- `SBX_CRED_<SVC>_MODE`: `apikey` when the service's secret is bound at create, else `none`.
  `shell` gets all eight services and `claude` only `ANTHROPIC`, as in sbx; the other presets and
  kits get none, even one named `claude` or `shell` (sbx's set for them hasn't been compared).
- `TZ` is passed from the host's `TZ` in TTY sessions (`run`, `exec -it`) only when it's set; sbx
  derives one when it isn't.

Left out: `*_API_KEY=proxy-managed` and the `GH_TOKEN` sentinel (smolvm uses its own
placeholders), `MCP_*` (no MCP gateway), `GIT_CONFIG_*`, the proxy specifics
(`PROXY_CA_CERT_B64`, `JAVA_TOOL_OPTIONS`, `NODE_USE_ENV_PROXY`), `CLAUDE_ENV_FILE`,
`SSH_AUTH_SOCK*`, `WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR`, the PAM-style startup-hook environment and
`LC_ALL=C` for startup hooks. Kits relying on those see them unset.

## Kits

smolbento implements the [sandbox kit spec](https://github.com/docker/sandbox-kit-spec) at commit
`198d50b5fd57b216b511fd7200010a3636cb3f01` (`SPEC_COMMIT` in the code). v3 is still experimental
upstream. v2 `spec.yaml` kits are read into the same model, and smolvm Smolfiles work as kits too.

What each capability does in smolbento. A kit that **requires** one marked "no" or "later" fails
with its `type@version` before anything is created; an optional one is skipped with a warning.

| Capability | sbx (local) | smolbento |
|---|---|---|
| `network-policy@1`, `@2` | Yes | Yes: per-sandbox rules with source `kit`. Install-phase rules are in place from the sandbox's creation through its first start's setup and install steps, removed when install finishes, and never used by later starts. An install-phase deny of a CIDR is the exception: smolvm takes CIDR denies only at create, so it stays enforced for the sandbox's life (create prints a note) though `policy ls` doesn't show it. `@2` method and path rules aren't enforced, so a kit that requires them is refused |
| `credential@1` | Yes | API keys: yes, through your secrets. OAuth with `passthrough: true`: yes (the token and resource hosts are allowed; the agent's own login keeps its tokens in the sandbox). OAuth without passthrough: no |
| `port@1` | Yes | Yes, on `127.0.0.1` |
| `volume@1` | Yes, removed with the sandbox | Yes, on the sandbox's disk; removed with the sandbox (`rm`, `reset`, recreate), kept across stop and start; each fork gets its own copy |
| `resources@1` | Limited (no GPU) | CPUs and memory; GPU ignored, as in sbx |
| `lifecycle@1` | Yes | Yes: install steps on the first start, startup steps on every start (see below). `interactive` is ignored, as in sbx |
| `agent-context@1`, `@2` | Yes | Yes, in the same places as sbx (see below) |
| `sbx@1` | Yes | Yes: the workload's command is the agent, run as in sbx (see below) |
| `git-identity@1` | Yes | Yes: your `git config user.name/email` |
| `long-running@1` | Yes | Yes: no auto-stop when the last session ends |
| `privileged@1` | Yes | Yes |
| `agent-sessions@1` | Declaration only | Declaration only |
| `host-mount@1` | Yes | Later (Phase 5) |
| `ssh-agent@1` | Yes | Later (Phase 5, with `setup ssh`) |
| `agent-skills@1`, `agent-skill@1` | Yes | Later (Phase 5, with `--skills`) |
| `kit-registry@1` | Approved builder kits only | No |
| `agent-interactive-sessions@1`, `usb-device@1` | No | No |

What works as in sbx:

- **Launch.** A workload kit's command runs as the image's `USER` (root when it has none) under
  `/bin/bash`, so `BASH_ENV` is sourced, in the workspace path rather than `WORKDIR`. `sbt exec`
  uses the same user. An image without `/bin/bash` fails with `executable file '/bin/bash' not
  found` (exit 127). The image user gets your uid so it can write the workspace; a numeric `USER`
  runs as the account that has that uid. A workload whose image declares no `ENTRYPOINT` or `CMD`
  is refused at create and `kit validate`.
- **Hooks.** Install steps run as root in a workload kit's image `WORKDIR` (`/` otherwise);
  startup steps and kit files default to `agent`, not the image user. v3 install steps get a clean
  environment: `PATH`, `HOME`, `USER`, `TERM`, the proxy and CA variables, and the variables the
  step declares in `env`. v3 startup steps and all v2 steps get the sandbox's full environment.
- **Startup steps** block, in kit order, and a failing one fails the start
  (`kit startup exited with code N`); one marked `background: true` is started at its place and
  only logged if it fails. A blocking step that never finishes holds up the start (no timeout).
  The log is `/var/log/sbx-kit-startup.log`. If a startup step fails during create, the sandbox is
  still created, with sbx's `StartRuntime after create failed` warning, and left stopped; later
  starts fail until the step succeeds.
- **Kit arguments.** An optional argument a kit uses with no value and no default is an error
  (`create-phase kit arg "x" has no resolved value`); `--kit-arg x=` sets it to empty.
  `--kit-arg` without a kit is an error, and a `KIT.NAME` value for a kit that isn't in the set
  is ignored. Unquoted numbers and booleans in `default:` and `enum:` become strings.
- **Kit references.** A bare word is an agent name, never a kit, even when a directory of that name
  exists, and so is a dotted one: `sbt create alpine` fails with `unknown agent "alpine"`,
  `sbt create .hidden` with `unknown agent ".hidden"`, and `--kit alpine` with
  `kit reference "alpine": not a local path and does not look like a registry reference`. A local
  kit is a path (`.`, `..`, `./kit`, `../kit`, `/abs/kit`); a registry reference has a `/`
  (`docker.io/acme/kit:1`). ZIP kits and `git+` sources are refused.
- **Versions.** `provides: [name@1.2.0]` and `requires: ["name >= 1.0"]` follow the kit spec's
  version grammar. The agent presets provide their name at their image tag's version, so a v2
  mixin's `requires.agent: claude` works on `claude`.
- **Composition errors** use sbx's texts and name each kit by its reference as typed:
  `resolve: the kit set is not coherent:` followed by one `  - <problem>` line per problem,
  `resolve: dependency cycle among ./a, ./b`, and `kit ./x is listed more than once`.
- **Unbound credentials.** A required kit credential whose secret isn't set doesn't stop the
  create: it warns `WARN: required credential not found for service SERVICE` and the kit's
  requests go out without it. smolbento adds a line with the `sbt secret set` command to run.
- **`kit inspect` and `kit validate`** print sbx's summary (`Name:`, `Kind:`, `Schema:`,
  `Policies:`, `Credentials:`, `Commands:`) and `✓ <ref> — valid`; `kit inspect --format json` is
  the v2-shaped descriptor and `kit validate --json` is `{reference, kind, valid, warnings}`.
- **Kit rules in `policy ls`** are one `kit:<sandbox>` row per sandbox (source `kit`), whatever
  kits made them. They can't be removed with `policy rm`; deny a host instead.
- **Agent context** goes in the agent's file in the parent directory of the workspace path, inside
  the sandbox only (nothing is written on your machine): `CLAUDE.md` for claude, `GEMINI.md` for
  gemini, `AGENTS.md` for the others, or the file a workload kit's own `agent-context` names, with
  its text appended. A v2 mixin's text goes to `kits-agent-context/<kit>.md` next to that file,
  which lists it between `<!-- sbx:kits-section start -->` and `<!-- sbx:kits-section end -->`.
- **Settings.** `kit.allowedSources` and `kit.allowLocalKits` (see
  [Configuration](configuration.md#settings)).

Differences:

| Area | sbx | smolbento |
|---|---|---|
| Building local v3 kits | BuildKit on your machine | BuildKit in a hidden `_builder` sandbox; no Docker on your machine needed. It never gets your secrets. Base images that need a login pull with your `secret set --registry` credentials, which stay on the host: the builder gets a short-lived pull token for the `HOST/<repo>` references in the descriptor as a header smolvm sets, can reach those registries whatever the policy, and is recreated when the set of registries changes. A build that reaches a stored-login registry without naming `HOST/<repo>` gets `502 credential unavailable` and fails (remove the login or name the image that way); Docker Hub logins don't apply to builds yet |
| Where a kit sends a secret | Any host the kit names, after you approve it | A built-in service's secret only to that service's own hosts (else the kit is refused); a custom service's anywhere, with a note at `create` and `kit add` |
| Install-only credentials | Not injected after install: the placeholder stays and requests go out without the credential | The sandbox restarts once after install, without them; later requests to their hosts get `502` |
| OAuth credentials | Passthrough and sentinel tokens | Passthrough only (sentinel tokens need smolvm support) |
| Method and path rules | Enforced (`403` outside the rule) | Not enforced (as for `policy allow --method/--path`); a kit that requires them is refused |
| `kit add` | Recreates the container; refuses v2 kits with files and v3 mixins on a v3 workload; asks before opening network access, with no flag to skip the question | Applies to the running sandbox, files and deny rules included. Image layers, credentials, ports, volumes, resources, environment variables and `long-running` need a recreate ("recreate required"); asks before opening network access, and `-y/--yes` skips the question. A new startup step that fails only warns |
| `kit inspect --offline`, `kit validate --offline` | Skips the daemon policy (`kit.allowedSources`, `kit.allowLocalKits`, `kit.requireSignature`); local directory or ZIP only; v3 source directories refused (no builder) | Skips the source policy, `kit.allowLocalKits` included, as sbx documents. Local v2 kits and Smolfiles only. Registry refs and v3 source directories are refused (they need the network); `validate` of a v2 workload whose command comes from its image is refused too. No ZIP or git references |
| `kit inspect` output | Summary table; `--format json` is the v2-shaped descriptor; `--kit-arg` shows substituted content | Same shape, plus `--format yaml` and `--json`. After sbx's lines the table adds `Capabilities:` (what smolbento supports), then Source, Digest, Provides, Requires, Integrates, Conflicts, Credentials (each service and the hosts its secret is sent to) and Args when present; JSON/YAML carry those under a top-level `smolbento` key. `--kit-arg` is only checked, not substituted into the output |
| `kit validate` output | `✓ <ref> — valid`; `--json` gives `{reference, kind, valid, warnings}` | Same, with `--format table\|json\|yaml`. A failure with `--json`/`--format json\|yaml` prints the same object with `valid: false` and `errors: [<message>]` on stdout and exits 1; table output prints the plain error |
| Unmeasured parts of `kit inspect`/`validate` | | Inferred, not measured against sbx: `kind` values other than `directory` (we use `file`, `registry`, `builtin`); `Schema:` for registry (`v3`), builtin (`v3`) and Smolfile (`smolfile`) kits; the network rule counts (install and runtime rules merged, hosts deduplicated) and init-file count (v2 `files/home` and `files/workspace` files included); the JSON layout under sandbox, permissions, credentials and setup; the failure object above; `Template:` shown only for a built local v3 kit |
| The name `docker` | A registry ref (the `docker` image) | The shipped Docker kit; write `docker.io/library/docker` for the image |
| Docker in the sandbox | Run by the `-docker` images | The shipped `docker` kit, first before your kits (added to Docker-enabled images, or given with `--kit docker`), so their startup steps can use Docker. Its `dockerd` step runs in the background, so a failing `dockerd` is only logged (`/var/log/dockerd.log`) and doesn't stop the start |
| v3 mixins on built-in agents | Refused (`no workload kit in the set`) | Allowed |
| Loopback registries | HTTPS only | Plain HTTP for `localhost`, `127.0.0.0/8` and `::1`, as in Docker |
| Smolfile kits | None | A Smolfile defines its own workload, so one without a command keeps the shell agent's |
| Agent context file | Starts with a long platform preamble | No preamble: only kit text and the index |
| Mixin context when the workload declares no agent file | Dropped silently | Dropped with a warning |
| Startup log lines | `ok /etc/durable-startup.d/…` | `ok /etc/smolbento/startup.d/NN-<kit>.sh hook N`, one per step and start |
| v2 kits' `requires.agent` | A base-agent name | A capability name with no version, so any version of it meets it (v2 has no versioned provides); the presets provide theirs |
| `kit add` and earlier kits | Recreates with the whole set | Matches the new kit against the provides recorded at create, with their versions; records written before versions existed hold bare names, which meet only unconstrained requires. An agent preset's own name counts as version `0` (`claude@0`), so a versioned require on it can pass at create and fail at `kit add`. Errors name earlier kits by kit name (their references aren't recorded). The earlier kits' own requires and conflicts aren't checked again |
| Kit settings | Also `kit.requireSignature`, `kit.trustedSigners`, `kit.ignoreTransparencyLog`, `kit.allowExtractedAgents` | Not yet: signatures aren't checked, and built-in agents aren't kits |

Not compared with sbx yet:

- How arguments with float or unusual literal values (`1.0`, `0x10`, `True`) become strings
  (smolbento writes `1.0` as `1`).
- A startup step or v2 step run as a non-root user: it keeps the sandbox's environment, except
  that `HOME`, `USER`, `LOGNAME` and `SHELL` are that user's (through `runuser`, or `su` without
  `-` on images without `runuser`, which resets them too).
- A v3 mixin's agent context: smolbento puts it in `kits-agent-context/<kit>.md` and the index, as
  for a v2 mixin.
- `integrates` and `conflicts` errors (texts from the kit spec's resolver), and a published kit
  whose provides have no version (read as is; it meets only unconstrained requires).
- An optional argument a kit declares but doesn't use, with no value and no default.
- The agent file's kits index after hand edits, such as a removed or duplicated marker or text
  added inside the block.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error (the message says why) |
| 2 | Not implemented yet, Docker Cloud only, or a usage error |
| other | `run` and `exec` return the agent's or command's own status |
