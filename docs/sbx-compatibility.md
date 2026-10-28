# sbx compatibility

smolbento accepts Docker Sandboxes command lines flag for flag (sbx v0.49 reference). Anything not
implemented yet still parses, then exits with status **2** and a message saying so, so scripts fail
clearly rather than doing something different.

## Works today

`run`, `create`, `exec`, `ls`, `start`, `stop`, `rm`, `prune`, `reset`, `cp`, `version`,
`completion`, `diagnose`, `settings`, `policy`, `secret`, `ports`, `run/create --deny-network`
(per-sandbox deny rules, as in sbx), `run/create --clone`, kits (`run/create --kit`, `--kit-arg`,
`--kit-args-file`, `kit inspect`, `kit validate`, `kit add`; see [Kits](#kits)) and
`policy ls --source`.
`fork` is a smolbento extension: sbx has no fork (its `template save` saves the disk only).
`daemon` is accepted and does nothing: smolbento has no daemon.

## Parses, not implemented yet (exit 2)

| Command or flag | Planned |
|---|---|
| `policy refresh`, `secret import`, `secret set --oauth/--registry/--refresh` | Not implemented |
| `policy ls --created-via/--type/--protocol/--include-inactive`, `policy check --protocol` other than `tcp` | Not implemented (`policy ls --decision` and `--source` work) |
| `kit pack`, `kit push`, `kit pull`, `kit sign`, `kit verify` | Not implemented |
| `env` (sbxenv.yaml) | Later |
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
| Host services | Reachable per port as `host.docker.internal` when the policy allows `localhost:PORT` | Not reachable yet; planned with host services. The host's localhost is always blocked. Under allow-all the host's LAN IP isn't, so services listening on `0.0.0.0` are reachable through it (sbx blocks it) |
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
| `--version` | `sbx version vX` | `sbt --version` prints `sbt X`; `sbt version` also shows the smolvm version |

## Kits

smolbento implements the [sandbox kit spec](https://github.com/docker/sandbox-kit-spec) at commit
`198d50b5fd57b216b511fd7200010a3636cb3f01` (`SPEC_COMMIT` in the code). v3 is still experimental
upstream. v2 `spec.yaml` kits are read into the same model, and smolvm Smolfiles work as kits too.

What each capability does in smolbento. A kit that **requires** one marked "no" or "later" fails
with its `type@version` before anything is created; an optional one is skipped with a warning.

| Capability | sbx (local) | smolbento |
|---|---|---|
| `network-policy@1`, `@2` | Yes | Yes: per-sandbox rules with source `kit`. Install-phase rules are in place from the sandbox's creation through its first start's setup and install steps, removed when install finishes, and never used by later starts. An install-phase deny of a CIDR is the exception: smolvm takes CIDR denies only at create, so it stays enforced for the sandbox's life (create prints a note) though `policy ls` no longer shows it. `@2` method and path rules aren't enforced, so a kit that requires them is refused |
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
  `--kit-arg` without a kit is an error. Unquoted numbers and booleans in `default:` and `enum:`
  become strings.
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
| Building local v3 kits | BuildKit on your machine | BuildKit in a hidden `_builder` sandbox; no Docker on your machine needed. It pulls base images without a registry login (kits built on `dhi.io`, like Docker's examples, don't build yet) and never gets your secrets |
| Where a kit sends a secret | Any host the kit names, after you approve it | A built-in service's secret only to that service's own hosts (else the kit is refused); a custom service's anywhere, with a note at `create` and `kit add` |
| Install-only credentials | Not injected after install: the placeholder stays and requests go out without the credential | The sandbox restarts once after install, without them; later requests to their hosts get `502` |
| OAuth credentials | Passthrough and sentinel tokens | Passthrough only (sentinel tokens need smolvm support) |
| Method and path rules | Enforced (`403` outside the rule) | Not enforced (as for `policy allow --method/--path`); a kit that requires them is refused |
| `kit add` | Recreates the container; refuses v2 kits with files and v3 mixins on a v3 workload; asks before opening network access, with no flag to skip the question | Applies to the running sandbox, files and deny rules included. Image layers, credentials, ports, volumes, resources, environment variables and `long-running` need a recreate ("recreate required"); asks before opening network access, and `-y/--yes` skips the question. A new startup step that fails only warns |
| `kit inspect`, `kit validate` | `--format`, `--offline` | Neither; `kit inspect --json` gives JSON |
| The name `docker` | A registry ref (the `docker` image) | The shipped Docker kit; write `docker.io/library/docker` for the image |
| A ref that is also a local path | Registry ref | A local kit: a ref that names a file or directory relative to the current directory loads it, e.g. `alpine` with an `alpine` directory present. Write `docker.io/library/alpine` for the registry. `docker` is always the shipped kit |
| Docker in the sandbox | Run by the `-docker` images | The shipped `docker` kit, first before your kits (added to Docker-enabled images, or given with `--kit docker`), so their startup steps can use Docker. Its `dockerd` step runs in the background, so a failing `dockerd` is only logged (`/var/log/dockerd.log`) and doesn't stop the start |
| v3 mixins on built-in agents | Refused (`no workload kit in the set`) | Allowed |
| Loopback registries | HTTPS only | Plain HTTP for `localhost`, `127.0.0.0/8` and `::1`, as in Docker |
| Smolfile kits | None | A Smolfile defines its own workload, so one without a command keeps the shell agent's |
| Agent context file | Starts with a long platform preamble | No preamble: only kit text and the index |
| Mixin context when the workload declares no agent file | Dropped silently | Dropped with a warning |
| Startup log lines | `ok /etc/durable-startup.d/…` | `ok /etc/smolbento/startup.d/NN-<kit>.sh hook N`, one per step and start |
| Kit settings | Also `kit.requireSignature`, `kit.trustedSigners`, `kit.ignoreTransparencyLog`, `kit.allowExtractedAgents` | Not yet: signatures aren't checked, and built-in agents aren't kits |

Not compared with sbx yet:

- How arguments with float or unusual literal values (`1.0`, `0x10`, `True`) become strings
  (smolbento writes `1.0` as `1`).
- A startup step or v2 step run as a non-root user: it keeps the sandbox's environment, except
  that `HOME`, `USER`, `LOGNAME` and `SHELL` are that user's (through `runuser`, or `su` without
  `-` on images without `runuser`, which resets them too).
- A v3 mixin's agent context: smolbento puts it in `kits-agent-context/<kit>.md` and the index, as
  for a v2 mixin.
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
