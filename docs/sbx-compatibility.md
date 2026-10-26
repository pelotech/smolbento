# sbx compatibility

smolbento accepts Docker Sandboxes command lines flag for flag (sbx v0.49 reference). Anything not
implemented yet still parses, then exits with status **2** and a message saying so, so scripts fail
clearly rather than doing something different.

## Works today

`run`, `create`, `exec`, `ls`, `start`, `stop`, `rm`, `prune`, `reset`, `cp`, `version`,
`completion`, `diagnose`, `settings`, `policy`, `secret`, `ports`, and `run/create --deny-network`. `daemon` is accepted and
does nothing: smolbento has no daemon.

## Parses, not implemented yet (exit 2)

| Command or flag | Planned |
|---|---|
| `policy refresh`, `secret import`, `secret set --oauth/--registry/--refresh` | Not implemented |
| `policy ls --source/--created-via/--type/--protocol/--include-inactive`, `policy check --protocol` other than `tcp` | Not implemented (`policy ls --decision` works) |
| `run/create --clone` | Later |
| `--kit`, `kit`, `env` (sbxenv.yaml) | Later |
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
| Network | Default-deny policy | Same three modes and rule syntax. Exact hosts match only that host, and `**.x.com` matches subdomains at any depth but not `x.com` (as in sbx). Looser: `*.x.com` (sbx: exactly one label) matches any depth; wildcards inside a label (`crl*.x.com`, `?`, `[..]`) widen to `*.x.com`; ports, methods and paths in rules aren't enforced. `balanced` is sbx's 195 rules plus Nix caches, on any port rather than only 443 |
| Host deny rules | Always enforced | Under allow-all, host deny rules aren't enforced (only deny CIDRs are, at create), and a host deny that a broader allow still covers isn't either; `sbt policy check` says "isn't enforced" |
| Secrets | Proxy injects on the wire | smolvm substitutes on the wire; a secret's hosts, and their subdomains, are always reachable from sandboxes that bound it (`policy deny` of one is refused); new values apply on the next start |
| Policy changes | Live everywhere | Live, except switching a running sandbox between allow-all and a restricted mode, which applies on its next start, and deny-CIDR rules, which apply only to sandboxes created afterwards |
| `--deny-network` | Applies to the sandbox | Only when the sandbox is created; on an existing sandbox `run` warns |
| Approvals | Queue | Derived from smolvm's blocked-request (egress) log; the host is the approval id |
| Published ports | Any host IP | `127.0.0.1` only (smolvm publishes on loopback) |
| Single-file `:ro` mounts | Supported | Directories only (smolvm mounts directories) |
| Machine names | `.` allowed | Names can't contain `--` or end in `-` (smolvm rules) |
| Daemon | `sandboxd` | None; each command talks to smolvm directly |
| `--version` | `sbx version vX` | `sbt --version` prints `sbt X`; `sbt version` also shows the smolvm version |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error (the message says why) |
| 2 | Not implemented yet, Docker Cloud only, or a usage error |
| other | `run` and `exec` return the agent's or command's own status |
