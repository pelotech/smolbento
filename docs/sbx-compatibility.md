# sbx compatibility

smolbento accepts Docker Sandboxes command lines flag for flag (sbx v0.49 reference). Anything not
implemented yet still parses, then exits with status **2** and a message saying so, so scripts fail
clearly rather than doing something different.

## Works today

`run`, `create`, `exec`, `ls`, `start`, `stop`, `rm`, `prune`, `reset`, `cp`, `version`,
`completion`, `diagnose`, `settings`. `daemon` is accepted and does nothing: smolbento has no daemon.

## Parses, not implemented yet (exit 2)

| Command or flag | Planned |
|---|---|
| `policy`, `secret`, `ports` | Next phase. See [Development status](development-status.md) |
| `run/create --clone` | Later |
| `--kit`, `kit`, `env` (sbxenv.yaml) | Later |
| `template`, `setup ssh`, `mcp`, `--static-mcp`, `--skills`, `skills` | Later |
| `tui` | Later |
| `--deny-network` | With network policy |
| `--pull always\|never` | `--pull missing` works (it's what smolvm does) |
| `exec -d`, `--detach-keys` | Not supported (sbx doesn't support `exec -d` either) |

## Never (Docker Cloud only, exit 2)

`login`, `logout`, `move`, `ttl`, `attach`, `volume`, the global `--cloud` flag, and the cloud-only
`run`/`create` flags (`--allow-network`, `--image-ref`, `--platform`, `--ttl`, `--on-timeout`,
`-v/--volume`, `--new`).

## Differences you'll notice

| Area | sbx | smolbento |
|---|---|---|
| Network | Default-deny policy with a balanced allow list | **Open network for now**, until the policy phase lands |
| Secrets | Stored and injected by a proxy | Not yet; pass keys with `-e` or log in inside the sandbox |
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
