# Configuration

## Settings

```sh
sbt settings ls                         # every setting, its value and where it came from
sbt settings get docker.enabled
sbt settings set docker.enabled false
sbt settings unset docker.enabled       # back to the default
```

| Setting | Env var | Default | Meaning |
|---|---|---|---|
| `docker.enabled` | `SMOLBENTO_DOCKER` | `true` | Use the Docker-enabled agent images and run a private Docker engine in each sandbox |
| `smolvm.path` | `SMOLBENTO_SMOLVM` | `smolvm` | The smolvm binary to run |

An environment variable wins over the config file, which wins over the default. Booleans accept
`true`/`false`, `1`/`0`, `yes`/`no` and `on`/`off`.

`docker.enabled` applies to sandboxes created afterwards.

## Files

| Path | Contents |
|---|---|
| `~/.config/smolbento/config.toml` | Settings written by `sbt settings set` |
| `~/.config/smolbento/policy.toml` | Network policy: mode, global and per-sandbox rules |
| `~/.config/smolbento/secrets.toml` | Where each secret comes from (never the value) |
| `~/.config/smolbento/secret-values.toml` | Secret values, mode 0600, only where no OS keychain is usable (headless Linux, CI) |
| `~/.cache/smolbento/sessions/` | One file per attached `run` session, used to stop a sandbox when the last session ends |

`XDG_CONFIG_HOME` and `XDG_CACHE_HOME` are honoured (also on macOS). `SMOLBENTO_CONFIG_DIR` and
`SMOLBENTO_CACHE_DIR` override both.

`config.toml` looks like:

```toml
[settings]
"docker.enabled" = "false"
```

If the file can't be parsed, every command except `diagnose` and `settings` stops with the parse
error, so you can still inspect and fix it.

## Where sandboxes live

smolbento keeps no database of its own. Each sandbox is a smolvm machine named `sbx-<name>` (with
`.` in the name turned into `_`), and its details are stored as labels on that machine:

| Label | Value |
|---|---|
| `sbx.name` | Sandbox name |
| `sbx.agent` | Agent it was created for |
| `sbx.workspace` | Primary workspace path (absent for a sandbox without one) |
| `sbx.workspaces` | All mounted paths, as a JSON list |
| `sbx.created` | Creation time, unix seconds |
| `sbx.docker` | Whether it runs a private Docker engine |
| `sbx.secrets` | Services whose secrets were bound at create |
| `sbx.credential-hosts` | Hosts those secrets use, recorded at create so the sandbox can always reach them |

`smolvm machine ls` shows them alongside any machines you made with smolvm directly; `sbt ls` shows
only the ones smolbento made.

## Secret values

Secret values live in the OS keychain: on macOS through `/usr/bin/security` (items under service
`smolbento`), on Linux through `secret-tool` when a Secret Service is running. Where neither is
available they go in `~/.config/smolbento/secret-values.toml` (mode 0600). `secrets.toml` never
holds values.

On macOS a stored value can be at most about 1.9 KB (`security` truncates longer input); for larger
values, such as certificates or keys, use `secret set --ref` or `--command` so the value is read at
each start instead of stored. Keychain items hold the value hex-encoded behind an `sbx1:` prefix.
