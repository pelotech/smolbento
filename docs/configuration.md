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
| `clone.fetch-on-exit` | `SMOLBENTO_CLONE_FETCH_ON_EXIT` | `true` | After `run` in a clone sandbox, fetch the agent's commits into the `sandbox-<name>` remote |
| `fork.enabled` | `SMOLBENTO_FORK` | `true` | Start clone and mountless sandboxes branchable so `sbt fork` can copy them; `false` also turns `sbt fork` off |
| `kit.allowedSources` | `SMOLBENTO_KIT_ALLOWED_SOURCES` | `["docker.io/"]` | Where published kits may load from: a JSON array of prefixes (`["*"]` allows any) |
| `kit.allowLocalKits` | `SMOLBENTO_KIT_ALLOW_LOCAL_KITS` | `true` | Allow kits from local directories, descriptor files and Smolfiles |

An environment variable wins over the config file, which wins over the default. Booleans accept
`true`/`false`, `1`/`0`, `yes`/`no` and `on`/`off`.

`docker.enabled` applies to sandboxes created afterwards.

`kit.allowedSources` uses sbx's names and syntax. Each entry is a prefix of the kit's registry and
repository, with the tag or digest dropped and Docker Hub spelled out: `alpine` is
`docker.io/library/alpine`, `ghcr.io/acme/kit:1` is `ghcr.io/acme/kit`. End a prefix with `/` to
match whole names (`ghcr.io/acme/` doesn't match `ghcr.io/acmex/kit`). An entry without `/` is a
registry host and matches only that host: `ghcr.io` allows `ghcr.io/acme/kit` but not
`ghcr.io.evil.com/kit`, and `localhost:5000` doesn't allow other ports. Host names are matched
without regard to case; repository names aren't. Docker Hub's other host names
(`index.docker.io`, `registry-1.docker.io`) are separate registries, as in sbx. An empty entry is
an error. To also allow one organisation's kits on GitHub:
`sbt settings set kit.allowedSources '["docker.io/","ghcr.io/acme/"]'`; `settings set` checks the
value first. A refused kit's error suggests the setting that would allow it. The setting applies
to kits only: the images a kit names (a workload kit's image, the base image its layers are added
to) are pulled without it, like a Dockerfile's `FROM`. Registries are reached over HTTPS, except
loopback ones (`localhost`, `127.0.0.0/8`, `::1`), which use plain HTTP. sbx's signature settings
(`kit.requireSignature`, `kit.trustedSigners`, `kit.ignoreTransparencyLog`) and
`kit.allowExtractedAgents` aren't available yet.

`fork.enabled` applies from each sandbox's next start; see [Fork](usage.md#fork) for what it
costs.

## Files

| Path | Contents |
|---|---|
| `~/.config/smolbento/config.toml` | Settings written by `sbt settings set` |
| `~/.config/smolbento/policy.toml` | Network policy: mode, global and per-sandbox rules |
| `~/.config/smolbento/secrets.toml` | Where each secret comes from (never the value) |
| `~/.config/smolbento/secret-values.toml` | Secret values, mode 0600, only where no OS keychain is usable (headless Linux, CI) |
| `~/.cache/smolbento/sessions/` | One file per attached `run` session, used to stop a sandbox when the last session ends |
| `~/.cache/smolbento/kits/` | Downloaded and built kits, and images with kit layers added; safe to delete |

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
| `sbx.clone` | `true` for a `--clone` sandbox |
| `sbx.clone-top` | Top of the cloned repo, when the workspace is a subdirectory of it |
| `sbx.credential-env` | Env vars those secrets use; a start keeps any without a value out of the sandbox, even if the service is gone |
| `sbx.kits` | Kits applied at create, pinned to their digests |
| `sbx.command` | The command a workload kit launches, as a JSON list |
| `sbx.user` | The image user a v3 workload kit's agent and `exec` run as (`0` for root) |
| `sbx.agent-file` | The agent instructions file a workload kit's own `agent-context` names, so `kit add` can index a new mixin's context in it |
| `sbx.workdir` | A v3 workload kit's image `WORKDIR`, where install hooks run (absent for `/`) |
| `sbx.credential-install` | Env vars of credentials a kit needs only while installing; later starts leave them out |
| `sbx.long-running` | `true` when a kit asked not to stop the sandbox when its last session ends |

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
