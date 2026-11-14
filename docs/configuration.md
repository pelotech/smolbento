# Configuration

## Settings

```sh
sbt settings ls                         # every setting, its value and where it came from
sbt settings get docker.enabled
sbt settings set docker.enabled false
sbt settings unset docker.enabled       # back to the default
```

An environment variable beats the config file, which beats the default. Booleans accept
`true`/`false`, `1`/`0`, `yes`/`no` and `on`/`off`.

| Setting | Env var | Default | Meaning |
|---|---|---|---|
| `docker.enabled` | `SMOLBENTO_DOCKER` | `true` | Docker-enabled agent images, and a private Docker engine in each sandbox. Applies to sandboxes created afterwards. |
| `smolvm.path` | `SMOLBENTO_SMOLVM` | `smolvm` | The smolvm binary to run. |
| `smolvm.image-cache-size` | `SMOLBENTO_IMAGE_CACHE_SIZE` | `40g` | Disk for smolvm's cache of ready-to-boot images. See [Details](#details). |
| `clone.fetch-on-exit` | `SMOLBENTO_CLONE_FETCH_ON_EXIT` | `true` | After `run` in a clone sandbox, fetch the agent's commits into the `sandbox-<name>` remote. |
| `fork.enabled` | `SMOLBENTO_FORK` | `true` | Start clone and mountless sandboxes branchable so `sbt fork` can copy them. `false` also turns `sbt fork` off. Applies from each sandbox's next start; see [Fork](usage.md#fork). |
| `kit.allowedSources` | `SMOLBENTO_KIT_ALLOWED_SOURCES` | `["docker.io/"]` | Registry prefixes published kits may load from, as a JSON array. See [Kit sources](#kit-sources). |
| `kit.allowLocalKits` | `SMOLBENTO_KIT_ALLOW_LOCAL_KITS` | `true` | Allow kits from local directories, descriptor files and Smolfiles. |
| `kit.requireSignature` | `SMOLBENTO_KIT_REQUIRE_SIGNATURE` | `false` | Load registry kits only when a trusted signer signed them. Refuses local kits. See [Kit signatures](#kit-signatures). |
| `kit.trustedSigners` | `SMOLBENTO_KIT_TRUSTED_SIGNERS` | Docker employees: `identityRegexp` `^.*@docker\.com$`, `issuer` `https://accounts.google.com` | JSON array of trusted signers. See [Kit signatures](#kit-signatures). |
| `kit.ignoreTransparencyLog` | `SMOLBENTO_KIT_IGNORE_TRANSPARENCY_LOG` | `false` | Verify keyless kit signatures without requiring a Rekor transparency-log entry. |
| `browser.enabled` | `SMOLBENTO_BROWSER_ENABLED` | `true` | Let sandboxes open `https://` URLs in your browser while you're attached. `false` also stops in-sandbox logins that redirect to `localhost`. See [Details](#details). |
| `ssh.agentForwardingEnabled` | `SMOLBENTO_SSH_AGENT_FORWARDING` | `true` | Let sandboxes list your SSH agent's keys and sign with them, but not add, remove or lock keys. See [SSH agent](usage.md#ssh-agent). |
| `ssh.agentSocketPath` | `SMOLBENTO_SSH_AGENT_SOCKET` | empty | Fixed host SSH agent socket. Empty uses each client's current `SSH_AUTH_SOCK`. |
| `ssh.knownHostsFile` | `SMOLBENTO_SSH_KNOWN_HOSTS_FILE` | `~/.ssh/known_hosts` | `known_hosts` file whose host keys decide which servers a kit's `ssh-agent@1` `authenticate` list admits. Read at each login. smolbento-only. |
| `env.rememberHostCommands` | `SMOLBENTO_ENV_REMEMBER_HOST_COMMANDS` | `false` | Keep an approval of an environment file's host commands until they change. Otherwise `sbt env create` and `sbt env run` ask every time. |
| `skills.defaultMode` | `SMOLBENTO_SKILLS_DEFAULT_MODE` | `readonly` | Default for a sandbox created without `--skills`: `off`, `readonly` or `readwrite`. See [Details](#details). |

The `SMOLBENTO_*` names are smolbento's own. sbx has no environment variable per setting. The few
variables its daemon reads (such as `DOCKER_SANDBOXES_PROXY` and `SBX_NO_TELEMETRY`) belong to
settings smolbento doesn't have (measured on sbx v0.53.0).

`kit.allowExtractedAgents` from sbx isn't available yet.

### Details

**`smolvm.image-cache-size`** caps smolvm's image seed cache (`~/Library/Caches/smolvm/image-seeds`
on macOS, `~/.cache/smolvm/image-seeds` on Linux). The first sandbox of an image fills it, so later
sandboxes of that image start in seconds without a pull. Past the cap, the least recently used
images go first, and the next sandbox of an evicted image pulls again. An agent image takes about
2 to 3 GB. Sizes take `k`, `m`, `g` or `t` (`60g`, `1t`). Zero is refused. If you set smolvm's own
`SMOLVM_IMAGE_SEED_MAX_BYTES`, it wins. smolvm checks the cap when it adds an image.

**`browser.enabled`** applies from the next `run` or `exec -it`. Copying to your clipboard isn't
affected. See [Browser and clipboard](usage.md#browser-and-clipboard).

**`ssh.agentForwardingEnabled` and `ssh.agentSocketPath`** are checked when a sandbox is created and
again for each new agent connection from it. If forwarding is off, or there's no agent, at create,
the sandbox gets none until it's recreated. A kit that requires an agent refuses the create in that
case. `ssh.agentSocketPath` must name an existing socket; smolbento never starts an agent itself.

**`ssh.knownHostsFile`** is read each time a sandbox asks the agent to log in, so edits apply to the
next login. A missing or unreadable file means no server is trusted and logins are refused. See
[SSH agent](usage.md#ssh-agent).

**`skills.defaultMode`** applies when a sandbox is created and neither `--skills` nor
`sandboxOptions.skills` says otherwise. An existing sandbox keeps the mode it was created with. A
bad setting value is reported as `setting skills.defaultMode: ...`. A bad `--skills` or
`sandboxOptions.skills` value is reported as `invalid skills mode "x": use off, readonly or
readwrite`. See [Skills](usage.md#skills).

### Kit sources

`kit.allowedSources` uses sbx's names and syntax. Each entry is a prefix of a kit's registry and
repository, with the tag or digest dropped and Docker Hub spelled out. `alpine` is
`docker.io/library/alpine`, and `ghcr.io/acme/kit:1` is `ghcr.io/acme/kit`.

- End a prefix with `/` to match whole names. `ghcr.io/acme/` doesn't match `ghcr.io/acmex/kit`.
- An entry without `/` is a registry host and matches only that host. `ghcr.io` allows
  `ghcr.io/acme/kit` but not `ghcr.io.evil.com/kit`. `localhost:5000` doesn't allow other ports.
- Host names match without regard to case. Repository names do not.
- Docker Hub's other host names (`index.docker.io`, `registry-1.docker.io`) are separate registries,
  as in sbx.
- An empty entry is an error. `"*"` allows any source.

To also allow one organisation's kits on GitHub:

```sh
sbt settings set kit.allowedSources '["docker.io/","ghcr.io/acme/"]'
```

`settings set` checks the value first. A refused kit's error suggests the setting that would allow
it.

The setting covers kits only. The images a kit names (a workload kit's image, and the base image its
layers are added to) are pulled without it, like a Dockerfile's `FROM`. Registries are reached over
HTTPS, except loopback ones (`localhost`, `127.0.0.0/8`, `::1`), which use plain HTTP.

### Kit signatures

With `kit.requireSignature` set to `true`, a registry kit loads only if one of its signatures
verifies for a signer in `kit.trustedSigners`. Verification uses `cosign`, from `PATH` or from
`SMOLBENTO_COSIGN`. Local kits are refused while the setting is on. `--offline` skips the check, as
in sbx. Presets and shipped kits are exempt.

`kit.trustedSigners` is a JSON array. Each entry is either:

- a key: `{"key": "/path/to/public.pem"}`, or
- keyless: `{"issuer": "...", "identity": "..."}`. Each field can also be written as
  `issuerRegexp` or `identityRegexp`.

`kit.ignoreTransparencyLog` relaxes only the keyless check, which otherwise needs a Rekor entry.

Sign a kit with `sbt kit sign --help`.

## Files

| Path | Contents |
|---|---|
| `~/.config/smolbento/config.toml` | Settings written by `sbt settings set` |
| `~/.config/smolbento/policy.toml` | Network policy: mode, global and per-sandbox rules |
| `~/.config/smolbento/mcp.toml` | Registered MCP servers |
| `~/.config/smolbento/secrets.toml` | Where each secret comes from (never the value) |
| `~/.config/smolbento/secret-values.toml` | Secret values, mode 0600, only where no OS keychain is usable (headless Linux, CI) |
| `~/.cache/smolbento/sessions/` | One file per attached `run` session, used to stop a sandbox when its last session ends |
| `~/.cache/smolbento/kits/` | Downloaded and built kits, and images with kit layers added. Safe to delete. |
| `~/.local/share/smolbento/agent-skills/` | The shared [skills](usage.md#skills) store, one directory per skill. `sbt reset` deletes it. |
| `~/.local/share/smolbento/agent-skills-metadata/` | Where each skill added from a repository came from (`sources.json`) |
| `~/.local/share/smolbento/env/` | Your approval record for each environment file (`<name>.toml`) |
| `~/.local/share/smolbento/templates/` | Saved templates: `templates.json` and the `<id>.smolmachine` packs |
| `~/.local/share/smolbento/kit-host-mounts/` | Kit [host mounts](usage.md#kit-host-mounts), kept after their sandboxes are removed |

`XDG_CONFIG_HOME`, `XDG_CACHE_HOME` and `XDG_DATA_HOME` are honoured, also on macOS.
`SMOLBENTO_CONFIG_DIR`, `SMOLBENTO_CACHE_DIR` and `SMOLBENTO_DATA_DIR` override them. An empty
`SMOLBENTO_*_DIR`, or an empty or relative XDG variable, counts as unset.

`config.toml` looks like this:

```toml
[settings]
"docker.enabled" = "false"
```

If the file can't be parsed, every command except `diagnose` and `settings` stops with the parse
error, so you can still inspect and fix the file.

## Where sandboxes live

smolbento keeps no database. Each sandbox is a smolvm machine named `sbx-<name>` (with `.` in the
name turned into `_`). Its details are stored as labels on that machine:

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
| `sbx.credential-env` | Env vars those secrets use. A start leaves out any without a value, even if the service is gone. |
| `sbx.credential-install` | Env vars of credentials a kit needs only while installing. Later starts leave them out. |
| `sbx.clone` | `true` for a `--clone` sandbox |
| `sbx.clone-top` | Top of the cloned repo, when the workspace is a subdirectory of it |
| `sbx.kits` | Kits applied at create, pinned to their digests |
| `sbx.command` | The command a workload kit launches, as a JSON list |
| `sbx.user` | The image user a v3 workload kit's agent and `exec` run as (`0` for root) |
| `sbx.agent-file` | The agent instructions file a workload kit's `agent-context` names, so `kit add` can index a new mixin's context in it |
| `sbx.workdir` | A v3 workload kit's image `WORKDIR`, where install hooks run (absent for `/`) |
| `sbx.skills` | The skills mode, the `/run/sbx/skills-shared` mount (`none`, `ro` or `rw`), and each skills directory with its access (`none`, `link`, or the store mounted over it `ro` or `rw`), set at create |
| `sbx.long-running` | `true` when a kit asked not to stop the sandbox when its last session ends |

`smolvm machine ls` shows these alongside machines you made with smolvm directly. `sbt ls` shows
only the ones smolbento made.

## Secret values

Secret values live in the OS keychain. On macOS they go through `/usr/bin/security`, as items under
service `smolbento`. On Linux they go through `secret-tool` when a Secret Service is running. Where
neither is available, they go in `~/.config/smolbento/secret-values.toml` (mode 0600).
`secrets.toml` never holds values.

A registry credential's password or token is stored the same way, as account `registry:<host>`.
`secrets.toml` keeps its host, user name and `--registry-auth-endpoint` under `[[registries]]`.

On macOS, a stored value can be at most about 1.9 KB, because `security` truncates longer input. For
larger values, such as certificates or keys, use `secret set --ref` or `--command`. The value is
then read at each start instead of stored. Keychain items hold the value hex-encoded behind an
`sbx1:` prefix.
