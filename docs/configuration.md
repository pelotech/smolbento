# Configuration

On this page: [Settings](#settings) · [Files](#files) · [Where sandboxes
live](#where-sandboxes-live) · [Secret values](#secret-values)

## Settings

```sh
# every setting, its value and where it came from
bento settings ls
bento settings get docker.enabled
bento settings set docker.enabled false
# back to the default
bento settings unset docker.enabled
```

An environment variable beats the config file, which beats the default. Booleans accept
`true`/`false`, `1`/`0`, `yes`/`no` and `on`/`off`.

| Setting | Env var | Default | Meaning |
|---|---|---|---|
| `sandbox.autoName` | `SMOLBENTO_SANDBOX_AUTO_NAME` | `false` | When a default name belongs to another directory's sandbox, take the suggested `<agent>-<parent>-<directory>` name instead of refusing. smolbento only. See [Usage](usage.md). |
| `sandbox.disk.dockerVolume` | `SMOLBENTO_SANDBOX_DISK_DOCKER_VOLUME` | (smolvm's default, 20 GiB) | Disk for Docker's data in new sandboxes, such as `30g`. smolvm keeps image layers on the same disk. An environment file's `dockerSize` wins. |
| `docker.enabled` | `SMOLBENTO_DOCKER` | `true` | Docker-enabled agent images, and a private Docker engine in each sandbox. Applies to sandboxes created afterwards. |
| `smolvm.path` | `SMOLBENTO_SMOLVM` | (empty) | A smolvm to run instead of the release smolbento downloads, such as one you built. smolbento is tested with the downloaded one (`bento diagnose` names it). |
| `smolvm.home` | `SMOLBENTO_SMOLVM_HOME` | `~/.smolbento` | Where smolvm keeps smolbento's sandboxes, and where the downloaded smolvm goes. `-` uses your smolvm's own default location. On macOS keep it short: smolvm's sockets inside it must fit in 103 bytes. |
| `smolvm.image-cache-size` | `SMOLBENTO_IMAGE_CACHE_SIZE` | `40g` | Disk for smolvm's cache of ready-to-boot images. See [Details](#details). |
| `clone.fetch-on-exit` | `SMOLBENTO_CLONE_FETCH_ON_EXIT` | `true` | After `run` in a clone sandbox, fetch the agent's commits into the `sandbox-<name>` remote. |
| `fork.enabled` | `SMOLBENTO_FORK` | `true` | Start clone and mountless sandboxes branchable so `bento fork` can copy them. `false` also turns `bento fork` off. Applies from each sandbox's next start; see [Fork](usage.md#fork). |
| `kit.allowedSources` | `SMOLBENTO_KIT_ALLOWED_SOURCES` | `["docker.io/","ghcr.io/pelotech/smolbento/"]` | Registry prefixes published kits may load from, as a JSON array. See [Kit sources](#kit-sources). |
| `kit.showWarnings` | `SMOLBENTO_KIT_SHOW_WARNINGS` | `false` | Show what smolbento skips or ignores of a kit's optional parts: unsupported optional capabilities, optional credentials without a secret, ignored v2 fields. `-D` shows them too. Off by default because the kit works without them. smolbento only. |
| `kit.allowLocalKits` | `SMOLBENTO_KIT_ALLOW_LOCAL_KITS` | `true` | Allow kits from local directories, descriptor files and Smolfiles. |
| `kit.requireSignature` | `SMOLBENTO_KIT_REQUIRE_SIGNATURE` | `false` | Load registry kits only when a trusted signer signed them. Refuses local kits. See [Kit signatures](#kit-signatures). |
| `kit.trustedSigners` | `SMOLBENTO_KIT_TRUSTED_SIGNERS` | Docker identities (`identityRegexp` `^.*@docker\.com$`, `issuer` `https://accounts.google.com`) and smolbento's kit releases (see [Kit signatures](#kit-signatures)) | JSON array of trusted signers. See [Kit signatures](#kit-signatures). |
| `kit.ignoreTransparencyLog` | `SMOLBENTO_KIT_IGNORE_TRANSPARENCY_LOG` | `false` | Verify keyless kit signatures without requiring a Rekor transparency-log entry. |
| `clipboard.textCopy` | `SMOLBENTO_CLIPBOARD_TEXT_COPY` | `false` | Let sandboxes copy text to your clipboard (`pbcopy`, `wl-copy`, `xclip`, `xsel`, `clip.exe` in the sandbox). See [Browser and clipboard](usage.md#browser-and-clipboard). |
| `browser.enabled` | `SMOLBENTO_BROWSER_ENABLED` | `true` | Let sandboxes open `https://` URLs in your browser. `false` also stops in-sandbox logins that redirect to `localhost`. See [Details](#details). |
| `network.egress` | `SMOLBENTO_NETWORK_EGRESS` | `hosted` | Who handles a sandbox's egress: `hosted` or `smolvm`. Some sandboxes fall back to `smolvm`, with a warning; recorded per sandbox at create. See [Hosted egress](network-and-secrets.md#hosted-egress). |
| `ssh.agentForwardingEnabled` | `SMOLBENTO_SSH_AGENT_FORWARDING` | `true` | Let sandboxes list your SSH agent's keys and sign with them, but not add, remove or lock keys. See [SSH agent](usage.md#ssh-agent). |
| `ssh.agentSocketPath` | `SMOLBENTO_SSH_AGENT_SOCKET` | empty | Fixed host SSH agent socket. Empty uses the user session's `SSH_AUTH_SOCK` (the `bento` client's, while attached). |
| `ssh.knownHostsFile` | `SMOLBENTO_SSH_KNOWN_HOSTS_FILE` | `~/.ssh/known_hosts` | `known_hosts` file whose host keys decide which servers a kit's `ssh-agent@1` `authenticate` list admits. Read at each login. smolbento-only. |
| `env.rememberHostCommands` | `SMOLBENTO_ENV_REMEMBER_HOST_COMMANDS` | `false` | Keep an approval of an environment file's host commands until they change. Otherwise `bento env create` and `bento env run` ask every time. |
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

**`browser.enabled`** applies to each new connection (the service unit reads settings per connection). Copying to your clipboard isn't
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
readwrite`. See [Skills](kits.md#skills).

### Kit sources

`kit.allowedSources` uses sbx's names and syntax. Each entry is a prefix of a kit's registry and
repository, with the tag or digest dropped and Docker Hub spelled out. `alpine` is
`docker.io/library/alpine`, and `ghcr.io/acme/kit:1` is `ghcr.io/acme/kit`.

The default allows Docker Hub, as in sbx, and `ghcr.io/pelotech/smolbento/`, where smolbento
publishes its own kits (such as [`nix`](kits.md#the-nix-kit)). Nothing else on GHCR.

- End a prefix with `/` to match whole names. `ghcr.io/acme/` doesn't match `ghcr.io/acmex/kit`.
- An entry without `/` is a registry host and matches only that host. `ghcr.io` allows
  `ghcr.io/acme/kit` but not `ghcr.io.evil.com/kit`. `localhost:5000` doesn't allow other ports.
- Host names match without regard to case. Repository names do not.
- Docker Hub's other host names (`index.docker.io`, `registry-1.docker.io`) are separate registries,
  as in sbx.
- An empty entry is an error. `"*"` allows any source.

To also allow one organisation's kits on GitHub:

```sh
bento settings set kit.allowedSources '["docker.io/","ghcr.io/acme/"]'
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
in sbx. Built-in agents' kits (sbx publishes them unsigned) and shipped kits are exempt, and so
are they from `kit.allowedSources`.

`kit.trustedSigners` is a JSON array. Each entry is either:

- a key: `{"key": "/path/to/public.pem"}`, or
- keyless: `{"issuer": "...", "identity": "..."}`. Each field can also be written as
  `issuerRegexp` or `identityRegexp`.

`kit.ignoreTransparencyLog` relaxes only the keyless check, which otherwise needs a Rekor entry.

The default trusts Docker identities, as in sbx, and smolbento's own kit releases: issuer
`https://token.actions.githubusercontent.com`, identity
`https://github.com/pelotech/smolbento/.github/workflows/release-please.yaml@refs/heads/main`.

Sign a kit with `bento kit sign --help`.

## Files

| Path | Contents |
|---|---|
| `~/.smolbento/` | smolvm's state for smolbento's sandboxes (`smolvm.home`), and the downloaded smolvm in `engine/<version>/` |
| `~/.config/smolbento/config.toml` | Settings written by `bento settings set` |
| `~/.config/smolbento/policy.toml` | Network policy: mode, global and per-sandbox rules, dismissed approvals |
| `~/.config/smolbento/mcp.toml` | Registered MCP servers |
| `~/.config/smolbento/secrets.toml` | Where each secret comes from (never the value) |
| `~/.config/smolbento/secret-values.toml` | Secret values, mode 0600, only where no OS keychain is usable (headless Linux, CI) |
| `~/.cache/smolbento/sessions/` | One file per attached `run` session, used to stop a sandbox when its last session ends |
| `~/.cache/smolbento/kits/` | Downloaded and built kits, and images with kit layers added. Safe to delete. |
| `~/.local/share/smolbento/agent-skills/` | The shared [skills](kits.md#skills) store, one directory per skill. `bento reset` deletes it. |
| `~/.local/share/smolbento/agent-skills-metadata/` | Where each skill added from a repository came from (`sources.json`) |
| `~/.local/share/smolbento/env/` | Your approval record for each environment file (`<name>.toml`) |
| `~/.local/share/smolbento/templates/` | Saved templates: `templates.json` and the `<id>.smolmachine` packs |
| `~/.local/share/smolbento/egress/<sandbox>/` | A hosted-egress sandbox's CA (its private key included; it can sign for any host, and the egress process decrypts only secret hosts and hosts with request rules), its interceptor token and `egress.log` (denied connections, unresolved secrets by name), in a 0700 directory. Removed with the sandbox. |
| `~/.local/share/smolbento/kit-host-mounts/` | Kit [host mounts](kits.md#kit-host-mounts), kept after their sandboxes are removed |
| `~/Library/Application Support/smolbento/launchd/dev.smolbento.<id>.<sandbox>.<agent\|bridge\|egress>.plist` (macOS), `~/.config/systemd/user/smolbento-<id>-<sandbox>-<agent\|bridge\|egress>.socket` and `…@.service` (`….service` for egress) (Linux) | [Host service](usage.md#browser-and-clipboard) units, one per socket of a sandbox; `<id>` is a short hash of the data dir. Removed with the sandbox. |
| `~/Library/Application Support/smolbento/sock/` (macOS), `$XDG_RUNTIME_DIR/smolbento/` (Linux) | Their sockets, mode 0600 in a private (0700) directory. Without a service manager, sockets are `/tmp/sbt-<uid>/`, served while attached. |

`bento setup ssh` also edits one file outside these directories: `~/.ssh/config`, between its
`# >>> smolbento (managed) >>>` markers only. smolbento keeps no SSH host key or known-hosts file.

`XDG_CONFIG_HOME`, `XDG_CACHE_HOME` and `XDG_DATA_HOME` are honoured, also on macOS.
`SMOLBENTO_CONFIG_DIR`, `SMOLBENTO_CACHE_DIR` and `SMOLBENTO_DATA_DIR` override them. An empty
`SMOLBENTO_*_DIR`, or an empty or relative XDG variable, counts as unset. A relative
`SMOLBENTO_*_DIR` is taken from the current directory.

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
| `sbx.id` | The sandbox's `SANDBOX_ID`, a UUID made at create (a fork gets its own) |
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
| `sbx.agent-file` | The agent instructions files the kits' `agent-context` names, comma-separated, so `kit add` can add a new mixin's context to each |
| `sbx.agent-context` | The `agent-context` version (`1` or `2`) the sandbox's kit instructions were written under, so `kit add` keeps to it. Absent until a kit's instructions are written |
| `sbx.workdir` | A v3 workload kit's image `WORKDIR`, where install hooks run (absent for `/`) |
| `sbx.skills` | The skills mode, the `/run/sbx/skills-shared` mount (`none`, `ro` or `rw`), and each skills directory with its access (`none`, `link`, or the shared mount bound over it `ro` or `rw`), set at create |
| `sbx.long-running` | `true` when a kit asked not to stop the sandbox when its last session ends |
| `sbx.version` | The smolbento version that created it |
| `sbx.fork-of` | The sandbox it was forked from |
| `sbx.template` | The saved template it was created from |
| `sbx.registries` | The kit builder's stored registry hosts, comma-separated, fixed at create |
| `sbx.credential-format.<ENV>` | How a kit credential's value is formatted (`format:…` or `basic:<user>`) |
| `sbx.credential-service.<ENV>` | The secret service behind a kit credential's env var, when it isn't one of that service's own |
| `sbx.mcp` | The `--static-mcp` servers, comma-separated (empty for `none`; absent without the flag) |
| `sbx.mcp-secret.<ENV>` | The `--static-mcp` server secret a guest env var is bound to |
| `sbx.host-access` | `true` when created without the host loopback deny, because a `localhost` rule applied |
| `sbx.bridge` | `true` when created with the browser and clipboard bridge socket |
| `sbx.service` | `true` when launchd or `systemd --user` units own its host sockets |
| `sbx.ssh-agent` | The SSH agent granted at create, per phase, as JSON |
| `sbx.host-mounts` | Kit host mounts: guest path to host directory, as a JSON object |
| `sbx.no-fuse` | `true` when created without `/dev/fuse` (an environment file's `sandboxOptions.fuse: false`) |
| `sbx.read-only-files` | Workspace files made read-only at each start (an environment's files), as a JSON list |

`bento smolvm machine ls` shows these. Machines you make with `bento smolvm` sit next to smolbento's
sandboxes, but `bento ls` shows only the ones smolbento made.

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
