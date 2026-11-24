# Kits, skills, MCP servers and templates

What a sandbox is built from and what you can add to it. Running agents is in [Usage](usage.md).

On this page: [Kits](#kits) · [Skills](#skills) · [MCP servers](#mcp-servers) ·
[Templates](#templates)

## Kits

Kits add tools, files, network rules, credentials and setup steps. smolbento runs Docker Sandboxes
kits (v3, and v2 `spec.yaml`) and smolvm Smolfiles.

```sh
# add a mixin kit to an agent
bento run claude . --kit docker.io/acme/postgres-kit:1
# a workload kit replaces the agent
bento run docker.io/acme/my-agent:1 .
# a local kit, with an argument
bento create shell . --kit ./my-kit --kit-arg region=eu
# what it provides and asks for
bento kit inspect ./my-kit
# check it without running it
bento kit validate ./my-kit
# add a mixin to an existing sandbox
bento kit add claude-myrepo ./my-mixin
```

A **mixin** adds to an agent (`--kit`, repeatable). A **workload** kit replaces the agent. Pass it
where the agent name goes, and the sandbox takes its name. Its image's command runs as the image's
`USER` (root if none) under `/bin/bash`, in the workspace path, and `bento exec` uses the same user.
smolvm maps the workspace to that user. A workload with no `ENTRYPOINT` or `CMD` is refused, and one
without `/bin/bash` can't start its agent. A v3 workload's `ENTRYPOINT` + `CMD` also run at every
boot (as the image user), as the kit spec's default launch mode says; the machine stays up if it
exits, and `bento run` still starts its own interactive session.

| Reference | Kit |
|---|---|
| `docker` | The shipped Docker kit |
| `git-signing` | The shipped [git-signing kit](#the-git-signing-kit) |
| `nix` | smolbento's [Nix kit](#the-nix-kit), pulled from `ghcr.io/pelotech/smolbento/kits/nix:latest` |
| `docker.io/acme/kit:1`, `ghcr.io/acme/kit@sha256:…` | A published kit, pulled from its registry |
| `./my-kit` (a directory with one `*.yaml` that has `schemaVersion: "3"` or starts `# syntax=docker/sandbox-kit:3`), or that file | A local v3 kit, built in the builder sandbox (below) |
| `./my-kit` (a directory with a `spec.yaml`) | A local v2 kit |
| `./Smolfile`, `./x.smolfile` | A smolvm Smolfile |

v2 and v3 kits can't share a sandbox. The built-in agents are v3 kits; `docker` and a Smolfile can
go with either.

A local kit is always a path (`./my-kit`, `../kits/my-kit`, `.`, or absolute). A bare word is never
a local kit, even if a directory has that name; only `docker`, `git-signing` and `nix` are bare kit names. `bento create my-kit` fails with `unknown agent "my-kit"`,
and `--kit my-kit` says `not a local path and does not look like a registry reference`. Write
`docker.io/library/alpine` for the alpine image.

Kits declare versions with `provides: [postgres@16.2.0]` and `requires: ["postgres >= 16"]`. A
missing or mismatched capability stops the create with `resolve: the kit set is not coherent:` and
one line per problem. sbx's agent kits provide their own name (`claude@2.1.325`), so
`requires: [claude]` works on `claude`.

`bento kit inspect REF` prints the kit's summary, capabilities, source, provides, requires,
credentials (with the hosts each secret goes to) and arguments. `--format json` (or `--json`) and
`--format yaml` print a v2-shaped descriptor with smolbento's extras under `smolbento`. `bento kit
validate REF` prints `✓ REF — valid`, or the error and exits 1; with `--json` or `--format
json|yaml` it prints `{reference, kind, valid, warnings}`, plus `errors` when invalid. `--offline`
checks a local v2 kit or Smolfile without the network or source policy.

`--kit-arg NAME=VALUE` applies to every kit, `--kit-arg KIT.NAME=VALUE` to one, and `--kit-args-file
FILE` reads `NAME=VALUE` lines. Files are read first, then `--kit-arg`; the last value wins, and a
per-kit value beats an all-kits one. A `KIT.NAME` for a kit not in the sandbox is ignored. Argument
values aren't secret: they reach the environment and smolvm's machine config, and each kit's values
(defaults included) are kept with the sandbox (its `sbx.kits` label, shown by
`bento smolvm machine status`), in templates saved from it, and in their `--output` archives. Put secrets in
[credentials](network-and-secrets.md#secrets). An argument with no value and no default fails with `create-phase kit arg
"x" has no resolved value`; `--kit-arg x=` sets it empty. `--kit-arg` without a kit is an error.
Unquoted numbers and booleans in `default:` and `enum:` are read as strings. A `pattern:` has to
match the whole value, as if it were written `^(?:…)$`.

In a kit, `${{ kit.args.NAME }}` and `${{ kit.env.NAME }}` are replaced, in any field of a
capability's config and in its map keys. Any other `${{ … }}`, such as a GitHub Actions expression
in a file the kit writes, is left as it is. A value that is nothing but one reference takes the type
its value spells, so `container: ${{ kit.args.port }}` with `port=8080` is the number 8080.
`true`/`false` become booleans, and a number does only when it prints back the same (`1.0`, `007`
and `1e5` stay text). `volume@1`'s `size` and `mode` always stay text. A config with references is
checked fully at create, after they're replaced. Two map keys that become the same key are an
error.

`${{ kit.env.NAME }}` reads the sandbox's environment as the spec defines it: the workload image's
`ENV`, then what kits export (`args.*.env`), then `-e`/`--env` at create, the last winning; an empty
`-e NAME=` is a value. `HOME` and `WORKSPACE` are smolbento's. `kit add` reads only what kits export,
since a sandbox doesn't keep its image's `ENV` or its create's `-e`.

What a kit does, and when:

- On first start, install steps run once, as root, in a workload image's `WORKDIR` (`/` otherwise),
  with network only for installing. A failing step, or a kit file that can't be written, removes the
  sandbox. Fix the cause and run the same command. In a v2 kit, `files/workspace` and `${WORKDIR}`
  are the primary workspace, or `/home/agent/workspace` without one.
- On every start, startup steps run in kit order, before the agent. A failing one is a warning
  with the log's last lines, and the sandbox starts anyway, as in sbx 0.51. A `background: true`
  step keeps running; if it fails, only the log records it. A step that doesn't finish holds up the
  start; there is no timeout, as in sbx.
- Logs go to `/var/log/sbx-kit-startup.log` in the sandbox. Each start adds a `=== dispatcher run …
  ===` line, each finished step an `ok /etc/smolbento/startup.d/NN-<kit>.sh hook N` line, and a
  failing step its output and exit code.
- At create and `kit add`, a failing startup step is the same warning; the sandbox is created and
  runs.
- Startup steps run as the session user (the workload image's user, else `agent`) unless they name a
  user, as the kit spec's `lifecycle@1/default-users` says; install steps run as root. A numeric user
  runs as the account with that uid.
- A Docker engine comes from `dockerd@1`. The shipped `docker` kit is that one request and nothing
  else (the image must have Docker). A workload that asks for an engine
  (`com.docker.sandboxes.start-docker`, or a `-docker` image) gets the `docker` kit even when its own
  `provides` lists `docker`, as sbx's kits do. A kit providing `docker` no longer replaces it.
- `dockerd@1` makes the sandbox privileged and gives the engine its own volumes (`/var/lib/docker`,
  `/var/lib/containerd`). On every start smolbento starts `dockerd` before any startup step and waits
  up to 60 s for it to answer; if it doesn't, the start fails (see `/var/log/dockerd.log`). The
  socket is handed to the image user's group. A kit that starts dockerd itself declares
  `dockerd@1` with `config: {autoStart: false}`; if another kit also asks for the engine, smolbento
  starts it, so that kit's step must accept a running engine. With `docker.enabled=false` a required
  `dockerd@1` refuses the create, `--kit docker` included, and an optional one is skipped with its
  whole group.
- A v3 install step gets a clean environment (`PATH`, `HOME`, `USER`, `TERM`, the proxy and CA
  variables, and what its `env` lists). Startup steps and v2 steps get the full sandbox environment.
- A missing credential doesn't block create. You get `WARN: required credential not found for
  service SERVICE` and the `bento secret set` command. Requests go out without it until you set it and
  recreate the sandbox. A built-in service's secret goes only to its own hosts
  ([Security](SECURITY.md#kits)). A credential needed only for install is available during install;
  the sandbox then restarts once without it, and later requests to its hosts get `502`.
- Volumes live on the sandbox's disk and are removed with it. Host mounts are shared and kept ([kit
  host mounts](#kit-host-mounts)).

Only Docker Hub kits and smolbento's own (`ghcr.io/pelotech/smolbento/`) load by default, plus local
kits. See [Configuration](configuration.md) for
`kit.allowedSources` and `kit.allowLocalKits`, and [Security](SECURITY.md#kits) for what a kit can
open.

### The `nix` kit

`nix` adds Nix (flakes on), direnv with nix-direnv, and xz to any agent, with nothing downloaded at
create:

```sh
bento create claude . --kit nix
bento create docker.io/sbx/antigravity:latest . --kit nix
```

- `nix-daemon` starts with the sandbox and runs builds as root; you use `nix` as yourself. Flakes'
  own binary caches are honoured.
- A workspace `.envrc` is allowed at each start (direnv records that under `~/.local/share`, not in
  the repo). Agents run commands in shells that don't load it, so the kit tells them (in
  `CLAUDE.md`/`AGENTS.md`) to use `direnv exec . <cmd>` or `nix develop -c <cmd>`. On an image
  without `runuser` or `su`, run `direnv allow` once yourself.
- direnv reads its config from `/etc/direnv` (`DIRENV_CONFIG`), where the kit loads nix-direnv, so a
  `~/.config/direnv` of your own isn't read.
- Nix's default profile and `/home/agent/.nix-profile/bin` come first on `PATH`; on a workload image
  whose user isn't `agent`, add that user's `~/.nix-profile/bin` yourself for `nix profile add`.
- It brings its own network rules for the Nix caches and GitHub, for policies other than `balanced`.
- The store is on the root filesystem's disk, smolvm's 10 GiB overlay by default. For large dev
  shells, raise it with `sandboxOptions.rootSize` in an environment file.
- `nix` is `:latest` while the kit is 0.x and may change; pin a version
  (`ghcr.io/pelotech/smolbento/kits/nix:0.0.1`) or a digest in environment files. Each release
  notes the smolbento it needs.

### The `git-signing` kit

`git-signing` signs commits with a key from your SSH agent, under any agent, and sets your git name
and email. It is built in, so nothing is downloaded:

```sh
bento create claude . --kit git-signing
```

The kit's [README](https://github.com/pelotech/smolbento/tree/main/kits/git-signing) covers which
repositories and key it signs with, the `signingKey` argument and its limits.

### Agent instructions from kits

Kit instructions go in the agent's file in the workspace's parent directory, inside the sandbox
only. For workspace `~/src/app`, claude reads `~/src/CLAUDE.md`, gemini `~/src/GEMINI.md`, and other
agents `~/src/AGENTS.md`. With no workspace, `/home/agent` is used.

A kit can name the file instead, with `directory` and `filename` in its `agent-context`, as an
agent's kit does for the place its agent reads at startup (`/home/agent/.claude/CLAUDE.md`). Any
kit can, a mixin too. Every file named this way gets every kit's instructions, so two agents in one
sandbox each read all of them, and the file beside the workspace isn't written. A `filename`
without a `directory` counts only in the workload kit.

How the text gets there depends on the `agent-context` version the kits declare:

- **`agent-context@2`** (and a v2 kit's `agentInstructions`): the kits' text is in the file
  itself, so the agent reads it at startup. It sits between `<!-- sbx:kits-section start -->` and
  `<!-- sbx:kits-section end -->`, one kit's text after another, a blank line apart.
- **`agent-context@1`**: the file gets a `## Kits` list between the same two markers, one line per
  kit saying where its text is. The agent reads a kit's text when it needs it. Text a kit ships as
  a file (`contentFile`) is listed where the kit's image has it; inline text is written to
  `kits-agent-context/<kit>.md` beside the agent file.

A sandbox uses one version for all its kits, as the kit spec requires. It is `@2`, unless a kit
requires `@1` (declares it without `optional: true`). A kit can offer both by declaring each with
`optional: true`, as the shipped kits and sbx's agents do; it then follows the others. A kit that
offers only the version not in use, as optional, is added without its instructions
(`kit.showWarnings` shows a warning). Kits that require different versions can't share a sandbox,
and `create` says which. `kit add` keeps to the sandbox's version: a kit that requires the other
one needs a recreate.

Text outside the markers is yours and is kept. Unlike sbx, smolbento writes no platform preamble.

- Nothing is written on your machine. A file that would land in a mounted workspace is skipped with
  a warning.
- When no kit names a file and the workload kit declares no `agent-context`, mixin instructions are
  dropped (`kit.showWarnings` shows a warning).
- `kit add` of a kit that names its own file needs a recreate (`recreate required: agent file`): a
  new file gets every kit's instructions, and only a create has them all.
- A kit can't end the section: a `<!-- sbx:` marker in kit text is written as `&lt;!-- sbx:`.
- `kit add` puts the new kit's text after what the section holds. If an add fails partway and you
  run it again, that kit's `@2` text is there twice; remove one copy by hand.
- Files are owned by `agent`, except a file the image already has owned by root, which keeps its
  owner.
- With `--clone` and a subdirectory workspace, the parent directory is in the clone, so the files
  show up as untracked.

### Adding a kit to a sandbox

`bento kit add SANDBOX REF` applies a mixin to an existing sandbox without restarting it; a stopped
sandbox is started for it. A kit that changes the image, credentials, ports, volumes, host mounts,
agent skills, the SSH agent, resources, environment variables (an exported argument included) or
auto-stop needs a new sandbox. `kit add` then says `recreate required` and changes nothing. A kit that opens network access asks first; `-y` grants it, and without a terminal
it fails.

### Kit host mounts

A kit that declares `host-mount@1` gets a directory on your machine at the path it names, such as a
cache. It's created on first use under `~/.local/share/smolbento/kit-host-mounts/`
(`$XDG_DATA_HOME/smolbento/…`, or `$SMOLBENTO_DATA_DIR/kit-host-mounts/`), one per kit and path. All
of a kit's sandboxes share it, the agent can write it, and it survives sandbox removal. A local kit
is keyed by its directory and a published kit by its repository, so a new tag keeps the same
directory.

To bind your own directory, pass `--mount` at create:

```sh
bento create ./my-kit . --mount ~/agent-cache:/home/agent/.cache/tool
```

`--mount HOST:SANDBOX_PATH` is repeatable. `SANDBOX_PATH` must be one a kit declares (`no kit
declares host-mount@1 at "PATH"` otherwise). `HOST` is resolved from the current directory and must
exist. Mounts are set at create only: `bento run --mount` on an existing sandbox still checks `HOST`
(an error if missing or invalid), then warns and ignores it. `kit add` of such a kit says `recreate
required`. `mounts:` in an [environment file](environments.md#environments-sbxenvyaml) does the same.

`bento inspect` shows `Host mounts: HOST:PATH` (`mounts` in JSON). `rm` and `prune` never delete
these directories. `bento kit mounts ls` lists them (`ID`, the kit, its path, the host directory;
`--json` too), and `bento kit mounts rm ID…` deletes them with their contents, refusing one a
sandbox still mounts. `reset` deletes them with the rest of smolbento's data.

### The builder sandbox

Local v3 kits build with BuildKit in a hidden sandbox, `_builder`, so Docker isn't needed on your
machine. It's created on first use, stopped after each build, hidden from `bento ls`, and keeps the
build cache; `bento rm _builder` resets it (`rm --all` and `prune` leave it). Each build starts its `dockerd` if it isn't running, so a
builder left without Docker (an interrupted first start, say) recovers without losing that cache.
Builds use your global network policy (`bento policy log
_builder` shows blocks) and never get your secrets. An image that needs a login (Docker's examples
use `dhi.io`) needs a [registry credential](network-and-secrets.md#registry-credentials).

## Skills

Skills are folders with a `SKILL.md` that agents load on demand. smolbento keeps one shared store
and links it into sandboxes.

```sh
# from GitHub, or any Git URL
bento skills add anthropics/skills --skill pdf
# every skill in the repository
bento skills add anthropics/skills
# copy skills from your agents' directories
bento skills import
# SKILL and STORE columns; --json, -q
bento skills ls
# re-fetch a skill added from a repository
bento skills update pdf
bento skills rm pdf
```

The store is `~/.local/share/smolbento/agent-skills/` (`$XDG_DATA_HOME/smolbento/agent-skills`, or
`$SMOLBENTO_DATA_DIR/agent-skills`), one directory per skill. It isn't sbx's store; `import` brings
skills over, and `import --dry-run` previews them.

- `add` clones with your host `git` (HTTPS, SSH, `http://`, `git://`), so private repositories work.
  git never prompts, so set up a credential helper or SSH agent first. A failed clone prints `clone
  skills repository: exit status N: ...`.
- Each directory below the repository root with a `SKILL.md` is a skill; directories inside a skill
  aren't searched. A root `SKILL.md` makes the whole repository one skill. Symlinks and special
  files are never copied.
- The name is the `SKILL.md` `name:`, else the directory's (the repository's, for a root skill):
  anthropics/skills' `template/` becomes `template-skill`. An invalid name is skipped with a
  warning; two skills with one name is an error.
- `--skill` (repeatable, or comma-separated) picks skills by name. An existing skill asks before
  it's replaced. `-f` skips the question, and without a terminal replacing needs `-f`.
- `import` reads `~/.agents/skills`, `~/.claude/skills`, `~/.config/opencode/skills`,
  `~/.copilot/skills`, `~/.cursor/skills` and `~/.factory/skills`, in that order. On a clash the
  earlier one wins, with a warning.
- `update` works only for skills added from a repository (recorded in
  `agent-skills-metadata/sources.json`; `import` drops that record). It prints `Updated skill x` or
  `Skill "x" is already up to date` for each, then `Updated N skills in <store>`. With none, it
  prints `No repository-installed skills found`.
- `rm` asks first; `-f` skips. `import` asks only before replacing a skill.

`bento reset` deletes the store and its records.

### Sharing the store with a sandbox

`--skills` on `create` sets how the sandbox gets the store (on `run`, for a new sandbox):

| Mode | In the sandbox |
|---|---|
| `readonly` (default) | The store is mounted read-only at `/run/sbx/skills-shared`. The agent's skills directory holds one symlink per skill, such as `pdf -> /run/sbx/skills-shared/pdf`. The agent can add its own directories beside them. |
| `readwrite` | The store is mounted over the agent's skills directory. Writes there land in your store at once. |
| `off` | No store and no skills directory |

```sh
bento create claude . --skills readwrite
# the default for new sandboxes
bento settings set skills.defaultMode off
```

The mode is fixed at create. On an existing sandbox, `--skills` is ignored, like `--cpus`, and so is
a changed `skills.defaultMode`. Precedence: `--skills`, then `sandboxOptions.skills` in an
[environment file](environments.md#environments-sbxenvyaml), then the setting
([Configuration](configuration.md#settings)).

In `readonly`, links are remade at every start: a new skill is linked at the next start, and a
removed one leaves a dangling link until then. An agent-made file with a stored skill's name is left
alone. In `readwrite`, changes show at once. Agents read skills when a session starts, so start a
new session after a change.

| Agent | Skills directory (in the sandbox) |
|---|---|
| `claude` | `~/.claude/skills` |
| `codex`, `devin` | `~/.agents/skills` |
| `copilot` | `~/.copilot/skills` |
| `cursor` | `~/.cursor/skills` |
| `droid` | `~/.factory/skills` |
| `opencode` | `~/.config/opencode/skills` |
| `kiro`, `docker-agent`, `shell` | none: the store isn't shared |

`~` is `/home/agent`. Links are
made as root at each start, owned by the image's `agent` account (uid 1000 without one). A skills
directory reached through a symlink gets no links, and a required bundled skill for it fails the
create. If linking fails, the start warns (`couldn't link shared skills`) and goes on.

### Skills from kits

- `agent-skills@1` names a `path` (absolute) that gets the store, with `mode` `readonly` (default)
  or `readwrite`. Access is the narrower of the kit's mode (the widest across kits) and `--skills`.
  The store is mounted over that path, with no links. `off` leaves it out.
- `agent-skill@1` bundles a skill from the kit's image. `path` is its directory; `name` (optional)
  is its name, defaulting to the directory's. At first start smolbento checks that `SKILL.md` is a
  file and no skill of that name exists, then links it into every skills directory. A required
  bundled skill that fails either check, or has nowhere to go, fails the create and removes the
  sandbox. An optional one prints `warning: skipping skill NAME: reason` and the sandbox starts
  without it. A name that matches a stored skill is a conflict: the store link comes first.
  smolbento links bundled skills and never runs them.
- With bundled skills, no skills directory is mounted over, since that would put the kit's skills in
  your store. Every directory instead links into `/run/sbx/skills-shared`. That mount is read-write
  if any directory would have been, else read-only. With `off`, the directories hold only the
  bundled skills.
- A bundled skill named like a stored skill fails the create with `failed to compose shared skills
  into the sandbox: bundled skills NAME cannot be exposed in DIR: another skill already uses the
  name`.
- `kit add` refuses kits with either capability, since mounts are set at create. Create a new
  sandbox with the kit.

## MCP servers

Register servers once, then give them to a sandbox's agent at create.

```sh
# A remote server. ${api-key} is a secret, set separately.
bento mcp add linear --url https://mcp.linear.app/sse --header 'Authorization: Bearer ${api-key}'
bento secret set mcp:linear:api-key

# A server that runs as a command, inside the sandbox.
bento mcp add files --command npx --args -y --args @modelcontextprotocol/server-filesystem --args /workspace

bento mcp ls
bento mcp inspect linear
bento mcp rm linear

bento run claude --static-mcp linear,files
```

- `--static-mcp` applies only at create; `--static-mcp none` records no servers. `bento inspect` shows
  the set.
- At create, each remote server's host is allowed for that sandbox, and the servers are written into
  the agent's MCP config (for Claude Code, with `claude mcp add --scope user`).
- A header secret never enters the sandbox. The agent's config holds a smolvm placeholder, which
  smolvm swaps for the real value only on HTTPS requests to that server's host. Secrets are stored
  like any other (`-t`, `--ref`, `--command` work) and are global.
- A command server runs inside the sandbox, so the command must exist in the image.

Limits:

- Only the `claude` agent so far. Other agents fail the create with an error.
- OAuth isn't supported. A server that only offers OAuth login can't take a token header.
- A header secret needs an `https://` URL with a host name and no port. A server can have one header
  with a secret.
- URLs with credentials (`https://user:pass@host/`) are refused. URLs are stored as given, so keep
  secrets out of query strings.
- `localhost` URLs are refused: inside a sandbox, that means the sandbox itself.
- `bento template save` refuses a sandbox created with `--static-mcp`.
- You can edit `mcp.toml` by hand; a selected server is checked as `mcp add` checks it, before
  anything is created.
- `mcp auth`, `mcp load` and `mcp unload` aren't supported ([sbx
  compatibility](sbx-compatibility.md#mcp-servers)).

## Templates

Install your tools once in a sandbox, save it as a template, and start new sandboxes from it.

```sh
bento stop claude-myrepo
bento template save claude-myrepo myimage:v1
# also export to a file
bento template save claude-myrepo myimage:v1 -o myimage.tar
# or: create -t myimage:v1
bento run -t myimage:v1 claude .
# --json, --format json|yaml, -q
bento template ls
# name, or a 4+ hex character id prefix; -f skips the prompt
bento template rm myimage:v1
# import a file made with --output
bento template load myimage.tar
```

- The sandbox must be stopped to save it.
- `-t` looks for a saved template of that name first, then treats the value as an image. It never
  takes an id prefix (unlike `template rm`), so a name of only hex digits, such as `abcd`, is an
  image. `--pull never` works only with a saved template whose kits are in the kit cache.
- The agent must match: a `claude` template can't start a `codex` sandbox.
- `/tmp` and the workspace (mounted, not on the disk) aren't kept.
- A template keeps the sandbox's kits (pinned) and their args (not secret: they're in exported
  archives too). A create from it loads them again and
  reruns their install and startup steps, under the same kit settings as any create:
  `kit.allowedSources`, `kit.allowLocalKits`, and `kit.requireSignature` (which needs the registry,
  even with `--pull never`). With `docker.enabled=false` the docker kit is left out. A sandbox made
  from a template can't be saved yet.
- A template saved without kit records or a command is refused: save it again from a new sandbox.
  A create from a template runs the command its source sandbox ran.
- `-t` can't combine with `--kit` kits that add image layers, since the disk is saved whole.
  Layer-free kits such as `docker` work.
- Removing a template doesn't affect sandboxes made from it. Kit install steps run again for each
  new sandbox.
