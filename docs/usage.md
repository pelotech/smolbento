# Usage

Examples use `sbt`; `sbx` and `bento` are the same program.

## Run an agent

```sh
cd ~/code/myrepo
sbt run claude
```

`run` creates the sandbox if needed, starts it if stopped, and attaches you. The sandbox is named
`<agent>-<directory name>` (here `claude-myrepo`), so the same agent in the same directory
reattaches.

When the last attached session exits (closing the terminal counts), the sandbox stops. Its disk is
kept, so the next `run` resumes with what the agent installed.

| Form | Effect |
|---|---|
| `sbt run claude` | Sandbox for the current directory |
| `sbt run claude ~/code/api ~/code/docs:ro` | First path is the workspace; more paths are mounted; `:ro` is read-only |
| `sbt run --name claude-myrepo` | Reattach by name |
| `sbt run --name review claude .` | A second sandbox on the same directory |
| `sbt run -d claude` | Start and leave running; prints the name |
| `sbt run --rm claude` | Delete on exit (kept, with a warning, while another session is attached) |
| `sbt run claude -- -c` | Pass arguments to the agent |

`run` exits with the agent's exit status.

### Agent arguments

Arguments after `--` are **appended** to the agent's default command if the first one starts with
`-`. Otherwise they **replace** its flags. `sbt run claude -- -c` runs `claude
--dangerously-skip-permissions -c`.

### Agents

| Agent | Runs | Image (`docker/sandbox-templates:`) |
|---|---|---|
| `claude` | `claude --dangerously-skip-permissions` | `claude-code-docker-0.10.0` |
| `codex` | `codex --dangerously-bypass-approvals-and-sandbox` | `codex-docker-0.11.0` |
| `copilot` | `copilot --yolo` | `copilot-docker-0.11.0` |
| `cursor` | `cursor-agent --yolo` | `cursor-agent-docker-0.11.0` |
| `devin` | `devin --permission-mode dangerous --respect-workspace-trust=false` | `devin-docker-0.11.0` |
| `docker-agent` | `docker-agent run --yolo` | `docker-agent-docker-0.11.0` |
| `droid` | `droid` | `droid-docker-0.11.0` |
| `kiro` | `kiro chat --trust-all-tools` | `kiro-docker-0.4.0` |
| `opencode` | `opencode` | `opencode-docker-0.11.0` |
| `shell` | `bash -l` | `shell-docker-0.10.0` |

These are the Docker sandbox images that `sbx` uses. Renovate keeps the tags current. For another
image, use `-t <image>`; it needs an `agent` user. The first run of an agent pulls its image, which
takes a minute or two.

`gemini` is retired, as in sbx 0.53, and a new sandbox can't use it. Use the `antigravity` kit (`sbt
create docker.io/sbx/antigravity:latest .`) or `docker.io/sbx/gemini-kit:latest`, which keeps Gemini
CLI running. In an environment file, keep `agent: gemini` and add the gemini kit to `kits:`.
Existing `gemini` sandboxes keep working.

## Create without attaching

```sh
sbt create claude .            # create and start; workspace = current directory
sbt create shell               # no path: no host directory mounted
```

A sandbox made by `create` runs until you stop it.

`run` and `create` print their steps (SANDBOX, KITS when a kit was pulled or built, IMAGE, SETUP)
and then `Created sandbox NAME`. `create` adds `try: sbt run --name NAME`. `start` prints `○ NAME —
starting…`, then `✓ Started NAME`. Without a terminal, each step prints a line when it starts and
another when it ends:

```
SANDBOX
  Name:       shell-proj
  Agent:      shell
  Workspace:  -
  Image:      docker/sandbox-templates:shell-0.10.0
  CPU:        3
  Memory:     1536 MiB

IMAGE
  ○ image — preparing…
  ✓ image — ready

SETUP
  ○ sandbox — starting…
  ✓ sandbox — started

  ✓ Created sandbox shell-proj
        try: sbt run --name shell-proj
```

On a terminal, each step redraws in place with a spinner, and a pull shows its percentage (`⠙ image
— pulling… 42%`). The image step says `preparing` until smolvm reports a pull; an image smolvm has
cached doesn't pull (see [`smolvm.image-cache-size`](configuration.md#settings)).

Progress goes to stdout. Scripts that capture output (`name=$(sbt run -d …)`) pass `--no-progress`,
which also hides the `Created` and `try:` lines. `run -d --no-progress` then prints only the name.

| Option | Meaning |
|---|---|
| `--name NAME` | Letters, digits, `-` and `.`; at least 2 characters |
| `--cpus N` | `0` or unset: all host CPUs |
| `-m, --memory SIZE` | Such as `4g` or `512m`. Default: half of host memory, from 512 MiB to 32 GiB |
| `-e, --env KEY=VALUE` | A bare `KEY` copies the host's value |
| `--env-file FILE` | `KEY=VALUE` lines |
| `-p, --publish [[127.0.0.1:]HOST:]PORT[/udp]` | Published on `127.0.0.1`; with no host port, a free one is picked |
| `-t, --template TEMPLATE` | Another image, or a saved [template](#templates) |
| `--clone` | The agent works on its own clone of the repo ([Clone mode](#clone-mode)) |

Other create-time options have their own sections: `--kit` ([Kits](#kits)), `--mount` ([Kit host
mounts](#kit-host-mounts)), `--deny-network` ([Network policy](#network-policy)), `--skills`
([Sharing the store](#sharing-the-store-with-a-sandbox)) and `--static-mcp` ([MCP
servers](#mcp-servers)). These options are fixed at create. To change one, `rm` the sandbox and
create it again.

## Clone mode

```sh
cd ~/code/myrepo
sbt run --clone claude .
```

The agent works on a clone of your repo. Your checkout is mounted read-only at
`/run/sandbox/source`, and on first start it's cloned to the same path on the sandbox's own disk.
The clone survives stop and start and is writable, so `:ro` on a `--clone` workspace is ignored.

The clone starts from your repo's `HEAD` (for a linked worktree, its branch, or its commit when
detached). If that checkout fails, it starts from the source repo's default `HEAD` with a warning.
Uncommitted changes aren't carried over.

Remotes (`origin`, `upstream`, …) are copied, except local-path and `file://` ones. User names and
tokens in HTTPS URLs are left out. SSH remotes are copied but have no keys in the sandbox, so for
pushes use an HTTPS remote with `sbt secret set github`. The copy is redone on every start. Remotes
you add or change reach the clone then, and a remote the agent changed is reset to your URL.

The agent can read your whole `.git` at `/run/sandbox/source`, including tokens in remote URLs and
`http.extraHeader` (see [sbx compatibility](sbx-compatibility.md)). Keep credentials out of it. Use
a credential helper on your machine, or `sbt secret`. `create --clone` warns about a token in a
remote URL.

The agent's commits come back through a remote named `sandbox-<name>`. Only branches come back; tags
stay in the sandbox (`--no-tags`).

```sh
git fetch sandbox-claude-myrepo
git log sandbox-claude-myrepo/main
git merge sandbox-claude-myrepo/main          # or check out, cherry-pick, …
```

- `run` fetches `sandbox-<name>` on exit and prints git's summary. Turn it off with `sbt settings
  set clone.fetch-on-exit false`. A failed fetch only warns. The automatic fetch checks objects
  (`fetch.fsckObjects`) and doesn't recurse into submodules.
- Any fetch from a stopped clone sandbox starts it, fetches, and stops it again. That includes `git
  fetch --all`, `git remote update` and an IDE's background fetch.
- A `git fetch` that overlaps a `run` exiting can leave the sandbox running. `sbt stop <name>` stops
  it.
- `git fetch` runs `smolbento _upload-pack <name>`, so `smolbento` must be on your `PATH`.
- `--clone` needs a workspace in a git repository and git 2.31 or newer on your machine. The image
  needs git too; the built-in images have it, and with `-t` pick one that does. A failed clone fails
  the start with git's error, and the sandbox from a failed first start is removed. Fix the cause
  and rerun `create` or `run`.
- `--clone` applies only at create.
- `sbt rm`, `prune` and `reset` remove the `sandbox-<name>` remote and its branches. To keep a
  branch: `git branch keep sandbox-<name>/main`.
- `run --rm` keeps the remote, so fetched commits survive; later fetches fail. Remove it with `git
  remote remove sandbox-<name>` when done.

## Fork

```sh
sbt fork claude-myrepo                        # one copy: claude-myrepo-fork-1
sbt fork claude-myrepo --count 3              # three copies, for parallel attempts
sbt fork claude-myrepo --name claude-try-b    # pick the copy's name
```

`fork` copies a running sandbox (memory, processes and disk) and prints the new names, one per line.
A stopped sandbox is started first. Copies are copy-on-write, so they're quick and small. After that
they diverge. A file written in one isn't seen in the others or the original.

Use forks for parallel attempts or as an undo point. Fork before risky work, and if it goes wrong,
`sbt rm` the copy and fork the original again.

- Only clone sandboxes and sandboxes without a writable host folder can be forked. `:ro` workspaces
  are fine.
- Forks of forks aren't supported. Fork the original.
- A fork uses its original's sandbox secrets (its own wins), then the global ones. It gets a copy of
  the original's per-sandbox policy rules, which you can change per fork. `sbt secret ls --sandbox
  FORK` lists the original's secrets too.
- A clone fork has its own remote: `git fetch sandbox-claude-myrepo-fork-1`.
- `sbt rm` of a sandbox with forks fails unless the forks go in the same command. `prune` and
  `reset` remove forks first; `prune` keeps a stopped sandbox while it has forks.
- `sbt ls --json` shows `fork_of`. Published ports get new host ports; see `sbt ports <fork>`.
- smolvm limits how deep copies can chain, and `fork` says so.
- Sandboxes started before fork support, or while `fork.enabled` was off, need one restart (`sbt
  stop NAME && sbt start NAME`) first.

Clone and mountless sandboxes start branchable. That costs idle memory that smolvm doesn't return to
your machine, and it carries a Linux secret-exposure risk (see [Security](SECURITY.md)). If you
don't use fork, turn it off with `sbt settings set fork.enabled false`; it applies from each
sandbox's next start.

## Run commands inside

```sh
sbt exec claude-myrepo git status
sbt exec -it claude-myrepo bash               # interactive shell
sbt exec --privileged claude-myrepo apt-get install -y ripgrep
sbt exec -u root -w /tmp -e DEBUG=1 claude-myrepo env
```

`exec` starts a stopped sandbox first and runs as `agent` in the workspace, unless you pass `-u` or
`-w`. `--privileged` runs as root. It exits with the command's status.

The agent and every `exec` see the sbx sandbox variables: `SANDBOX_NAME`, `SANDBOX_VM_ID` (the
name), `SANDBOX_ID` (a UUID, new per sandbox and per fork), `WORKSPACE_DIR`, `SBX_AGENT`, and for
the `shell` and `claude` presets (not kits of those names) `SBX_CRED_<SERVICE>_MODE` (`apikey` if
that secret was set at create, else `none`). The `claude` preset also gets `IS_SANDBOX=1`. Your `-e`
wins. Differences from sbx are in [sbx compatibility](sbx-compatibility.md#sandbox-environment).

## Browser and clipboard

The sandbox can open URLs in your browser and copy text to your clipboard, whenever it runs. On
macOS (launchd) and Linux (`systemd --user`) a service unit owns the socket, so nothing needs to be
attached; without a usable service manager (a container, CI without a user session) it works only
while `sbt run` or `sbt exec -it` is attached.

```sh
# inside the sandbox
xdg-open https://github.com/login/device    # opens in your host browser
git diff | wl-copy                          # or xclip, xsel, pbcopy, clip.exe
```

- Only `https://` URLs open. Others, or any URL when nothing serves the socket, print `Open this URL
  in your browser: URL`.
- Copying is text only. Reading the clipboard (`wl-paste`, `xclip -o`, `xsel -o`) prints nothing,
  and images can't be pasted. Copying when nothing serves the socket fails with `<command>: failed
  to write host clipboard`.
- Browser logins work. For a `redirect_uri` of `http://localhost:PORT/…` or
  `http://127.0.0.1:PORT/…`, smolbento listens on your `127.0.0.1:PORT` for 10 minutes (the
  connection's process stays that long) and relays the callback. If something else answers that port, it warns and still
  opens the URL. A session relays at most 4 ports. A callback with a body
  (`response_mode=form_post`) loses it; query-string redirects work.
- Over SSH without a forwarded display (Linux: no `DISPLAY` or `WAYLAND_DISPLAY`; macOS: always over
  SSH), URLs are printed instead.
- `sbt settings set browser.enabled false` stops URL opening and the login relay. Copying still
  works.
- The shims go in `/usr/local/bin` on every start and need `curl` in the image. `BROWSER` is
  `xdg-open`, so agents such as Claude Code's `/login` open the browser.
- The unit runs `sbt _serve bridge NAME` for each connection, with the settings and `PATH` of the
  last `sbt` that touched the sandbox (`create`, `start`, `run`, `exec` rewrite a unit that
  differs, so an upgraded binary or a new `PATH` follows). Units are written at create for sandboxes
  created by this version; earlier ones, and without a service manager, are served only while
  attached (the first attached session serves it).
- Sandboxes created before the bridge have none; recreate them. The socket directory must be
  private and yours (0700), checked at create and at start (macOS: `~/Library/Application
  Support/smolbento/sock`; Linux: `$XDG_RUNTIME_DIR/smolbento`; attached-only serving:
  `/tmp/sbt-<uid>`), or the bridge is skipped with a warning.
- Forks don't install the shims or get units, but keep the parent's socket mount, so they can use
  the parent's bridge while the parent's unit (or attached session) serves it.
- `sbt rm`, `prune`, `reset` and `env rm` remove a sandbox's units and sockets. Units of a sandbox
  deleted with `smolvm machine delete` are removed by the next `create`, `start`, `run`, `exec`,
  `rm` or `prune` (never by `ls`); `prune --dry-run` lists them and `diagnose` reports them.

## SSH agent

Sandboxes of the built-in agents can use your SSH agent. Git over SSH and commit signing work, and
your keys never enter the sandbox.

```sh
# inside the sandbox ($SSH_AUTH_SOCK is /run/ssh-agent.sock)
ssh-add -l                                  # lists your keys
git commit -S -m "signed"                   # with gpg.format=ssh
ssh-add -D                                  # fails: the sandbox can't change your agent
```

- The agent is `SSH_AUTH_SOCK` when you run `sbt`, or the socket in `ssh.agentSocketPath`. With
  none, or with `ssh.agentForwardingEnabled` set to `false`, the sandbox is created without one,
  silently.
- Only listing keys and signing get through. Adding, removing or locking keys fails.
- With a service manager (launchd on macOS, `systemd --user` on Linux) a unit owns the sandbox's
  agent socket and runs `sbt _serve agent NAME` for each connection, so the agent answers whenever
  the sandbox runs, attached or not, across stop and start. The unit uses `ssh.agentSocketPath`,
  else the `SSH_AUTH_SOCK` of the user session (launchd supplies macOS's; on Linux the unit gets
  that of the last `sbt` that wrote it). Without a service manager, or for a sandbox created before
  units, it is served only while `sbt` runs for the sandbox (`run`, `exec -it`, plain `exec`; the
  first `sbt` to start serves it). A socket path of 104 bytes or more (a very long home
  directory) also means no units.
- Units live in `~/Library/Application Support/smolbento/launchd` (`dev.smolbento.<id>.<sandbox>.agent.plist`; not in `~/Library/LaunchAgents`, which makes macOS announce a background item per sandbox, and not persistent: they're loaded again when `create`, `start`, `run` or `exec` find them unloaded after a reboot) or
  `~/.config/systemd/user` (`smolbento-<id>-<sandbox>-agent.socket`), named with a short hash of
  smolbento's data dir; they exist only for sandboxes with a runtime grant or the bridge, and go with
  the sandbox (see [Browser and clipboard](#browser-and-clipboard)). The socket is `0600` in a
  private directory of yours.
- Each connection re-reads settings. `sbt settings set ssh.agentForwardingEnabled false` refuses new
  connections at once; open ones stay. A changed `ssh.agentSocketPath` applies to new connections.
- Kits request it with `ssh-agent@1`: `phase: install`, `runtime` or both, and `sign: [git, …]` to
  allow only those namespaces. A v3 workload kit gets no agent without it. A required grant with no
  agent stops the create (`kit K: com.docker.sandbox/ssh-agent@1 needs an SSH agent, but SSH_AUTH_SOCK is unset`); an
  optional one is left out with a note. An `install` grant is served only during install steps, and
  a step sees `SSH_AUTH_SOCK` only if it lists it in `env`.
- `authenticate: [host | user@host]` (with `unrestricted: false`) allows logins to those servers
  and nothing else. A login is signed only when the same connection first sent a session binding
  (OpenSSH 8.9+ does) that smolbento verified, for that login's session, with a host key your
  `known_hosts` lists for a named server (and the named user, if the entry has one). Host keys come
  from `ssh.knownHostsFile` (default `~/.ssh/known_hosts`), read at each login, never from the
  sandbox; log in once from your own shell, or add the key, first. Entries merge per phase like
  `sign`.
- The grant is fixed at create. Sandboxes created before this feature have no agent; recreate them.
- Forks keep the parent's socket mount, so they can use the parent's grant while the parent is
  served.

## Docker inside a sandbox

Every sandbox runs its own Docker engine, so agents can `docker build` and `docker compose up`
without touching your host's Docker. Its storage lives on the sandbox's disk and survives restarts.

To skip Docker (smaller images, faster first pull), run `sbt settings set docker.enabled false`
before creating sandboxes; agents then use the plain image variants.

The engine comes from the shipped `docker` kit ([Kits](#kits)). Docker-enabled images get it
automatically; add it to any image with `--kit docker`, as in `sbt create -t alpine --kit docker
shell .`. dockerd starts on every start, and logs to `/var/log/dockerd.log`.

## Kits

Kits add tools, files, network rules, credentials and setup steps. smolbento runs Docker Sandboxes
kits (v3, and v2 `spec.yaml`) and smolvm Smolfiles.

```sh
sbt run claude . --kit docker.io/acme/postgres-kit:1    # add a mixin kit to an agent
sbt run docker.io/acme/my-agent:1 .                     # a workload kit replaces the agent
sbt create shell . --kit ./my-kit --kit-arg region=eu   # a local kit, with an argument
sbt kit inspect ./my-kit                                # what it provides and asks for
sbt kit validate ./my-kit                               # check it without running it
sbt kit add claude-myrepo ./my-mixin                    # add a mixin to an existing sandbox
```

A **mixin** adds to an agent (`--kit`, repeatable). A **workload** kit replaces the agent. Pass it
where the agent name goes, and the sandbox takes its name. Its image's command runs as the image's
`USER` (root if none) under `/bin/bash`, in the workspace path, and `sbt exec` uses the same user.
smolvm maps the workspace to that user. A workload with no `ENTRYPOINT` or `CMD` is refused, and one
without `/bin/bash` can't start its agent. A v3 workload's `ENTRYPOINT` + `CMD` also run at every
boot (as the image user), as the kit spec's default launch mode says; the machine stays up if it
exits, and `sbt run` still starts its own interactive session.

| Reference | Kit |
|---|---|
| `docker` | The shipped Docker kit |
| `docker.io/acme/kit:1`, `ghcr.io/acme/kit@sha256:…` | A published kit, pulled from its registry |
| `./my-kit` (a directory with one `*.yaml` starting `# syntax=docker/sandbox-kit:3`), or that file | A local v3 kit, built in the builder sandbox (below) |
| `./my-kit` (a directory with a `spec.yaml`) | A local v2 kit |
| `./Smolfile`, `./x.smolfile` | A smolvm Smolfile |

v2 and v3 kits can't share a sandbox. Agent presets, `docker` and a Smolfile can go with either.

A local kit is always a path (`./my-kit`, `../kits/my-kit`, `.`, or absolute). A bare word is never
a kit, even if a directory has that name. `sbt create my-kit` fails with `unknown agent "my-kit"`,
and `--kit my-kit` says `not a local path and does not look like a registry reference`. Write
`docker.io/library/alpine` for the alpine image.

Kits declare versions with `provides: [postgres@16.2.0]` and `requires: ["postgres >= 16"]`. A
missing or mismatched capability stops the create with `resolve: the kit set is not coherent:` and
one line per problem. Agent presets provide their own name, so a v2 mixin's `requires.agent: claude`
works on `claude`.

`sbt kit inspect REF` prints the kit's summary, capabilities, source, provides, requires,
credentials (with the hosts each secret goes to) and arguments. `--format json` (or `--json`) and
`--format yaml` print a v2-shaped descriptor with smolbento's extras under `smolbento`. `sbt kit
validate REF` prints `✓ REF — valid`, or the error and exits 1; with `--json` or `--format
json|yaml` it prints `{reference, kind, valid, warnings}`, plus `errors` when invalid. `--offline`
checks a local v2 kit or Smolfile without the network or source policy.

`--kit-arg NAME=VALUE` applies to every kit, `--kit-arg KIT.NAME=VALUE` to one, and `--kit-args-file
FILE` reads `NAME=VALUE` lines. Files are read first, then `--kit-arg`; the last value wins, and a
per-kit value beats an all-kits one. A `KIT.NAME` for a kit not in the sandbox is ignored. Argument
values aren't secret (they reach the environment and smolvm's machine config), so put secrets in
[credentials](#secrets). An argument with no value and no default fails with `create-phase kit arg
"x" has no resolved value`; `--kit-arg x=` sets it empty. `--kit-arg` without a kit is an error.
Unquoted numbers and booleans in `default:` and `enum:` are read as strings.

What a kit does, and when:

- On first start, install steps run once, as root, in a workload image's `WORKDIR` (`/` otherwise),
  with network only for installing. A failing step, or a kit file that can't be written, removes the
  sandbox. Fix the cause and run the same command. In a v2 kit, `files/workspace` and `${WORKDIR}`
  are the primary workspace, or `/home/agent/workspace` without one.
- On every start, startup steps run in kit order, before the agent. A failing one fails the start
  (`kit startup exited with code N`). A `background: true` step (such as the `docker` kit's
  `dockerd`) keeps running; if it fails, only the log records it. A step that doesn't finish holds
  up the start; there is no timeout, as in sbx.
- Logs go to `/var/log/sbx-kit-startup.log` in the sandbox. Each start adds a `=== dispatcher run …
  ===` line, each finished step an `ok /etc/smolbento/startup.d/NN-<kit>.sh hook N` line, and a
  failing step its output and exit code.
- A failing startup step at create leaves the sandbox created, with a warning, and stopped. Each
  later start fails until the step succeeds. `kit add` only warns.
- Startup steps run as `agent` unless they name a user (a numeric user runs as the account with that
  uid). The `docker` kit runs before your kits.
- A v3 install step gets a clean environment (`PATH`, `HOME`, `USER`, `TERM`, the proxy and CA
  variables, and what its `env` lists). Startup steps and v2 steps get the full sandbox environment.
- A missing credential doesn't block create. You get `WARN: required credential not found for
  service SERVICE` and the `sbt secret set` command. Requests go out without it until you set it and
  recreate the sandbox. A built-in service's secret goes only to its own hosts
  ([Security](SECURITY.md#kits)). A credential needed only for install is available during install;
  the sandbox then restarts once without it, and later requests to its hosts get `502`.
- Volumes live on the sandbox's disk and are removed with it. Host mounts are shared and kept ([kit
  host mounts](#kit-host-mounts)).

Only Docker Hub kits load by default, plus local kits. See [Configuration](configuration.md) for
`kit.allowedSources` and `kit.allowLocalKits`, and [Security](SECURITY.md#kits) for what a kit can
open.

### Agent instructions from kits

Kit instructions go in the agent's file in the workspace's parent directory, inside the sandbox
only. For workspace `~/src/app`, claude reads `~/src/CLAUDE.md`, gemini `~/src/GEMINI.md`, and other
agents `~/src/AGENTS.md`. With no workspace, `/home/agent` is used. A workload kit can name its own
file, and its text is appended.

Each mixin's text goes to `kits-agent-context/<kit>.md` beside that file, and the file gets a `##
Kits` list between `<!-- sbx:kits-section start -->` and `<!-- sbx:kits-section end -->`. `kit add`
adds a line to the list. Unlike sbx, smolbento writes no platform preamble.

- Nothing is written on your machine. A file that would land in a mounted workspace is skipped with
  a warning.
- A workload kit with no agent file drops mixin instructions, with a warning.
- Files are owned by `agent`, except a file the image already has owned by root, which keeps its
  owner.
- With `--clone` and a subdirectory workspace, the parent directory is in the clone, so the files
  show up as untracked.

### Adding a kit to a sandbox

`sbt kit add SANDBOX REF` applies a mixin to an existing sandbox without restarting it; a stopped
sandbox is started for it. A kit that changes the image, credentials, ports, volumes, resources,
environment variables or auto-stop needs a new sandbox. `kit add` then says `recreate required` and
changes nothing. A kit that opens network access asks first; `-y` grants it, and without a terminal
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
sbt create ./my-kit . --mount ~/agent-cache:/home/agent/.cache/tool
```

`--mount HOST:SANDBOX_PATH` is repeatable. `SANDBOX_PATH` must be one a kit declares (`no kit
declares host-mount@1 at "PATH"` otherwise). `HOST` is resolved from the current directory and must
exist. Mounts are set at create only: `sbt run --mount` on an existing sandbox still checks `HOST`
(an error if missing or invalid), then warns and ignores it. `kit add` of such a kit says `recreate
required`. `mounts:` in an [environment file](#environments-sbxenvyaml) does the same.

`sbt inspect` shows `Host mounts: HOST:PATH` (`mounts` in JSON). `rm`, `prune` and `reset` never
delete these directories; delete one yourself when no sandbox needs it.

### The builder sandbox

Local v3 kits build with BuildKit in a hidden sandbox, `_builder`, so Docker isn't needed on your
machine. It's created on first use, stopped after each build, hidden from `sbt ls`, and keeps the
build cache; `sbt rm _builder` resets it. Builds use your global network policy (`sbt policy log
_builder` shows blocks) and never get your secrets. An image that needs a login (Docker's examples
use `dhi.io`) needs a [registry credential](#registry-credentials).

## Skills

Skills are folders with a `SKILL.md` that agents load on demand. smolbento keeps one shared store
and links it into sandboxes.

```sh
sbt skills add anthropics/skills --skill pdf     # from GitHub, or any Git URL
sbt skills add anthropics/skills                 # every skill in the repository
sbt skills import                                # copy skills from your agents' directories
sbt skills ls                                    # SKILL and STORE columns; --json, -q
sbt skills update pdf                            # re-fetch a skill added from a repository
sbt skills rm pdf
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

`sbt reset` deletes the store and its records.

### Sharing the store with a sandbox

`--skills` on `create` sets how the sandbox gets the store (on `run`, for a new sandbox):

| Mode | In the sandbox |
|---|---|
| `readonly` (default) | The store is mounted read-only at `/run/sbx/skills-shared`. The agent's skills directory holds one symlink per skill, such as `pdf -> /run/sbx/skills-shared/pdf`. The agent can add its own directories beside them. |
| `readwrite` | The store is mounted over the agent's skills directory. Writes there land in your store at once. |
| `off` | No store and no skills directory |

```sh
sbt create claude . --skills readwrite
sbt settings set skills.defaultMode off          # the default for new sandboxes
```

The mode is fixed at create. On an existing sandbox, `--skills` is ignored, like `--cpus`, and so is
a changed `skills.defaultMode`. Precedence: `--skills`, then `sandboxOptions.skills` in an
[environment file](#environments-sbxenvyaml), then the setting
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

`~` is `/home/agent`. Sandboxes created before skills existed have none; recreate them. Links are
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
sbt mcp add linear --url https://mcp.linear.app/sse --header 'Authorization: Bearer ${api-key}'
sbt secret set mcp:linear:api-key

# A server that runs as a command, inside the sandbox.
sbt mcp add files --command npx --args -y --args @modelcontextprotocol/server-filesystem --args /workspace

sbt mcp ls
sbt mcp inspect linear
sbt mcp rm linear

sbt run claude --static-mcp linear,files
```

- `--static-mcp` applies only at create; `--static-mcp none` records no servers. `sbt inspect` shows
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
- `sbt template save` refuses a sandbox created with `--static-mcp`.
- You can edit `mcp.toml` by hand; a selected server is checked as `mcp add` checks it, before
  anything is created.
- `mcp auth`, `mcp load` and `mcp unload` aren't supported ([sbx
  compatibility](sbx-compatibility.md#mcp-servers)).

## Templates

Install your tools once in a sandbox, save it as a template, and start new sandboxes from it.

```sh
sbt stop claude-myrepo
sbt template save claude-myrepo myimage:v1
sbt template save claude-myrepo myimage:v1 -o myimage.tar   # also export to a file
sbt run -t myimage:v1 claude .                 # or: create -t myimage:v1
sbt template ls                                # --json, --format json|yaml, -q
sbt template rm myimage:v1                     # name, or a 4+ hex character id prefix; -f skips the prompt
sbt template load myimage.tar                  # import a file made with --output
```

- The sandbox must be stopped to save it.
- `-t` looks for a saved template of that name first, then treats the value as an image. It never
  takes an id prefix (unlike `template rm`), so a name of only hex digits, such as `abcd`, is an
  image. `--pull never` works only with a saved template.
- The agent must match: a `claude` template can't start a `codex` sandbox.
- `/tmp` and the workspace (mounted, not on the disk) aren't kept.
- A sandbox made from a template, or running a kit workload (an agent that isn't a built-in preset),
  can't be saved yet.
- `-t` can't combine with `--kit` kits that add image layers, since the disk is saved whole.
  Layer-free kits such as `docker` work.
- Removing a template doesn't affect sandboxes made from it. Kit install steps run again for each
  new sandbox.

## Environments (sbxenv.yaml)

`sbt env` reads the same `sbxenv.yaml` files as `sbx env` (schema `"1"`). They describe a sandbox's
agent, workspace, kits, ports, variables and secrets.

```yaml
schemaVersion: "1"
agent: claude
name: myrepo
workspace: .
args:
  region:
    default: eu-west-1
env:
  AWS_REGION: ${{ env.args.region }}
ports:
  - host: 8080
    sandbox: 8080
secrets:
  github:
    command: gh auth token
sandboxOptions:
  cpus: 4
  memory: 8g
```

```sh
sbt env plan                         # show what applying would do; changes nothing
sbt env create                       # from ./sbxenv.yaml: plan, ask once, create (no attach)
sbt env run -f ./team ./local.yaml   # create if missing, then attach; -f skips the question
sbt env exec -- make test            # run a command in the environment's sandbox
sbt env rm                           # remove the sandbox and the secrets scoped to it
```

- Each `PATH` is a file or a directory holding `sbxenv.yaml`. With none, `~/.sbxenv.yaml` (if
  present) then `./sbxenv.yaml` are read. Maps merge by key, lists concatenate, later values win; an
  empty `key:` keeps the earlier value. Relative paths are relative to the file naming them. `${{
  env.projectDir }}` is the first `PATH`'s directory (the current directory with no `PATH`, even
  when `~/.sbxenv.yaml` is read). `${{ env.fileDir }}` is the declaring file's directory.
- Only `true` and `false` are booleans. Text fields take numbers and booleans as written: `PORT:
  8080` and `DEBUG: on` are the strings `8080` and `on`.
- `~/.sbxenv.yaml` applies to every environment and can be enough alone. `sbt env run` then works in
  a directory with no `sbxenv.yaml`. It can't set `name`, and its `workspace` must be `${{
  env.projectDir }}` or below, as in `workspace: {path: ${{ env.projectDir }}, clone: true}`.
- Args are declared under `args:` and used as `${{ env.args.NAME }}`. Each needs exactly one of
  `default` or `required: true`, and may set `enum` or `pattern` (not both). Set values with
  `--env-arg NAME=VALUE` or `--env-args-file FILE`; `--env-arg` wins.
- The name comes from `name:` or `--name`, otherwise `<agent>-<workspace directory>`. Give every
  command the `--name` you created the sandbox with.
- `env plan` prints the changes and whether applying would ask. `+` adds, `~` changes, `-` removes,
  `>` is a host command that runs again, `!` is an unapproved item the plan doesn't add (a path on
  your machine, or a `preRemove` command). A change only a new sandbox picks up says `waits for the
  next create`; `env` values and `initialize` apply at once.
- `env create` and `env run` ask `Approve this plan? (y/N)`. A yes is remembered until the files or
  the plan change. `-f/--force` approves one invocation without remembering it. Without a terminal
  and without `--force`, an unapproved plan is refused. `env rm` asks `Remove? [y/N]` and forgets
  the approval. `env exec` never asks.
- Lifecycle commands and `command:` sources of secrets and registries run on your machine with your
  privileges. A file that declares any asks on every `env create` and `env run`. `sbt settings set
  env.rememberHostCommands true` keeps an approval until the commands change.
- Commands run through `sh -c`, in `initialize` (every create and run, before anything),
  `postCreate` (after a new sandbox is created) and `preRemove` (`env rm`, after you confirm). A
  phase stops at the first failure or timeout. A failing `initialize` stops before anything is
  created; a failing `postCreate` keeps the sandbox and says to `sbt env rm`; a failing `preRemove`
  only warns and removal goes on. Commands get `sbt`'s environment plus `SBX_LIFECYCLE_PHASE`,
  `SBX_ENV_FILE`, `SBX_ENV_FILES` (joined with `:`), `SBX_ENV_DIR`, `SBX_SANDBOX_NAME`, `SBX_AGENT`
  and `SBX_WORKSPACE`, but not the file's `env` or any secret. Make `initialize` safe to run twice.
  `--skip-host-commands` (on `env create`, `run`, `rm` and `plan`) skips all three phases without
  changing your approval.
- `env run` launches `entrypoint` and `cmd` in place of the agent. With only `cmd`, the agent's own
  command gets it as arguments. Plain `sbt run NAME` is unaffected. The last file wins. Arguments
  after `--` (`sbt env run . -- --base HEAD`) replace `cmd` for that run.
- There's no `--agent` flag, and sbx has none either. Set `agent: ${{ env.args.agent }}` with a
  declared `agent` arg instead: `sbt env run --env-arg agent=opencode -- -c` runs `opencode -c`.
- Registry logins pull this sandbox's image and kits. They're resolved at create and stored for that
  sandbox only, ahead of a host-wide `sbt secret set --registry` login. They're removed with the
  sandbox.
- Bindings add extra domains a service's credential may go to. As in sbx, they're global: they go
  into your secrets file at create, for every later sandbox. `env rm` leaves them; `env rm
  --prune-bindings` removes each declared service's whole binding. The service must be one `sbt
  secret set` knows.
- `mcp.servers` entries with a `url` are registered as `sbt mcp add` would (they stay after `env
  rm`) and given to the agent as `--static-mcp` does, with the same limits. Entries with a `command`
  are refused.
- `env create` refuses an existing sandbox (use `env run`, or `env rm` first). Secrets are stored
  before the sandbox is made; a failed create leaves them, and `env rm` with the same files removes
  them.
- On an existing sandbox, `env run` starts it if needed and attaches, passing the file's current
  `env` values. Other changes (kits, ports, workspaces, secrets, options) need `env rm` and `env
  create`.
- `env exec` takes the `sbt exec` flags and the command after `--`. Without `--`, every argument is
  the command and files come from the current directory. A command with options needs `--` (`sbt env
  exec -- ls -la`).
- `agent` names a built-in agent, or a workload kit from `kits:` (a local kit by directory name, a
  registry kit by the last part of its repository name). Other kits are added to it. A missing local
  path, a `.zip` or a `git+` source is refused before any secret is stored. An unpullable registry
  kit fails after that; `env rm` removes the secrets.
- `mounts:` maps a kit's [host mount](#kit-host-mounts) path to your directory, as `--mount` does.
  Relative paths are relative to the file naming them; later files win per path.

Lifecycle, as written in a file:

```yaml
lifecycle:
  initialize:            # every `env create` and `env run`, before anything else
    - name: deps         # optional label
      command: ./scripts/setup.sh
      workdir: ./tools   # optional; default: the project directory
      timeout: 90s       # optional; a duration such as 1.5s or 1m30s
  postCreate: [...]
  preRemove: [...]
```

A background command must redirect its output (`cmd >/dev/null 2>&1 &`), or it fails five seconds
after it exits. Ctrl-C ends the running command and what it started.

Registry logins and bindings:

```yaml
registries:
  ghcr.io:
    username: {value: me}
    secret: {command: gh auth token}
bindings:
  github:
    apiKey:
      domains: [uploads.github.com]
```

Not supported yet (exit 2, naming the field): `mcp` servers with a `command`,
`sandboxOptions.profile`, `display`, `gpu` and `usb`, and `pullPolicy: always`. `fuse` and
`pullPolicy: missing|never` are accepted. Environment files inside a writable mounted workspace are
made read-only at each start, unless `writableEnvFiles: true`. `refresh` and `backend` on a secret
do nothing. Secret service names must be ones `sbt secret set` knows. See [sbx
compatibility](sbx-compatibility.md#environment-files).

## Files and ownership

Workspaces are mounted at the same absolute path as on your machine, so paths in errors and logs
match. In the sandbox, smolvm shows the workspace as owned by `agent`, and files the agent creates
appear on your machine owned by you. On macOS, the virtiofs mount also makes them private to you, so
files are mode 600 and directories mode 700.

## Network policy

Creating or starting a sandbox needs a network policy. The first time, `sbt` asks which one to use
and saves the answer:

| Mode | Meaning |
|---|---|
| `allow-all` | Open network |
| `balanced` | Default deny, plus Docker Sandboxes' baseline of 195 rules (AI APIs, package registries, code hosts, container registries, cloud services, OS packages, certificate checks, Nix caches) |
| `deny-all` | Nothing, unless you allow it |

Without a terminal, `sbt` fails rather than asking. In scripts and CI, run `sbt policy init
balanced`.

```sh
sbt policy allow network api.example.com,*.example.org   # applies to running sandboxes at once
sbt policy deny network tracking.example.com
sbt policy allow network internal.example.com --sandbox claude-myrepo
sbt policy ls                       # --wide shows every host and enforcement notes
sbt policy check network pypi.org   # exits 1 when denied, and says which rule decided
sbt policy log                      # requests sandboxes made that were blocked
sbt policy approval ls              # blocked hosts with no rule yet
sbt policy approval respond registry.example.com allow
sbt policy rm network --resource api.example.com
sbt create claude . --deny-network evil.com,tracker.example   # deny rules for this sandbox only
```

Rules take hosts (`api.x.com`), wildcards (`*.x.com`, `**.x.com`), IPs and CIDRs, comma-separated.
`**` allows everything. Where smolvm enforces a rule more loosely than sbx, see [sbx
compatibility](sbx-compatibility.md).

- `run` and `create --deny-network <HOST>` add a deny rule for the new sandbox only, as `sbt policy
  deny network --sandbox <NAME> <HOST>` does. It applies only at create; on an existing sandbox
  `run` warns and changes nothing. If the create fails, its rules are removed.
- smolbento 0.2.0's `--deny-network` took no host and made the sandbox deny-all (`deny_network =
  true` under `[sandboxes.<NAME>]` in `policy.toml`). Those stay deny-all, `policy reset` included;
  delete the line to restore the global mode.
- A sandbox's secret hosts, and their subdomains, are always reachable. `policy deny` of one is
  refused, naming the secret's service.
- A deny with a port (`host.example.com:8080`) isn't enforced: smolvm can't filter by port. Deny the
  host without a port. The exception is a deny with exactly the same text as an allow, which cancels
  that allow. `policy ls` notes rules that aren't fully enforced; `policy check` without a port
  checks 443. Details are in [sbx compatibility](sbx-compatibility.md).
- `balanced` allows its hosts on any port. sbx limits them to 443.
- `sbt policy reset` stops running sandboxes, then removes the mode and every rule. The next create
  or start asks for a mode again.
- Blocked requests come from smolvm's egress log. `policy approval` lists hosts with no rule yet;
  the host is the approval ID.

### Host services

A sandbox reaches your machine's localhost as `host.docker.internal` once a `localhost` rule allows
it:

```sh
sbt policy allow network --sandbox claude-myrepo localhost   # before the sandbox is created
sbt run --name claude-myrepo claude .
# inside: curl http://host.docker.internal:11434/
sbt policy rm network --sandbox claude-myrepo --resource localhost   # closes it, live
sbt policy allow network --sandbox claude-myrepo localhost           # opens it again, live
```

- Only your `localhost` rules (global, or `--sandbox NAME`) give host access, and only at create.
  For such a sandbox, later `localhost` rules open and close access live. Other sandboxes have
  loopback blocked for life; a rule added later prints `note: NAME were created without host access;
  recreate them to use it`.
- smolvm can't open a single host port yet, so `localhost:11434` opens every port on your
  `127.0.0.1` to those sandboxes, and `policy allow` warns (`warning: smolvm can't open a single
  host port yet; …`). See [Security](SECURITY.md#host-services-localhost-rules).
- Kit rules never grant host access, and `_builder` never has it. An `allow-all` sandbox keeps host
  access until recreated.
- Each start adds `100.96.0.1 host.docker.internal` to `/etc/hosts`. The name resolves everywhere,
  but only sandboxes created with host access can connect.
- `127.0.0.1`, `::1` and `host.docker.internal` rules aren't host-services rules; the rule must say
  `localhost`. A blocked request gets connection refused. sbx returns `403 Approval required`
  instead.

## Secrets

Agents never see your API keys. The variable holds a placeholder inside the sandbox, and smolvm
swaps in the real value only on HTTPS requests to that service's hosts.

```sh
sbt secret set anthropic                    # prompts (hidden input; an empty line cancels)
sbt secret set claude --ref op://Private/claude-sandbox/credential   # 1Password, read at each start
sbt secret set github --command 'gh auth token'                      # run at each start
sbt secret set openai --sandbox claude-myrepo -t sk-…                # one sandbox only
sbt secret set-custom --host api.example.com --env EXAMPLE_TOKEN --command 'pass show example'
sbt secret ls
sbt secret rm github
```

- `--ref` takes an `op://…` reference or an AWS Secrets Manager ARN (its region is used). Typed or
  `-t` values go to your OS keychain ([Configuration](configuration.md#secret-values)).
- `set-custom` takes bare host names (no scheme, port, path or IP; repeat `--host`), or
  `*.example.com` for every subdomain. `*.com` is refused, as smolvm refuses it; `*.co.uk` is
  accepted, since smolvm has no public suffix list. It warns about a name that doesn't resolve, and
  the create fails while one doesn't resolve. Removing a custom service's last secret removes the
  service too.
- A `--command` source runs in a fresh temporary directory, so give helper scripts an absolute path
  or put them on `PATH`. `./get-token.sh` no longer works.
- Built-in services: `anthropic`, `claude` (Claude Code's `claude setup-token` token), `cursor`,
  `droid`, `github`, `google`, `groq`, `mistral`, `nebius`, `openai`, `openrouter`, `xai`.

When things take effect:

- A sandbox binds the services that have a secret when it's **created**, and can always reach their
  hosts.
- A new value for a bound service applies at the **next start**, usually the next `sbt run`.
- A secret for a service the sandbox wasn't created with needs a **recreate**; `secret set` tells
  you which.

### Registry credentials

A registry credential lets smolbento pull kits and images that need a login. It stays on your
machine; sandboxes never get it.

```sh
sbt secret set --registry dhi.io --username alice --password-stdin < token.txt   # Docker Hub token
gh auth token | sbt secret set --registry ghcr.io --password-stdin               # token-only
sbt secret ls
sbt secret rm --registry dhi.io
```

The token goes to your OS keychain; `secrets.toml` keeps the host and user name. Omit `--username`
for token-only registries such as ghcr.io. Docker Hub, `dhi.io` and Quay robots need it; an empty
`--username` counts as none. For a token server on another host, pass `--registry-auth-endpoint
https://…` with the exact URL. The login goes only over HTTPS (or plain HTTP to a localhost
registry), and only to the registry, `auth.docker.io` for Docker Hub, or that URL.

Used for:

- Pulling published kits from that registry. A stored login replaces anonymous pulls, so an expired
  token also breaks that registry's public kits. Remove it with `sbt secret rm --registry HOST`.
- Local kit builds, in the `_builder` sandbox. It can reach every logged-in registry, and smolvm
  sets the `Authorization` header there. Before a build that names `HOST/<repo>` in its descriptor,
  smolbento gets a short-lived pull token and starts the builder with it, so a build must start
  pulling within a few minutes. Only `HOST/…` references count.
- A build that reaches a logged-in registry without naming it that way gets `502 credential
  unavailable` and fails, naming the registry. Write the image as `HOST/<repo>`, or remove the
  login.
- Local builds don't yet support Docker Hub logins (`FROM debian` gets no token) or non-default
  ports (`registry.corp:5000`). Registries that accept Basic auth only work for kit pulls, not
  builds.
- Concurrent builds that use a registry login restart the builder, so run them one at a time. Adding
  or removing a login recreates the builder and its cache at the next build.

Registry logins appear only in plain `sbt secret ls`, not with `-g`, `--sandbox` or a service
filter. `--sandbox` and `--all-sandboxes` (a login for a sandbox's own `docker pull`) aren't
supported yet.

`sbt rm` removes that sandbox's own secrets and per-sandbox policy. `sbt reset` removes all secrets
too, unless you pass `--preserve-secrets`.

## Ports

```sh
sbt ports claude-myrepo --publish 3000          # picks a free host port; works while running
sbt ports claude-myrepo --publish 8080:80
sbt ports claude-myrepo                         # list
sbt ports claude-myrepo --unpublish 8080:80
```

Ports bind `127.0.0.1` and `[::1]`. UDP ports change only while the sandbox is stopped, so a change
that includes one doesn't start it.

## Copy files

```sh
sbt cp ./notes.md claude-myrepo:/tmp/notes.md
sbt cp claude-myrepo:/home/agent/.bash_history ./history
sbt cp -L ./linked-file claude-myrepo:/tmp/f     # follow a symlink on your side
```

One side must be `SANDBOX:/absolute/path`; sandbox-to-sandbox copies aren't supported. A directory
copies in like `cp -r`, with symlinks copied as the files they point to. Out of a sandbox, only
single files copy.

## List

```sh
sbt ls
sbt ls --json            # or --format json|yaml
sbt ls -q                # names only
```

`sbt` with no arguments also lists sandboxes. `sbt inspect NAME` shows one sandbox's agent, kits,
state, image, workspace, host mounts, secrets, ports and sessions (`--json` or `--format
json|yaml`).

```
SANDBOX         AGENT    STATUS      PORTS                 WORKSPACE             CREATED
claude-myrepo   claude   ● running   127.0.0.1:18080->80   /Users/me/code/myrepo 2h
shell-scratch   shell    ○ stopped                         -                     1d
```

## Stop, start and remove

```sh
sbt stop claude-myrepo                 # keeps the disk
sbt start claude-myrepo
sbt rm claude-myrepo                   # asks first; -f to skip; --all for every sandbox
sbt prune                              # remove all stopped sandboxes, and leftover host services
sbt prune --dry-run --filter until=24h # stopped sandboxes created more than 24h ago
sbt reset -f                           # remove every sandbox
```

`prune --dry-run` also lists host service units left by sandboxes deleted with `smolvm machine
delete` (`Would remove NAME (leftover host services)`), and `prune` removes them without asking.

Commands that delete things ask for confirmation, and refuse to run without a terminal unless you
pass `-f`.
