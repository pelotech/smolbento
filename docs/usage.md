# Usage

Examples use `bento`; `sbx` (and `sbt`, if you alias it) is the same program.

More:

- [Kits, skills, MCP servers and templates](kits.md)
- [Environment files](environments.md)
- [Network policy and secrets](network-and-secrets.md)

On this page: [Run an agent](#run-an-agent) · [Create without attaching](#create-without-attaching)
· [Clone mode](#clone-mode) · [Fork](#fork) · [Run commands inside](#run-commands-inside) · [SSH
into a sandbox](#ssh-into-a-sandbox) · [Browser and clipboard](#browser-and-clipboard) · [SSH
agent](#ssh-agent) · [Docker inside a sandbox](#docker-inside-a-sandbox) · [Files and
ownership](#files-and-ownership) · [Ports](#ports) · [Copy files](#copy-files) · [List](#list) ·
[Stop, start and remove](#stop-start-and-remove)

## Run an agent

```sh
cd ~/code/myrepo
bento run claude
```

`run` creates the sandbox if needed, starts it if stopped, and attaches you. The sandbox is named
`<agent>-<directory name>` (here `claude-myrepo`), so the same agent in the same directory
reattaches.

Two directories with the same name (`pelotech/infrastructure` and `uki-code/infrastructure`) would
get the same default name. Without `--name`, `run` and `create` refuse a name another directory's
sandbox holds, and suggest one with the parent directory:

```console
$ bento run claude
error: sandbox name "claude-infrastructure" is already used by workspace "/src/pelotech/infrastructure"; pass --name to choose a different name, such as --name claude-uki-code-infrastructure
```

`bento settings set sandbox.autoName true` takes the suggested name instead of refusing. Either way, a
later `bento run claude` in that directory finds its sandbox by the directory, whatever it's called.

When the last attached session exits (closing the terminal counts), the sandbox stops. Its disk is
kept, so the next `run` resumes with what the agent installed.

| Form | Effect |
|---|---|
| `bento run claude` | Sandbox for the current directory |
| `bento run claude ~/code/api ~/code/docs:ro` | First path is the workspace; more paths are mounted; `:ro` is read-only |
| `bento run --name claude-myrepo` | Reattach by name |
| `bento run --name review claude .` | A second sandbox on the same directory |
| `bento run -d claude` | Start and leave running; prints the name |
| `bento run --rm claude` | Delete on exit (kept, with a warning, while another session is attached) |
| `bento run claude -- -c` | Pass arguments to the agent |

`run` exits with the agent's exit status.

### Agent arguments

Arguments after `--` are **appended** to the agent's default command if the first one starts with
`-`. Otherwise they **replace** its flags. `bento run claude -- -c` runs `claude
--dangerously-skip-permissions -c`.

### Agents

Each built-in agent is the kit sbx publishes for it, `docker.io/sbx/<agent>:latest`: `claude`,
`codex`, `copilot`, `cursor`, `devin`, `docker-agent`, `droid`, `kiro`, `opencode` and `shell`. The
kit brings the agent's image, command, network rules, credential hosts, settings (for `claude`:
the workspace trust and permission prompts, `--kit-arg model=…`, `--kit-arg reasoningEffort=…`),
agent file and skills directory, so agents are set up as in sbx and stay current. The first create
of an agent pulls its kit, which takes a minute or two; later creates use the kit cache.

`-t <image>` keeps the agent's kit and replaces its image (sbx allows this only for `shell`); the
image needs the kit's user (`agent`).

An agent kit's subscription login (`claude`'s claude.ai account) happens inside the sandbox, and
its tokens stay there: smolvm can't yet swap them for placeholders as sbx does. With an API key
set (`bento secret set anthropic`), the key stays on the host and the agent uses it.

`gemini` is retired, as in sbx 0.53, and a new sandbox can't use it. Use the `antigravity` kit (`bento
create docker.io/sbx/antigravity:latest .`) or `docker.io/sbx/gemini-kit:latest`, which keeps Gemini
CLI running. In an environment file, keep `agent: gemini` and add the gemini kit to `kits:`.

## Create without attaching

```sh
# create and start; workspace = current directory
bento create claude .
# no path: no host directory mounted
bento create shell
```

A sandbox made by `create` runs until you stop it.

`run` and `create` print their steps (SANDBOX, KITS when a kit was pulled or built, IMAGE, SETUP)
and then `Created sandbox NAME`. `create` adds `try: bento run --name NAME`. `start` prints `○ NAME —
starting…`, then `✓ Started NAME`. Without a terminal, each step prints a line when it starts and
another when it ends:

```
SANDBOX
  Name:       shell-proj
  Agent:      shell
  Workspace:  -
  Image:      from docker.io/sbx/shell:latest
  CPU:        3
  Memory:     1536 MiB

IMAGE
  ○ image — preparing…
  ✓ image — ready

SETUP
  ○ sandbox — starting…
  ✓ sandbox — started

  ✓ Created sandbox shell-proj
        try: bento run --name shell-proj
```

On a terminal, each step redraws in place with a spinner, and a pull shows its percentage (`⠙ image
— pulling… 42%`). The image step says `preparing` until smolvm reports a pull; an image smolvm has
cached doesn't pull (see [`smolvm.image-cache-size`](configuration.md#settings)).

Progress goes to stdout. Scripts that capture output (`name=$(bento run -d …)`) pass `--no-progress`,
which also hides the `Created` and `try:` lines. `--no-input`, on any command, never prompts: a
command that would ask fails with the flag or command to use instead. `run -d --no-progress` then prints only the name.

| Option | Meaning |
|---|---|
| `--name NAME` | Letters, digits, `-` and `.`; at least 2 characters |
| `-w, --workdir DIR` | `run` only: start the session in `DIR`, absolute or relative to the workspace; applies on a re-attach too |
| `--cpus N` | `0` or unset: all host CPUs |
| `-m, --memory SIZE` | Such as `4g` or `512m`. Default: half of host memory, from 512 MiB to 32 GiB |
| `-e, --env KEY=VALUE` | A bare `KEY` copies the host's value |
| `--env-file FILE` | `KEY=VALUE` lines |
| `-p, --publish [[127.0.0.1:]HOST:]PORT[/udp]` | Published on `127.0.0.1`; with no host port, a free one is picked |
| `-t, --template TEMPLATE` | Another image, or a saved [template](kits.md#templates) |
| `--clone` | The agent works on its own clone of the repo ([Clone mode](#clone-mode)) |

Other create-time options have their own sections: `--kit` ([Kits](kits.md#kits)), `--mount` ([Kit host
mounts](kits.md#kit-host-mounts)), `--deny-network` ([Network policy](network-and-secrets.md#network-policy)), `--skills`
([Sharing the store](kits.md#sharing-the-store-with-a-sandbox)) and `--static-mcp` ([MCP
servers](kits.md#mcp-servers)). These options are fixed at create. To change one, `rm` the sandbox and
create it again.

## Clone mode

```sh
cd ~/code/myrepo
bento run --clone claude .
```

The agent works on a clone of your repo. Your checkout is mounted read-only at
`/run/sandbox/source`, and on first start it's cloned to the same path on the sandbox's own disk.
The clone survives stop and start and is writable, so `:ro` on a `--clone` workspace is ignored.

The clone starts from your repo's `HEAD` (for a linked worktree, its branch, or its commit when
detached). If that checkout fails, it starts from the source repo's default `HEAD` with a warning.
Uncommitted changes aren't carried over.

Remotes (`origin`, `upstream`, …) are copied, except local-path and `file://` ones. User names and
tokens in HTTPS URLs are left out. SSH remotes are copied but have no keys in the sandbox, so for
pushes use an HTTPS remote with `bento secret set github`. The copy is redone on every start. Remotes
you add or change reach the clone then, and a remote the agent changed is reset to your URL.

The agent can read your whole `.git` at `/run/sandbox/source`, including tokens in remote URLs and
`http.extraHeader` (see [sbx compatibility](sbx-compatibility.md)). Keep credentials out of it. Use
a credential helper on your machine, or `bento secret`. `create --clone` warns about a token in a
remote URL.

The agent's commits come back through a remote named `sandbox-<name>`. Only branches come back; tags
stay in the sandbox (`--no-tags`).

```sh
git fetch sandbox-claude-myrepo
git log sandbox-claude-myrepo/main
# or check out, cherry-pick, …
git merge sandbox-claude-myrepo/main
```

- `run` fetches `sandbox-<name>` on exit and prints git's summary. Turn it off with `bento settings
  set clone.fetch-on-exit false`. A failed fetch only warns. The automatic fetch checks objects
  (`fetch.fsckObjects`) and doesn't recurse into submodules.
- Any fetch from a stopped clone sandbox starts it, fetches, and stops it again. That includes `git
  fetch --all`, `git remote update` and an IDE's background fetch.
- A `git fetch` that overlaps a `run` exiting can leave the sandbox running. `bento stop <name>` stops
  it.
- `git fetch` runs `smolbento _upload-pack <name>`, so `smolbento` must be on your `PATH`.
- `--clone` needs a workspace in a git repository and git 2.31 or newer on your machine. The image
  needs git too; the built-in images have it, and with `-t` pick one that does. A failed clone fails
  the start with git's error, and the sandbox from a failed first start is removed. Fix the cause
  and rerun `create` or `run`.
- `--clone` applies only at create.
- `bento rm`, `prune` and `reset` remove the `sandbox-<name>` remote and its branches. To keep a
  branch: `git branch keep sandbox-<name>/main`.
- `run --rm` keeps the remote, so fetched commits survive; later fetches fail. Remove it with `git
  remote remove sandbox-<name>` when done.

## Fork

```sh
# one copy: claude-myrepo-fork-1
bento fork claude-myrepo
# three copies, for parallel attempts
bento fork claude-myrepo --count 3
# pick the copy's name
bento fork claude-myrepo --name claude-try-b
```

`fork` copies a running sandbox (memory, processes and disk) and prints the new names, one per line.
A stopped sandbox is started first. Copies are copy-on-write, so they're quick and small. After that
they diverge. A file written in one isn't seen in the others or the original.

Use forks for parallel attempts or as an undo point. Fork before risky work, and if it goes wrong,
`bento rm` the copy and fork the original again.

- Only clone sandboxes and sandboxes without a writable host folder can be forked. `:ro` workspaces
  are fine.
- Forks of forks aren't supported. Fork the original.
- A fork uses its original's sandbox secrets (its own wins), then the global ones. It gets a copy of
  the original's per-sandbox policy rules, which you can change per fork. `bento secret ls --sandbox
  FORK` lists the original's secrets too.
- A clone fork has its own remote: `git fetch sandbox-claude-myrepo-fork-1`.
- `bento rm` of a sandbox with forks fails unless the forks go in the same command. `prune` and
  `reset` remove forks first; `prune` keeps a stopped sandbox while it has forks.
- `bento ls --json` shows `fork_of`. Published ports get new host ports; see `bento ports <fork>`.
- smolvm limits how deep copies can chain, and `fork` says so.
- Sandboxes started before fork support, or while `fork.enabled` was off, need one restart (`bento
  stop NAME && bento start NAME`) first.

Clone and mountless sandboxes start branchable. That costs idle memory that smolvm doesn't return to
your machine, and it carries a Linux secret-exposure risk (see [Security](SECURITY.md)). If you
don't use fork, turn it off with `bento settings set fork.enabled false`; it applies from each
sandbox's next start.

## Run commands inside

```sh
bento exec claude-myrepo git status
# interactive shell
bento exec -it claude-myrepo bash
bento exec --privileged claude-myrepo apt-get install -y ripgrep
bento exec -u root -w /tmp -e DEBUG=1 claude-myrepo env
```

`exec` starts a stopped sandbox first and runs as `agent` in the workspace, unless you pass `-u` or
`-w`. `--privileged` runs as root. It exits with the command's status.

The agent and every `exec` see the sbx sandbox variables: `SANDBOX_NAME`, `SANDBOX_VM_ID` (the
name), `SANDBOX_ID` (a UUID, new per sandbox and per fork), `WORKSPACE_DIR`, `SBX_AGENT`, and
`SBX_CRED_<SERVICE>_MODE` for each service a kit declares a credential for (`apikey` if that secret
was set at create, else `none`; `claude` has `ANTHROPIC`). Your `-e` wins. Differences from sbx are in [sbx compatibility](sbx-compatibility.md#sandbox-environment).

## SSH into a sandbox

```sh
# once: adds a managed block to ~/.ssh/config
bento setup ssh
# a shell in the workspace
ssh claude-myrepo.sbx
ssh claude-myrepo.sbx git status
# reach a port inside the sandbox
ssh -L 8080:localhost:3000 claude-myrepo.sbx
# removes the block
bento setup ssh remove
```

`ssh NAME.sbx` starts a stopped sandbox, and fails for one that doesn't exist (create it first). It
runs as the sandbox's session user (`agent`) in the workspace, like `exec`. There is nothing to
install in the sandbox and no key or password: `ssh` runs `bento ssh proxy`, which speaks SSH for that
one connection, so only you can use it.

VS Code Remote-SSH works with `ssh NAME.sbx` as the host: it installs its server through exec, then
forwards ports (the sandbox needs network access to download it, per your policy). It isn't
tested here, as VS Code can't be scripted.

Port forwarding (`ssh -L`) reaches `localhost`, `127.0.0.0/8` and `::1` inside the sandbox only. The
sandbox needs `nc` or bash. SFTP and `scp`, agent forwarding, X11 and remote forwarding (`-R`) are
refused; use `bento cp` for files. `setup ssh` never edits anything outside its own block (put at the
top of `~/.ssh/config`). See [sbx compatibility](sbx-compatibility.md#ssh).

## Browser and clipboard

The sandbox can open URLs in your browser and, once you allow it, copy text to your clipboard,
whenever it runs. On
macOS (launchd) and Linux (`systemd --user`) a service unit owns the socket, so nothing needs to be
attached; without a usable service manager (a container, CI without a user session) it works only
while `bento run` or `bento exec -it` is attached.

```sh
# inside the sandbox
# opens in your host browser
xdg-open https://github.com/login/device
# or xclip, xsel, pbcopy, clip.exe
git diff | wl-copy
```

- Only `https://` URLs open. Others, or any URL when nothing serves the socket, print `Open this URL
  in your browser: URL`.
- Copying is off until you run `bento settings set clipboard.textCopy true`, as in sbx. It's text
  only. Reading the clipboard (`wl-paste`, `xclip -o`, `xsel -o`) prints nothing, and images can't
  be pasted. A copy that's off, or made when nothing serves the socket, fails with `<command>:
  failed to write host clipboard (copying may be off: …)`.
- Browser logins work. For a `redirect_uri` of `http://localhost:PORT/…` or
  `http://127.0.0.1:PORT/…`, smolbento listens on your `127.0.0.1:PORT` for 10 minutes (the
  connection's process stays that long) and relays the callback. If something else answers that
  port, it warns and still opens the URL. A session relays at most 4 ports, and a sandbox's
  sessions keep at most 4 such processes alive. On Linux `bento rm` stops them with the
  sandbox's units. A callback with a body
  (`response_mode=form_post`) loses it; query-string redirects work.
- Over SSH without a forwarded display (Linux: no `DISPLAY` or `WAYLAND_DISPLAY`; macOS: always over
  SSH), URLs are printed instead.
- `bento settings set browser.enabled false` stops URL opening and the login relay. Copying still
  works.
- The shims go in `/usr/local/bin` on every start and need `curl` in the image. `BROWSER` is
  `xdg-open`, so agents such as Claude Code's `/login` open the browser.
- The unit runs `bento _serve bridge NAME` for each connection, with the settings and `PATH` of the
  last `bento` that touched the sandbox (`create`, `start`, `run`, `exec` rewrite a unit that
  differs, so an upgraded binary or a new `PATH` follows). Units are written at create. Without a
  service manager, it is served only while attached (the first attached session serves it).
- The socket directory must be
  private and yours (0700), checked at create and at start (macOS: `~/Library/Application
  Support/smolbento/sock`; Linux: `$XDG_RUNTIME_DIR/smolbento`; attached-only serving:
  `/tmp/sbt-<uid>`), or the bridge is skipped with a warning.
- Forks don't install the shims or get units, but keep the parent's socket mount, so they can use
  the parent's bridge while the parent's unit (or attached session) serves it.
- `bento rm`, `prune`, `reset` and `env rm` remove a sandbox's units and sockets. Units of a sandbox
  deleted with `bento smolvm machine delete` are removed by the next `create`, `start`, `run`, `exec`,
  `rm` or `prune` (never by `ls`); `prune --dry-run` lists them and `diagnose` reports them.

## SSH agent

Sandboxes of the built-in agents can use your SSH agent. Git over SSH and commit signing work, and
your keys never enter the sandbox.

```sh
# inside the sandbox ($SSH_AUTH_SOCK is /run/ssh-agent.sock)
# lists your keys
ssh-add -l
# with gpg.format=ssh
git commit -S -m "signed"
# fails: the sandbox can't change your agent
ssh-add -D
```

- The agent is `SSH_AUTH_SOCK` when you run `bento`, or the socket in `ssh.agentSocketPath`. With
  none, or with `ssh.agentForwardingEnabled` set to `false`, the sandbox is created without one,
  silently.
- Only listing keys and signing get through. Adding, removing or locking keys fails.
- With a service manager (launchd on macOS, `systemd --user` on Linux) a unit owns the sandbox's
  agent socket and runs `bento _serve agent NAME` for each connection, so the agent answers whenever
  the sandbox runs, attached or not, across stop and start. The unit uses `ssh.agentSocketPath`,
  else the `SSH_AUTH_SOCK` of the user session (launchd supplies macOS's; on Linux the unit gets
  that of the last `bento` that wrote it). Without a service manager, it is served only while `bento` runs for the sandbox (`run`, `exec -it`, plain `exec`; the
  first `bento` to start serves it). A socket path of 104 bytes or more (a very long home
  directory) also means no units.
- Units live in `~/Library/Application Support/smolbento/launchd` (`dev.smolbento.<id>.<sandbox>.agent.plist`; not in `~/Library/LaunchAgents`, which makes macOS announce a background item per sandbox, and not persistent: they're loaded again when `create`, `start`, `run` or `exec` find them unloaded after a reboot) or
  `~/.config/systemd/user` (`smolbento-<id>-<sandbox>-agent.socket`), named with a short hash of
  smolbento's data dir; they exist only for sandboxes with a runtime grant or the bridge, and go with
  the sandbox (see [Browser and clipboard](#browser-and-clipboard)). The socket is `0600` in a
  private directory of yours.
- Each connection re-reads settings. `bento settings set ssh.agentForwardingEnabled false` refuses new
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
- The grant is fixed at create.
- Forks keep the parent's socket mount, so they can use the parent's grant while the parent is
  served.

## Docker inside a sandbox

Every sandbox runs its own Docker engine, so agents can `docker build` and `docker compose up`
without touching your host's Docker. Its storage lives on the sandbox's disk and survives restarts.

To skip Docker (smaller images, faster first pull), run `bento settings set docker.enabled false`
before creating sandboxes; agents then use the plain image variants.

The engine comes from the shipped `docker` kit ([Kits](kits.md#kits)). Docker-enabled images get it
automatically; add it to another image that has Docker with `--kit docker`. dockerd starts on every
start, before kit startup steps, and logs to `/var/log/dockerd.log`; a start fails if it doesn't
answer within 60 s.

## Files and ownership

Workspaces are mounted at the same absolute path as on your machine, so paths in errors and logs
match. In the sandbox, smolvm shows the workspace as owned by `agent`, and files the agent creates
appear on your machine owned by you. On macOS, the virtiofs mount also makes them private to you, so
files are mode 600 and directories mode 700.

## Ports

```sh
# picks a free host port; works while running
bento ports claude-myrepo --publish 3000
bento ports claude-myrepo --publish 8080:80
# list
bento ports claude-myrepo
bento ports claude-myrepo --unpublish 8080:80
```

Ports bind `127.0.0.1` and `[::1]`. UDP ports change only while the sandbox is stopped, so a change
that includes one doesn't start it.

## Copy files

```sh
bento cp ./notes.md claude-myrepo:/tmp/notes.md
bento cp claude-myrepo:/home/agent/.bash_history ./history
# follow a symlink on your side
bento cp -L ./linked-file claude-myrepo:/tmp/f
```

One side must be `SANDBOX:/absolute/path`; sandbox-to-sandbox copies aren't supported. A directory
copies in like `cp -r`, with symlinks copied as the files they point to. A directory copies out as
`docker cp` places it: as the destination when that doesn't exist, else into it under its own name,
with symlinks kept as links. It never merges into a directory that's already there.

## List

```sh
bento ls
# or --format json|yaml
bento ls --json
# names only
bento ls -q
```

`bento` with no arguments also lists sandboxes. `bento inspect NAME` shows one sandbox's agent, kits,
state, image, workspace, host mounts, secrets, ports and sessions (`--json` or `--format
json|yaml`).

```
SANDBOX         AGENT    STATUS      PORTS                 WORKSPACE             CREATED
claude-myrepo   claude   ● running   127.0.0.1:18080->80   /Users/me/code/myrepo 2h
shell-scratch   shell    ○ stopped                         -                     1d
```

## Stop, start and remove

```sh
# keeps the disk
bento stop claude-myrepo
bento start claude-myrepo
# asks first; -f to skip; --all for every sandbox
bento rm claude-myrepo
# remove all stopped sandboxes, and leftover host services
bento prune
# stopped sandboxes created more than 24h ago
bento prune --dry-run --filter until=24h
# remove every sandbox
bento reset -f
```

`prune --dry-run` also lists host service units left by sandboxes deleted with `bento smolvm
machine delete` (`Would remove NAME (leftover host services)`), and `prune` removes them without asking.

Commands that delete things ask for confirmation, and refuse to run without a terminal unless you
pass `-f`.
