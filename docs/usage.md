# Usage

Examples use `sbt`; `sbx` and `bento` are the same program.

## Run an agent

```sh
cd ~/code/myrepo
sbt run claude
```

`run` creates the sandbox if it doesn't exist, starts it if it's stopped, and attaches you to the
agent. The sandbox is named `<agent>-<directory name>` (here `claude-myrepo`), so running the same
agent in the same directory again reattaches to the same sandbox.

When the last session attached to a sandbox exits, the sandbox stops. Its disk is kept, so the next
`run` resumes with everything the agent installed.

| Form | Effect |
|---|---|
| `sbt run claude` | Sandbox for the current directory |
| `sbt run claude ~/code/api ~/code/docs:ro` | First path is the workspace; more paths are mounted too; `:ro` mounts read-only |
| `sbt run --name claude-myrepo` | Reattach to an existing sandbox by name |
| `sbt run --name review claude .` | A second sandbox on the same directory, under another name |
| `sbt run -d claude` | Start it and leave it running; prints the name |
| `sbt run --rm claude` | Delete the sandbox when the agent exits |
| `sbt run claude -- -c` | Pass arguments to the agent (see below) |

`run` exits with the agent's exit status.

### Agent arguments

Arguments after `--` follow sbx's rule: if the first one starts with `-`, they're **appended** to the
agent's default command; otherwise they **replace** its flags. With `claude`:

- `sbt run claude -- -c` runs `claude --dangerously-skip-permissions -c`
- `sbt run claude -- mcp list` runs `claude mcp list`

### Agents

| Agent | Runs | Image (`docker/sandbox-templates:`) |
|---|---|---|
| `claude` | `claude --dangerously-skip-permissions` | `claude-code-docker-0.10.0` |
| `codex` | `codex --dangerously-bypass-approvals-and-sandbox` | `codex-docker-0.7.0` |
| `copilot` | `copilot --yolo` | `copilot-docker-0.4.0` |
| `cursor` | `cursor-agent --yolo` | `cursor-agent-docker-0.7.0` |
| `devin` | `devin --permission-mode dangerous --respect-workspace-trust=false` | `devin-docker-0.7.0` |
| `docker-agent` | `docker-agent run --yolo` | `docker-agent-docker-0.7.0` |
| `droid` | `droid` | `droid-docker-0.4.0` |
| `gemini` | `gemini --yolo` | `gemini-docker-0.10.0` |
| `kiro` | `kiro chat --trust-all-tools` | `kiro-docker-0.4.0` |
| `opencode` | `opencode` | `opencode-docker-0.7.0` |
| `shell` | `bash -l` | `shell-docker-0.10.0` |

These are Docker's own sandbox images, the same ones `sbx` uses. Tags are pinned and updated by
Renovate. Use `-t <image>` to run a different image; it needs an `agent` user, like Docker's images.

The first run of an agent pulls its image, which takes a minute or two.

## Create without attaching

```sh
sbt create claude .            # create and start; workspace = current directory
sbt create shell               # no path: a sandbox with no host directory mounted
```

A sandbox made by `create` stays running until you stop it (as in sbx).

Options for `run` and `create`:

| Option | Meaning |
|---|---|
| `--name NAME` | Sandbox name (letters, digits, `-` and `.`; at least 2 characters) |
| `--cpus N` | CPUs; `0` or unset means all host CPUs |
| `-m, --memory SIZE` | Memory such as `4g` or `512m`; default half of host memory, between 512 MiB and 32 GiB |
| `-e, --env KEY=VALUE` | Environment variable; a bare `KEY` copies the host's value |
| `--env-file FILE` | Read `KEY=VALUE` lines |
| `-p, --publish [[127.0.0.1:]HOST:]PORT[/udp]` | Publish a port on `127.0.0.1`; with no host port, a free one is picked |
| `-t, --template IMAGE` | Use another image |
| `--clone` | Give the agent its own clone of the repo instead of mounting it (see [Clone mode](#clone-mode)) |

These are fixed when the sandbox is created; changing them later means `rm` and create again.

## Clone mode

```sh
cd ~/code/myrepo
sbt run --clone claude .
```

With `--clone` the agent doesn't write to your checkout. Your repo is mounted read-only at
`/run/sandbox/source`, and on the sandbox's first start it is cloned to the same path as on your
machine, on the sandbox's own disk. The clone starts from your repo's current `HEAD` (for a linked
worktree, its branch, or its commit when its `HEAD` is detached; should that checkout fail, it
starts from the source repo's default `HEAD` with a warning); uncommitted changes aren't carried
over. The clone survives stop and start. The clone is writable, so `:ro` on the `--clone` workspace
is ignored (the mounted repo is read-only anyway).

Your remotes (`origin`, `upstream`, …) are copied into the clone, except local-path and `file://`
ones. Any user name and token in an HTTPS remote URL is left out of the clone's copies. SSH remotes
are copied but won't work in the sandbox (no keys); use an HTTPS remote with
`sbt secret set github` if the agent should push. The copy is redone on every start, so remotes you
add or change on your machine reach the clone the next time the sandbox starts. A remote the
agent changes in the clone is reset to the host's URL on the next start, and remotes you delete on
your machine stay in the clone.

The agent can read your repo's whole `.git` at `/run/sandbox/source`, as in sbx, including
`.git/config` with any token in a remote URL or an `http.extraHeader`. Don't keep credentials
there; use a credential helper on your machine, or `sbt secret` for the sandbox. `create --clone`
warns when a remote URL has a user name or token in it.

The agent's commits come back through a remote `sandbox-<name>` added to your repo:

```sh
git fetch sandbox-claude-myrepo
git log sandbox-claude-myrepo/main
git merge sandbox-claude-myrepo/main          # or check out, cherry-pick, …
```

Only branches come back: the remote is set to `--no-tags`, so tags the agent makes stay in the
sandbox (sbx's remote follows tags).

Good to know:

- `run` fetches `sandbox-<name>` when the agent exits and prints git's summary. Turn it off with
  `sbt settings set clone.fetch-on-exit false`. A failed fetch only warns.
- That automatic fetch checks the objects it receives (`fetch.fsckObjects`) and doesn't recurse
  into submodules. A manual `git fetch` uses your git config; to check it too, run
  `git -c fetch.fsckObjects=true fetch sandbox-<name>`.
- Fetching from a stopped sandbox starts it, fetches, and stops it again. So does anything that
  fetches every remote (`git fetch --all`, `git remote update`, an IDE's background fetch), one
  stopped clone sandbox after another.
- Known limitation: if a `git fetch` overlaps a `run` exiting (or another fetch), the sandbox can
  be left running; `sbt stop <name>` stops it.
- `git fetch` runs `smolbento _upload-pack <name>` for that remote, so `smolbento` must be on your
  `PATH` (every install puts it there; the `sbt`, `sbx` and `bento` names are links to it).
- `--clone` needs a workspace path in a git repository, and git 2.31 or newer on your machine. The
  image needs git too: the built-in agent images have it, but with `-t` pick an image with git
  installed. If the clone fails, the start fails with git's error. On a sandbox's first start with
  kits (every Docker-enabled sandbox has the `docker` kit) the sandbox is then removed, so run the
  same `create` or `run` again; otherwise the next start tries again.
- `--clone` only applies when the sandbox is created; `run` on an existing sandbox ignores it.
- `sbt rm`, `prune` and `reset` remove the `sandbox-<name>` remote, and with it the
  `sandbox-<name>/…` branches, as sbx does. Merge what you want first, or keep a branch:
  `git branch keep sandbox-<name>/main`. Nothing else in your repo's config changes.
- `run --rm` keeps the remote, so the commits fetched when the agent exits survive. Its fetch fails
  from then on (the sandbox is gone); remove it with `git remote remove sandbox-<name>` when you're
  done.

## Fork

```sh
sbt fork claude-myrepo                        # one copy: claude-myrepo-fork-1
sbt fork claude-myrepo --count 3              # three copies, for parallel attempts
sbt fork claude-myrepo --name claude-try-b    # pick the copy's name
```

`fork` copies a running sandbox (memory, processes and disk) into new sandboxes and prints their
names, one per line. A stopped sandbox is started first. Copies are copy-on-write, so they're quick
and small, and from then on each one changes on its own: a file written in one isn't seen in the
others or in the original.

Use it for parallel attempts (fork once per idea, keep the best) or as an undo point: fork before
risky work, and if it goes wrong, `sbt rm` the copy you worked in and fork the original again.

Good to know:

- Only clone sandboxes (`--clone`) and sandboxes without a writable host folder can be forked:
  a host folder would be shared by every copy. Read-only (`:ro`) workspaces are fine.
- Forks of forks aren't supported yet; fork the original again instead.
- Secrets carry over: a fork uses its original's sandbox secrets (a secret set for the fork itself
  wins), then the global ones. It gets a copy of the original's per-sandbox policy rules (such as
  `--deny-network`), which you can change per fork afterwards. `sbt secret ls --sandbox FORK`
  lists the original's secrets too, under the original's scope.
- Each fork of a clone sandbox has its own `sandbox-<fork>` remote in your repo:
  `git fetch sandbox-claude-myrepo-fork-1`.
- Remove a sandbox's forks before the sandbox itself: `sbt rm` of a sandbox with forks fails unless
  its forks are removed in the same command. `prune` and `reset` remove forks first, and `prune`
  keeps a stopped sandbox while it still has forks.
- `sbt ls --json` shows a fork's original in `fork_of`. A fork's created time is its own.
- A fork's published ports get new host ports, picked by smolvm; see `sbt ports <fork>`.
- smolvm limits how deep a chain of copies can get, and says so if a fork would go past it.
- Sandboxes started before fork support, or while `fork.enabled` was off, need one restart
  (`sbt stop NAME && sbt start NAME`) before they can be forked; `fork` says so.

Sandboxes that can be forked (clone and mountless ones, not forks) are started branchable, which
has two costs: smolvm doesn't hand their idle memory back to your machine, and on Linux the VM
process's memory, which holds secret values, is readable by other processes running as you. If
you don't use fork, turn it off with `sbt settings set fork.enabled false`; it applies from each
sandbox's next start.

## Run commands inside

```sh
sbt exec claude-myrepo git status
sbt exec -it claude-myrepo bash               # interactive shell
sbt exec --privileged claude-myrepo apt-get install -y ripgrep
sbt exec -u root -w /tmp -e DEBUG=1 claude-myrepo env
```

`exec` starts a stopped sandbox first. It runs as the `agent` user in the workspace directory
unless you pass `-u` or `-w`; `--privileged` runs as root. It exits with the command's status.

## Docker inside a sandbox

Every sandbox runs its own Docker engine, so agents can `docker build` and `docker compose up`
without touching your host's Docker. Its storage is on the sandbox's own disk and survives restarts.

To skip Docker (smaller images, faster first pull), set `sbt settings set docker.enabled false`
before creating sandboxes; agents then use the plain image variants.

The engine comes from the shipped `docker` kit (see [Kits](#kits)): Docker-enabled images get it
automatically, and `--kit docker` adds it to any image, e.g. `sbt create -t alpine --kit docker
shell .`. dockerd starts on every start of the sandbox; its log is `/var/log/dockerd.log`.

## Kits

Kits add tools, files, network rules, credentials and setup steps to a sandbox. smolbento runs
Docker Sandboxes kits (v3, and v2 `spec.yaml`) and smolvm Smolfiles.

```sh
sbt run claude . --kit docker.io/acme/postgres-kit:1    # add a mixin kit to an agent
sbt run docker.io/acme/my-agent:1 .                     # a workload kit replaces the agent
sbt create shell . --kit ./my-kit --kit-arg region=eu   # a local kit, with an argument
sbt kit inspect ./my-kit                                # what it provides and asks for
sbt kit validate ./my-kit                               # check it without running it
sbt kit add claude-myrepo ./my-mixin                    # add a mixin to an existing sandbox
```

A **mixin** kit adds to an agent (`--kit`, repeatable). A **workload** kit is the agent: pass it
where the agent name goes, and the sandbox is named after it. Its image's command runs as the
image's `USER` (root if it sets none) under `/bin/bash`, so `BASH_ENV` is sourced, in the workspace
path; `sbt exec` uses the same user. The user gets your uid so it can write the workspace (a
numeric `USER` runs as the account with that uid). A workload whose image has no `ENTRYPOINT` or
`CMD` is refused, and one without `/bin/bash` fails to start its agent. A kit reference is one of:

| Reference | Kit |
|---|---|
| `docker` | The shipped Docker kit |
| `docker.io/acme/kit:1`, `ghcr.io/acme/kit@sha256:…` | A published kit, pulled from its registry |
| `./my-kit` (a directory with one `*.yaml` starting `# syntax=docker/sandbox-kit:3`), or that file | A local v3 kit, built in the builder sandbox (below) |
| `./my-kit` (a directory with a `spec.yaml`) | A local v2 kit |
| `./Smolfile`, `./x.smolfile` | A smolvm Smolfile |

A reference that names a file or directory relative to the current directory is that local kit,
even without `./`: with an `alpine` directory present, `alpine` loads it rather than the registry.
`docker` is always the shipped kit.

Kit arguments: `--kit-arg NAME=VALUE` sets an argument for every kit, `--kit-arg KIT.NAME=VALUE`
for one kit, and `--kit-args-file FILE` reads `NAME=VALUE` lines. Files are read in order, then
`--kit-arg`; the last value wins, and a value for one kit beats a value for all. Argument values
aren't secret: they can end up in the sandbox's environment and smolvm's machine config, so put
secrets in [credentials](#secrets) instead. An argument a kit uses that has no value and no default
is an error (`create-phase kit arg "x" has no resolved value`); `--kit-arg x=` sets it to empty.
`--kit-arg` without any kit is an error too. As in sbx, a `KIT.NAME` value for a kit that isn't in
the sandbox is ignored. Unquoted numbers and booleans in a kit's `default:` and `enum:` are read
as strings.

What a kit does, and when:

- **First start**: its install steps run once, as root in a workload kit's image `WORKDIR` (`/`
  otherwise), with any network access the kit needs only for installing. If one fails, or a kit
  file can't be written, the sandbox is removed and the error printed, so the same command works
  again once it's fixed. A failing startup step doesn't remove it (see below). Its files and agent
  instructions are written once (see [agent instructions](#agent-instructions-from-kits)); a v2
  kit's `files/workspace` and `${WORKDIR}` are the sandbox's primary workspace, or
  `/home/agent/workspace` without one.
- **Every start**: the kits' startup steps run in kit order before the agent, and a failing one
  fails the start (`kit startup exited with code N`). A step marked `background: true` (such as
  the `docker` kit's `dockerd`) is started at its place in that order and keeps running, so later
  steps can use it; one of those failing is only logged. A step that doesn't finish (and isn't
  marked `background`) holds up the start: there's no timeout, as in sbx.
  Output goes to `/var/log/sbx-kit-startup.log` in the sandbox: a `=== dispatcher run … ===` line
  per start, then `ok /etc/smolbento/startup.d/NN-<kit>.sh hook N` for each step that finished (or
  was started, for a background one), and a failing step's output and exit code. If a step fails
  during create, the sandbox is still created, with a warning, and stopped: each later start fails
  until the step succeeds, as in sbx. `kit add` only warns. Startup steps run as `agent` unless
  they name a user; a numeric user runs as the account that has that uid. The shipped `docker` kit
  comes before your kits, so your startup steps can use Docker.
- **Environment**: a v3 install step gets a clean environment (`PATH`, `HOME`, `USER`, `TERM`, the
  proxy and CA variables, and the variables it lists in `env`). Startup steps and every v2 step
  get the sandbox's full environment, as in sbx.
- **Credentials** come from your secrets. If a kit needs one you haven't set, the sandbox is still
  created, as in sbx: you get `WARN: required credential not found for service SERVICE` and the
  `sbt secret set` command to run, and the kit's requests go out without the credential until you
  set it and recreate the sandbox. A built-in service's secret only goes to that service's own
  hosts; see [Security](SECURITY.md#kits). A credential the kit needs only while installing is
  available during install; the sandbox then restarts once without it, and later requests to its
  hosts get `502`.
- **Volumes** a kit declares are on the sandbox's own disk: they survive stop and start, and are
  removed with the sandbox.

Only kits from Docker Hub load by default, plus local kits; see [Configuration](configuration.md)
for `kit.allowedSources` and `kit.allowLocalKits`, and [Security](SECURITY.md#kits) for what a kit
can open.

### Agent instructions from kits

Kit instructions for the agent go where sbx puts them: in the agent's file in the parent directory
of the workspace path, inside the sandbox only. With workspace `~/src/app`, claude reads
`~/src/CLAUDE.md`, gemini `~/src/GEMINI.md` and other agents `~/src/AGENTS.md`; a sandbox without a
workspace uses `/home/agent`. A workload kit can name its own file, and its text is appended to it.
Each mixin's text goes to `kits-agent-context/<kit>.md` next to that file, and the file gets a
`## Kits` list pointing at them, between `<!-- sbx:kits-section start -->` and
`<!-- sbx:kits-section end -->`. `kit add` adds a line to that list. Unlike sbx, smolbento writes no
platform preamble of its own.

- Nothing is written on your machine: if the file would land in a mounted workspace (say you also
  mounted the parent directory), smolbento skips it with a warning.
- If a workload kit declares no agent file, mixin instructions are dropped, with a warning.
- The files are owned by `agent`, except a file the image already has owned by root, which keeps
  its owner.
- With `--clone` and a workspace that is a subdirectory of the repo, the parent directory is inside
  the sandbox's clone, so the files show up there as untracked files.

### Adding a kit to a sandbox

`sbt kit add SANDBOX REF` adds a mixin to an existing sandbox without restarting it: network rules,
install and startup steps, files and agent instructions apply at once (a stopped sandbox is started
for it). A kit that would change the image, credentials, ports, volumes, resources, environment
variables or auto-stop needs a new sandbox: `kit add` says "recreate required" and changes nothing.
If the kit opens network access, `kit add` asks first; `-y` grants it, and without a terminal it
fails.

### The builder sandbox

Local v3 kits are built with BuildKit in a hidden sandbox, `_builder`, so you don't need Docker on
your machine. It's created on first use, stopped after each build and not shown by `sbt ls`; its
disk keeps the build cache, and `sbt rm _builder` resets it. Builds use your global network policy
(`sbt policy log _builder` shows what was blocked) and never get your secrets. Base images are
pulled without a registry login, so a kit built on an image that needs one (Docker's own examples
use `dhi.io`) won't build locally yet; published kits are not affected.

## Files and ownership

Workspaces are mounted at the same absolute path as on your machine, so paths in errors and logs
match. Inside the sandbox the `agent` user has your uid, so files the agent creates show up on your
machine owned by you. Files the agent creates are private to you (mode 600/700).

## Network policy

Creating or starting a sandbox needs a network policy. The first time, `sbt` asks which one your
sandboxes get, and saves the answer:

| Mode | Meaning |
|---|---|
| `allow-all` | Open network |
| `balanced` | Default deny, plus Docker Sandboxes' baseline: AI APIs, package registries, code hosts, container registries, cloud services, OS packages, certificate checks (and the Nix caches) |
| `deny-all` | Nothing, unless you allow it |

Without a terminal it can't ask and fails instead, so scripts and CI choose it up front:
`sbt policy init balanced`.

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

Rules take hosts (`api.x.com`), wildcards (`*.x.com`, `**.x.com`), IPs and CIDRs,
comma-separated; `**` allows everything. See [sbx compatibility](sbx-compatibility.md) for where
smolvm enforces a rule more loosely.

Good to know:

- `run`/`create --deny-network <HOST>` adds a deny rule for the new sandbox only, exactly as
  `sbt policy deny network --sandbox <NAME> <HOST>` does; repeat it or comma-separate hosts. It
  applies only when the sandbox is created: on an existing sandbox `run` warns and changes nothing
  (use `policy deny network --sandbox`). If the create fails, the rules it added are removed.
- smolbento 0.2.0's `--deny-network` took no host and made the sandbox deny-all
  (`deny_network = true` under `[sandboxes.<NAME>]` in `policy.toml`). Such sandboxes stay
  deny-all, `policy reset` included; delete that line to give one the global mode again.
- Hosts used by a sandbox's secrets, and their subdomains, are always reachable from it, so
  `policy deny` of such a host, or of one under it, is refused and names the secret's service.
- `balanced` is Docker's list of 195 rules; smolbento allows those hosts on any port (sbx limits
  them to 443).
- A deny with a port (`host.example.com:8080`, `10.0.0.0/8:22`) isn't enforced at all: smolvm can't
  filter by port, so the host stays reachable on every port. Deny the host without a port to block
  it. The one exception: a deny with exactly the same text as an allow rule cancels that allow.
  `policy deny` says so when you add one, `policy ls` notes rules that aren't fully enforced, and
  `policy ls --wide` and `policy check` show the details. `policy check` takes a port the same way
  (`host.example.com:8080`); without one it checks port 443.
- `sbt policy reset` stops running sandboxes, then removes the mode and every rule;
  sandboxes deny-all from smolbento 0.2.0's `--deny-network` stay so. The next create or start
  asks for a mode again.
- Blocked requests come from smolvm's egress log. `policy approval` lists the hosts with no rule
  yet; the host is the approval id.

## Secrets

Agents never see your API keys: inside the sandbox the variable holds a placeholder, and smolvm
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

`--ref` takes an `op://…` reference or an AWS Secrets Manager ARN (the ARN's region is used).
Values typed at the prompt or given with `-t` go to your OS keychain; see
[Configuration](configuration.md#secret-values).

`set-custom` takes bare host names (`api.example.com`, no scheme, port, path or IP; repeat
`--host` for more), or `*.example.com` for every subdomain of a domain (`*.com` is refused, as smolvm
refuses it; smolvm has no public suffix list, so `*.co.uk` is accepted). It warns when a host name
doesn't resolve: smolvm looks them up when it creates a sandbox, and the create fails while one
doesn't resolve.
Removing a custom service's last secret (in any scope) removes the service too.

Built-in services: `anthropic`, `claude` (Claude Code's `claude setup-token` token), `cursor`,
`droid`, `github`, `google`, `groq`, `mistral`, `nebius`, `openai`, `openrouter`, `xai`.

When things take effect:

- A sandbox binds the services that have a secret when it's **created**, and can always reach
  those services' hosts.
- A new value for a bound service applies on the sandbox's **next start** (sandboxes stop after each
  session, so usually the next `sbt run`).
- A secret for a service a sandbox wasn't created with needs the sandbox **recreated**; `secret set`
  tells you which.

`sbt rm` removes that sandbox's own secrets and its per-sandbox policy. `sbt reset` removes all
secrets too, unless you pass `--preserve-secrets`.

## Ports

```sh
sbt ports claude-myrepo --publish 3000          # picks a free host port; works while running
sbt ports claude-myrepo --publish 8080:80
sbt ports claude-myrepo                         # list
sbt ports claude-myrepo --unpublish 8080:80
```

Ports bind `127.0.0.1`. UDP ports can only be changed while the sandbox is stopped, so a change
that includes one doesn't start it.

## Copy files

```sh
sbt cp ./notes.md claude-myrepo:/tmp/notes.md
sbt cp claude-myrepo:/home/agent/.bash_history ./history
sbt cp -L ./linked-file claude-myrepo:/tmp/f     # follow a symlink on your side
```

One side must be `SANDBOX:/absolute/path`. Copying between two sandboxes isn't supported.

## List

```sh
sbt ls
sbt ls --json            # or --format json|yaml
sbt ls -q                # names only
```

`sbt` with no arguments also lists sandboxes.

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
sbt prune                              # remove all stopped sandboxes
sbt prune --dry-run --filter until=24h # stopped sandboxes created more than 24h ago
sbt reset -f                           # remove every sandbox
```

Commands that delete things ask for confirmation, and refuse to run without a terminal unless you
pass `-f`.
