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
worktree, its branch); uncommitted changes aren't carried over. The clone survives stop and start.
The clone is writable, so `:ro` on the `--clone` workspace is ignored (the mounted repo is
read-only anyway).

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
  installed. If the clone fails, the start fails with git's error and the next start tries again.
- `--clone` only applies when the sandbox is created; `run` on an existing sandbox ignores it.
- `sbt rm`, `prune` and `reset` remove the `sandbox-<name>` remote, and with it the
  `sandbox-<name>/…` branches, as sbx does. Merge what you want first, or keep a branch:
  `git branch keep sandbox-<name>/main`. Nothing else in your repo's config changes.
- `run --rm` keeps the remote, so the commits fetched when the agent exits survive. Its fetch fails
  from then on (the sandbox is gone); remove it with `git remote remove sandbox-<name>` when you're
  done.

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
