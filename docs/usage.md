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

These are fixed when the sandbox is created; changing them later means `rm` and create again.

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

The first `sbt run` or `sbt create` asks which policy your sandboxes get, and saves the answer:

| Mode | Meaning |
|---|---|
| `allow-all` | Open network |
| `balanced` | Default deny, plus Docker Sandboxes' baseline: AI APIs, package registries, code hosts, container registries, cloud services, OS packages, certificate checks (and the Nix caches) |
| `deny-all` | Nothing, unless you allow it |

In scripts and CI, choose it up front: `sbt policy init balanced`.

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
sbt create --deny-network claude    # this sandbox gets deny-all, whatever the global mode
```

Rules take hosts (`api.x.com`), wildcards (`*.x.com`, `**.x.com`), IPs and CIDRs,
comma-separated; `**` allows everything. See [sbx compatibility](sbx-compatibility.md) for where
smolvm enforces a rule more loosely.

Good to know:

- `--deny-network` only applies when a sandbox is created; `sbt run --deny-network` on an existing
  sandbox warns and changes nothing.
- Hosts used by a sandbox's secrets are always reachable from it, so `policy deny` of such a host
  is refused and names the secret's service.
- `balanced` is Docker's list of 195 rules; smolbento allows those hosts on any port (sbx limits
  them to 443).
- `sbt policy reset` removes the mode and every rule; `--deny-network` sandboxes stay deny-all.
  Until a mode is chosen again, starting a sandbox asks for one (without a terminal it warns and
  starts with an open network).
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

Ports bind `127.0.0.1`. UDP ports can only be changed while the sandbox is stopped.

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
