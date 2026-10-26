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
