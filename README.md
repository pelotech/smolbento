# smolbento

Run coding agents in [smolvm](https://github.com/smol-machines/smolvm) microVMs, with the command
line of Docker [Sandboxes](https://docs.docker.com/ai/sandboxes/) (`sbx`). One binary, invoked as
`bento` (or `sbx`). It has no daemon and needs no Docker on the host.

![bento run claude: a network policy prompt, the microVM starting Claude Code, and the agent
seeing only a placeholder for the API key](https://github.com/pelotech/smolbento/releases/download/demo/demo.gif)

## Why smolbento

It keeps the commands and kits of Docker Sandboxes, is open source and needs no account. Each
command calls smolvm directly. See
[smolbento and Docker Sandboxes](docs/comparison.md) for how the two differ, and
[sbx compatibility](docs/sbx-compatibility.md) for every command and flag.

## How a sandbox is isolated

```
 your machine ──────────────────────────────────────────────────────────────────────────
 │                                                                                     │
 │  bento secret set anthropic ──▶ OS keychain, 1Password ref or a command             │
 │                                    │ read at each start; never written to disk      │
 │                                    ▼                                                │
 │  bento's egress process and smolvm, outside the VM                                  │
 │   ├─ network policy: allowed hosts only, everything else refused ──▶ the internet   │
 │   ├─ credential swap: placeholder ──▶ real key, only on HTTPS to that service       │
 │   └─ hypervisor                                                                     │
 │       ┌─ microVM: its own kernel ───────────────────────────────────────────────┐   │
 │       │  agent (claude, codex, …)       ANTHROPIC_API_KEY=<placeholder>         │   │
 │       │  /your/workspace                the only host folder it gets by default │   │
 │       │  no host processes, keychain or Docker engine; host sockets only for    │   │
 │       │  the browser bridge and SSH agent forwarding, when you enable them      │   │
 │       └─────────────────────────────────────────────────────────────────────────┘   │
 ───────────────────────────────────────────────────────────────────────────────────────
```

- **Secrets:** the agent holds a placeholder. bento's egress process puts the real value in only on
  HTTPS requests to that service's hosts, so a leaked environment or prompt-injected `curl` gets nothing useful.
- **Network:** each sandbox gets a policy (`balanced`, `deny-all` or `allow-all`, plus your rules),
  enforced outside the VM. Blocked requests show in `bento policy log`.
- **MicroVM:** a separate kernel per sandbox. The agent can be root inside without touching the
  host. See [Security](docs/SECURITY.md).

## Agents and kits

Built-in agents, each the kit sbx publishes (`docker.io/sbx/<agent>`), set up as in sbx:

| Agent | | Agent | |
|---|---|---|---|
| `claude` | Claude Code | `droid` | Factory Droid |
| `codex` | OpenAI Codex | `kiro` | Kiro |
| `copilot` | GitHub Copilot CLI | `opencode` | opencode |
| `cursor` | Cursor CLI | `docker-agent` | Docker Agent |
| `devin` | Devin | `shell` | A plain shell, for your own tools |

Any other sbx kit works too, such as `bento create docker.io/sbx/antigravity:latest .`. Kits shipped
in [`kits/`](kits):

- [`docker`](kits/docker): a private Docker engine inside the sandbox, added to Docker-enabled
  sandboxes. It never sees the host's.
- [`git-signing`](kits/git-signing): commits signed with a key from your SSH agent, for any
  agent (`--kit git-signing`).
- [`nix`](kits/nix): Nix with flakes, direnv and nix-direnv, for any agent (`--kit nix`).

See [Kits](docs/kits.md#kits) to add your own.

## Install

macOS (Apple Silicon) or Linux (x86_64, arm64) with Homebrew:

```sh
# once: Homebrew 7+ only loads trusted taps
brew tap pelotech/tap && brew trust pelotech/tap
brew install pelotech/tap/smolbento
```

smolvm is downloaded on first run into `~/.smolbento` and checked against a built-in checksum.
Docker isn't needed. On Linux, your user needs `/dev/kvm` access.

From source or a release tarball, and how to uninstall: [Install](docs/install.md).

## First run

```sh
# optional: an API key, kept on your machine (skip it to log in inside the sandbox)
bento secret set anthropic
cd ~/code/myrepo
# create a sandbox for this directory and attach Claude Code
bento run claude
```

Set the key first: a sandbox uses the secrets that exist when it's created. The agent sees only a
placeholder. Choose a network policy when asked (`balanced` suits most work). When the last
session ends, the sandbox stops. Run `bento run claude` again to pick up where you left off. See
[Secrets](docs/network-and-secrets.md#secrets).

## Documentation

- [Usage](docs/usage.md): running agents, workspaces, files, cleaning up
- [Kits, skills, MCP servers and templates](docs/kits.md)
- [Network policy and secrets](docs/network-and-secrets.md), and [environment files](docs/environments.md)
- [Configuration](docs/configuration.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Full index](docs/README.md): architecture, security, development and contributing
