# smolbento

Run coding agents in [smolvm](https://github.com/smol-machines/smolvm) microVMs, with the command
line of Docker [Sandboxes](https://docs.docker.com/ai/sandboxes/) (`sbx`). One binary, invoked as
`bento` (or `sbx`). It has no daemon and needs no Docker on the host.

![bento run claude: a network policy prompt, the microVM starting Claude Code, and the agent
seeing only a placeholder for the API key](https://github.com/pelotech/smolbento/releases/download/demo/demo.gif)

## Why smolbento

Docker Sandboxes and smolbento both run each agent in its own microVM, and neither needs Docker
Engine on the host. smolbento keeps sbx's commands and kits, and differs in:

| | smolbento | Docker Sandboxes (`sbx`) |
|---|---|---|
| Account | None. Agent kits pull from Docker Hub without a login | Docker sign-in (`sbx login`) |
| Source | Open source, Apache-2.0 | Binary releases; Docker's docs state no license |
| Background process | None. Each command calls smolvm directly | A local daemon |
| MicroVM | [smolvm](https://github.com/smol-machines/smolvm) (libkrun: Hypervisor.framework on macOS, KVM on Linux) | Docker's hypervisor sandbox |
| Hosts | macOS on Apple Silicon; Linux x86_64 or arm64 with KVM | macOS 14+ on Apple Silicon, Windows 11, Ubuntu 24.04+ |
| Command line | sbx's commands and flags; `alias sbx=bento` makes it a drop-in | `sbx` |
| Cloud sandboxes | No | Yes |

Every intentional difference is listed in [sbx compatibility](docs/sbx-compatibility.md).

## How a sandbox is isolated

```
 your machine ──────────────────────────────────────────────────────────────────────────
 │                                                                                     │
 │  bento secret set anthropic ──▶ OS keychain, 1Password ref or a command             │
 │                                    │ read at each start; never written to disk      │
 │                                    ▼                                                │
 │  smolvm, outside the VM                                                             │
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

- **Secrets:** the agent holds a placeholder. smolvm puts the real value in only on HTTPS requests
  to that service's hosts, so a leaked environment or prompt-injected `curl` gets nothing useful.
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
- [`nix`](kits/nix): Nix with flakes, direnv and nix-direnv, for any agent (`--kit nix`).

See [Kits](docs/kits.md#kits) to add your own.

## Install

macOS (Apple Silicon) or Linux (x86_64, arm64) with Homebrew:

```sh
# once: Homebrew 7+ only loads trusted taps
brew tap pelotech/tap && brew trust pelotech/tap
brew install pelotech/tap/smolbento
```

That's all: smolvm is installed automatically. smolbento downloads the smolvm release it's tested
with the first time you run it, into `~/.smolbento`, and checks its checksum. Docker isn't needed.
On Linux, your user needs access to `/dev/kvm`.

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
