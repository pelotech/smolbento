# smolbento

A Docker Sandboxes (`sbx`) compatible CLI on top of [smolvm](https://github.com/smol-machines/smolvm)
microVMs. One Rust binary, invoked as `bento` (or `sbx`). Nothing ships an `sbt` link; the binary still answers to it by alias.

Design notes, specs and plans live in `docs/superpowers/` when present. It's gitignored for now, so
only some checkouts have it. If it's there, read the relevant section before changing behaviour.

## Rules

- **Shell out to smolvm; never link it.** Every smolvm call goes through the `Runner` trait in
  `src/smolvm/`. Pass `--error-format json`; parse `--json` output, never tables.
- **smolvm is the state.** Per-sandbox metadata lives in `sbx.*` machine labels, set at create. Do not
  add a sandbox state file. Global settings and lists live in `~/.config/smolbento/*.toml`. Other
  global data is listed in [docs/configuration.md](docs/configuration.md#files).
- **Always `--net-backend virtio-net`** on create. Live policy and port changes depend on it.
- **Command output goes through `ctx.out`** (`writeln!(&ctx.out, ..)`), never `println!`. Tests read
  it with `t.stdout()`. Errors and warnings stay `eprintln!`.
- **Interactive exec inherits stdio.** `run` and `exec -it` exec `smolvm machine exec -it` directly.
  Never pipe a TTY through buffers.
- **Secrets:** store sources only (keychain, `op://` or AWS ref, command). Resolve at `start` and pass
  as env to `smolvm machine start`. Never write values to disk, logs or argv. The one exception is
  the secret store itself, which on Linux without a Secret Service is a 0600 file.
- **Never use smolvm `--docker-socket` or `smolvm engine`.** Docker in a sandbox is its own private
  dockerd, which a kit's `dockerd@1` (the shipped `docker` kit) asks for and `src/sandbox/engine.rs`
  starts on each start, before the startup steps. The engine's containers are host machines
  that can bind any host path, so a sandbox given its socket could reach the whole host.
- **sbx compatibility:** flags and output match the sbx CLI reference. Record intentional differences
  in `docs/sbx-compatibility.md`; don't diverge silently. smolbento-only commands must not collide with
  sbx command names, and are added only when implemented.
- **Kits conform to the kit spec.** The [sandbox kit spec](https://github.com/docker/sandbox-kit-spec)
  decides how a kit is read and applied, at the commit in `SPEC_COMMIT` (`src/kits/mod.rs`). Before
  changing how a capability is applied, read its page under the spec's
  `docs/spec/capabilities/com.docker.sandbox/`, and name the rule's `tck:` id in the test. Where sbx
  behaves differently from the spec, follow the spec and record the difference in
  `docs/sbx-compatibility.md`. `just conformance` runs the spec's own suite.
- macOS and Linux now. Keep path handling in `workspace` so Windows can be added later. smolvm itself
  runs on Windows hosts, with the caveats in its `docs/limitations.md`.

## smolvm behaviour to rely on

smolbento runs the release pinned in `smolvm.lock` (`just smolvm-pin VERSION` bumps it), downloaded
on first use into `<smolvm.home>/engine/<version>/` (default `~/.smolbento`). Every smolvm call gets
`SMOLVM_DATA_DIR=<smolvm.home>`, so smolbento's machines are apart from the user's own smolvm. Tell
users to run `bento smolvm …`, never a bare `smolvm …`, which sees other machines. Tests:
`SMOLBENTO_SMOLVM` runs another binary (a local build), and e2e shares `/tmp/sbt-e2e-<uid>`.

As of smolvm 1.36. Check the reference source before depending on anything not listed here.

- **Errors:** `--error-format json` prints `{"error":{"code":…,"message":…}}` on stderr. The exit
  status is unchanged. Branch on `code` (`NOT_FOUND`, `CONFLICT`, `INTERRUPTED`, `CONFIG_ERROR`,
  `INVALID_STATE`, `STORAGE_ERROR`, `MOUNT_ERROR`, `KVM_UNAVAILABLE`, `HYPERVISOR_UNAVAILABLE`,
  `COMMAND_FAILED`, `SMOLVM_ERROR`), never on the message. Known quirks live in
  `src/smolvm/error.rs`.
- **Idmapped mounts (1.34.2+):** a `-v` host directory shows as owned by the machine's workload user
  (`-u` at `machine create`) when that user isn't root and the directory isn't owned by root (nor is
  smolvm run as root). Files stay owned by the host user. Live `machine mount add` mounts are mapped
  too. `--mount-socket` sockets are unaffected. So create with the session user (`agent`, or a
  workload's image user; `_builder` stays root), and never remap uids. The user must exist in the
  image, or the start fails. Startup steps exec as root.
- **Labels change in any state (1.35):** `machine update --label KEY=VALUE` and `--remove-label KEY`
  work on a running or stopped machine and need no restart, so sandbox metadata can change after
  create.
- **Always pass `--name`.** Without it, smolvm targets `$SMOLVM_MACHINE_NAME` (a user's direnv may set
  it), else `default`.
- **`machine update` needs a stopped machine.** The exception is allow-list changes (`--allow-host`,
  `--allow-host-pattern`, `--allow-cidr`, `--allow-udp` and their `--remove-*` forms) on a machine
  started with an allow list. Those apply from its next connection or DNS lookup, and persist.
  Lifting the allow list entirely, and every other change, waits for the next start.
- **Egress:** off by default. `--allow-host` matches a host and its subdomains. `--allow-host-pattern`
  matches an exact host, or `*.domain` for subdomains only. `--deny-cidr` (create and run only) is
  checked before every allow. `--allow-udp CIDR[:PORT[-END]]` is the only port-aware rule. Cloud
  metadata is always blocked. smolvm has no host-port, host-deny, method or path rules: see
  `docs/sbx-compatibility.md`. Hosted egress enforces them in bento's egress process (method, path
  and query rules by decrypting the hosts they name: `docs/network-and-secrets.md#request-rules`).
- **Interception:** credential substitution (`--credential`) can't be combined with
  `--egress-interceptor`/`--mediated-egress` or with `--trust-host-certs`. Proxy variables aren't
  forwarded unless `--use-host-proxy` is given. Since 1.35, a credential host's responses have the
  injected value replaced by the placeholder, so an echo can't prove substitution: check the
  server's answer instead (the e2e tests use httpbin's `/basic-auth`). A hosted sandbox (the
  default `network.egress`) starts with `--egress-interceptor`, so bento's egress process decides
  every TCP flow (by address and port, then by SNI or `Host:`) and swaps its secrets; smolvm gets
  no `--credential`. smolvm still applies the allow list, and drops every UDP datagram but DNS.
  It decrypts secret hosts and request-rule hosts with one broad CA per sandbox, and judges each
  request there through the interceptor's request filter (a 403 names the rule). A change to the
  set of request-rule hosts makes it exit 0, and its socket starts it again.
- **Credential values change live (1.35.4):** `machine credentials refresh -n M [BINDING…]` reads
  each binding's variable from its own environment and the running machine uses it from its next
  request. It refuses an unset or empty variable, so it can't take a value away. smolbento names
  every binding after its variable, lowercased (`Credential::binding`).
- **Credential bindings change live (1.36.1):** `machine credentials add -n M --credential SPEC`
  (replaces a binding of the same name) and `machine credentials remove -n M BINDING…` work on a
  running or stopped machine, from its next request. A new host gets its own CA, trusted by the
  guest at once. `machine ls --json` and `machine status --json` list each machine's `credentials`
  (name, variable, hosts; never values). A running machine that booted with no bindings takes
  added ones from its next start. `secret set` adds a service a sandbox lacks; `secret rm`
  refreshes running sandboxes with the value that still applies, else `smolbento-secret-removed`,
  and never removes a binding (a removed kit binding can't be rebuilt).
- **Host loopback (1.36):** a machine with a network reaches the host's `127.0.0.1` through its
  gateway or `host.docker.internal` unless `--deny-cidr` closes it. smolbento always passes
  `--deny-cidr 127.0.0.0/8 ::1/128` at create unless the sandbox gets host access.
- **First start (1.36):** smolvm no longer adds the image's registry to the allow list for a
  machine's first boot; it fetches the image on the host instead.
- **Guest `/tmp`, `/run` and `/dev/shm` are emptied on every restart,** and never enter a pack. `/run`
  and `/dev/shm` are tmpfs. `/tmp` is on the machine's root disk since 1.33. Anything smolbento puts
  there (for example `/run/smolbento`) must be recreated after each start. Persistent data goes on the
  machine's disk or in `/workspace`.
- **Images:** when the guest can't reach the registry, smolvm pulls the image on the host at the first
  start. That start still needs registry authorization. Later starts don't contact the registry.
  `--image` also takes a local archive (`./img.tar`, or `-` for stdin) or an unpacked rootfs dir.
  smolvm boots images and never builds them.
- **Lifecycle:** read-only commands (`ls`, `status`, `images`) never change a VM's state. `machine stop`
  sends SIGTERM and waits up to the stop timeout (`--timeout SECS`; `0` kills immediately), while
  `delete` doesn't wait. `machine logs` has the workload's output, not `exec` output. `machine mount
  add` mounts into a running machine until it stops.
- **Defaults:** 4 CPUs; memory of half the host's RAM, up to 8192 MiB; 20 GiB storage; 10 GiB overlay.
  Memory is elastic (balloon). Disks under 20 GiB need no host tools.
- **Exec output:** a plain `machine exec` prints when the command ends, and fails past 11 MiB of output.
  `--stream` prints as it arrives, with no cap. `-i` streams too.
- **Published ports** listen on `127.0.0.1` and `[::1]`, up to 4096 per machine. Ports below 1024 work
  on macOS too.
- **Files:** `machine cp` uploads a directory like `cp -r` (following symlinks), but downloads single
  files only. `machine files --name M upload-folder|download|archive` (1.35.4, `--name` only, absolute
  guest paths, a running machine) uploads a folder keeping links as links (the destination's parent
  must exist), downloads a file, or downloads a directory as a tar.
- **Secret refs** (`--secret-env GUEST=HOST_VAR`, `--secret-file`) resolve at launch and are never
  persisted. The HTTP API and `.smolmachine` packs refuse them.

## Layout

| Module | Responsibility |
|---|---|
| `main.rs` | process entry; `bento` and `sbx` are links to the one binary |
| `cli` | clap definitions mirroring sbx; handlers |
| `provision` | create and start: binds policy, secrets and kits to a sandbox; the kit builder |
| `ctx` | the context every command gets: paths, settings, smolvm, stdio |
| `smolvm` | `Runner` trait, command builder, JSON types; the pin (`smolvm.lock`), download and locate |
| `sandbox` | naming, labels, lifecycle, session tracking |
| `agents` | built-in agent names → sbx's published kits; retired agents |
| `workspace` | mounts; clone mode (host git, `sandbox-<name>` remote) |
| `config` | settings and precedence |
| `policy` | network rules, presets, compile to smolvm flags |
| `util` | leaf helpers: shell quoting, hashing, size parsing |
| `secrets` | sources, stores, resolve at start |
| `skills` | shared skills store; `--skills` modes; kit skill capabilities |
| `templates` | saved templates: smolvm packs, index, export archive |
| `mcp` | registered MCP servers; `--static-mcp`: hosts, credentials and agent config steps |
| `kits` | kit files: load, resolve, compose the image, apply to a sandbox; registry pulls |
| `env` | `sbxenv.yaml` environment files |
| `bridge` | host services for a sandbox: browser and clipboard shims, login relay; the socket listener |
| `host_service` | launchd and `systemd --user` units that own a sandbox's agent and bridge sockets; the orphan sweep |
| `ssh_agent` | SSH agent forwarding: grants, the label, the filtering proxy |
| `ssh` | `setup ssh` config block; the SSH server `ssh proxy` runs (sessions on a pty, `-L` forwards) |
| `crates/egress-front` | workspace member, the only crate on smolvm's `smolvm-credentials` and `smolvm-protocol` (git, at a fork `rev`: see its `Cargo.toml`); written to be lifted into smolvm, so no bento terms; see its README |

Shipped kits live in `kits/`. Planned for later phases: `tui`, and `images/plus/` for the plus image.

## Working

- Dev shell: `direnv allow` once (nix-direnv loads the flake). Shells without the direnv hook, such as
  agent tool shells, use `direnv exec . <cmd>`.
- `crates/egress-front` takes smolvm's crates from a tag on the `josmo/smolvm` fork, made by `just smolvm-fork` (what the
  tag is based on: the comment in the crate's `Cargo.toml`). A new tag updates the crate's `tag` and the flake hash.
- Fetching the smolvm git dependency may need `CARGO_NET_GIT_FETCH_WITH_CLI=true GIT_LFS_SKIP_SMUDGE=1`: a user git
  config can rewrite https to ssh, and smolvm's repo carries ~800 MB of LFS the crate doesn't need.
- Recipes: `just build`, `just test` (nextest: unit, `insta` snapshots, sbx parity), `just lint` (prek),
  `just e2e [threads] [filter]` (boots real VMs; needs a hypervisor), and `just check-target TARGET`
  (cross-compiles in a container).
- **Testing: fastest check first, each long run once.**
  - While iterating, run only the tests for what you changed: `direnv exec . cargo nextest run --lib
    <module or test name>`, or one group of e2e tests with `just e2e 2 <name filter>` (for example
    `basics::hosted_`). A name filter narrows the recipe's; never add a second `-E`, which is ORed and
    runs the whole suite.
  - Run each long check once, on the final tree. `just test` and `just lint` before each commit. The
    e2e tests your change touches once, after the last code change: commits that only change docs,
    or a rebase that brings no new code, don't need another run. The full `just e2e` only when a
    change reaches every sandbox (a new default, the create or start path), and then once.
  - Leave to CI what it already runs. CI's `darwin-check` covers `just check-target
    aarch64-apple-darwin` in about 3 minutes, while a local run can take 15 or more on a cold
    submodule fetch, so run it locally only for macOS-only code. The Linux e2e shards run on every PR.
  - A run that shows no progress for about twice its usual time (a stalled fetch, a hung image build)
    is stopped, not waited out. After a failure, rerun only the failed tests to tell a flake from a
    regression; Docker Hub pull timeouts are the environment, not the change.
  - Run `just test` and the affected `just e2e` tests on your Mac before pushing changes that affect
    macOS: CI can't boot VMs on macOS.
- Writing e2e tests: they run two at a time (`just e2e 4` for more), so each needs its own sandbox
  names and config/cache dirs. A test that changes global state (like the shared `_builder`) must be
  the only one that does. A test that needs outside credentials gets its own recipe
  (`just e2e-dhi`) and fails without them; it never returns early, which would pass.
- CI runs Linux only by default. VM tests run in CI only on x64 Linux, split over three runners by
  `just e2e-shard N`: the slowest tests are placed by hand (`e2e_heavy_*` in the justfile, kept in
  step with `.config/nextest.toml`), the rest by nextest's `--partition slice:N/3`. So an e2e test
  can't rely on another having run on the same machine. GitHub's arm64 Linux and macOS runners can't
  boot VMs. A macOS unit-test job runs only on manual `workflow_dispatch` with `macos: true`.
- The macOS release binary is cross-compiled on Linux and never run in CI. The full release builds
  run on the release-please PR and on PRs that change the build's inputs. Before merging a
  release-please PR, run `just test` and `just e2e` on a Mac. To build it natively instead, change
  its release matrix entry to `runner: macos-latest, builder: cargo`.
- New command or flag: add a parity line to `tests/parity/sbx-commands.txt` if it exists in sbx, a
  fake-`Runner` test asserting the smolvm argv, and update `--help` snapshots (`cargo insta review`).
- Reference smolvm source: `../smolvm-ref` (flags in `src/cli/machine.rs`, Smolfile in
  `docs/smolfile.md`, credentials in `docs/credential-substitution.md`, egress rules in
  `docs/throwaway-machine/README.md` and `docs/mediated-egress.md`, HTTP API in `docs/local-api/`;
  `docs/README.md` indexes the rest). Its `AGENTS.md` is the CLI quick reference.
- smolvm upstream (smol-machines/smolvm) acts on focused issues fast and merges small PRs. Propose a
  missing smolvm feature there (issue first, then a small PR) before building a workaround in
  smolbento.
- Conventional commits; release-please cuts releases.
