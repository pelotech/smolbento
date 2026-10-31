# smolbento

A Docker Sandboxes (`sbx`) compatible CLI on top of [smolvm](https://github.com/smol-machines/smolvm)
microVMs. One Rust binary, invoked as `sbt`, `sbx` or `bento`.

Design notes, specs and plans live in `docs/superpowers/` when present (gitignored for now, so they
exist only in some checkouts). If they're there, read the relevant section before changing behaviour.

## Rules

- **Shell out to smolvm; never link it.** Every smolvm call goes through the `Runner` trait in
  `src/smolvm/`. Pass `--error-format json`; parse `--json` output, not tables.
- **smolvm is the state.** Per-sandbox metadata lives in `sbx.*` machine labels set at create.
  Do not add a sandbox state file. Global data lives in `~/.config/smolbento/*.toml`.
- **Always `--net-backend virtio-net`** on create; live policy and port changes depend on it.
- **Command output goes through `ctx.out`** (`writeln!(&ctx.out, ..)`), never `println!`; tests
  read it with `t.stdout()`. Errors and warnings stay `eprintln!`.
- **Interactive exec inherits stdio.** `run` and `exec -it` exec `smolvm machine exec -it`
  directly; never pipe a TTY through buffers.
- **Secrets (when they land):** store sources only (keychain, `op://`/aws ref, command). Resolve
  at `start` and pass as env to `smolvm machine start`. Never write values to disk, logs or argv.
- **Never use smolvm `--docker-socket`.** Docker in a sandbox is its own private dockerd, started
  by smolbento after each start.
- **sbx compatibility:** flags and output match the sbx CLI reference. Record intentional
  differences in `docs/sbx-compatibility.md` rather than diverging silently. smolbento-only
  commands must not collide with sbx command names, and are added only when implemented.
- macOS + Linux now; keep path handling in `workspace` so Windows can be added later (smolvm
  itself runs on Windows hosts, with the caveats in its `docs/limitations.md`).

## smolvm behaviour to rely on

As of smolvm 1.32. Check the reference source before depending on anything not listed here.

- **Errors:** `--error-format json` prints `{"error":{"code":…,"message":…}}` on stderr, and the
  exit status is unchanged. Branch on `code` (`NOT_FOUND`, `CONFLICT`, `INTERRUPTED`,
  `CONFIG_ERROR`, `INVALID_STATE`, `STORAGE_ERROR`, `MOUNT_ERROR`, `KVM_UNAVAILABLE`,
  `HYPERVISOR_UNAVAILABLE`, `COMMAND_FAILED`, `SMOLVM_ERROR`), never on the message. Known quirks
  live in `src/smolvm/error.rs`.
- **Always pass `--name`.** Without it, smolvm targets `$SMOLVM_MACHINE_NAME` (a user's direnv
  may set it), else `default`.
- **`machine update` needs a stopped machine.** The exception is allow-list changes
  (`--allow-host`, `--allow-host-pattern`, `--allow-cidr`, `--allow-udp` and their `--remove-*`
  forms) on a machine started with an allow list: those apply from its next connection or DNS
  lookup and persist. Lifting the allow list entirely, and every other change, waits for the next
  start.
- **Egress:** off by default. `--allow-host` matches a host and its subdomains;
  `--allow-host-pattern` matches an exact host, or `*.domain` for subdomains only. `--deny-cidr`
  (create and run only) is checked before every allow. `--allow-udp CIDR[:PORT[-END]]` is the
  only port-aware rule. Cloud metadata is always blocked. smolvm has no host-port, host-deny,
  method or path rules: see `docs/sbx-compatibility.md`.
- **Interception:** credential substitution (`--credential`) can't be combined with
  `--egress-interceptor`/`--mediated-egress` or with `--trust-host-certs`. Proxy variables
  aren't forwarded unless `--use-host-proxy` is given.
- **Guest `/tmp`, `/run` and `/dev/shm` are tmpfs, emptied on every restart.** Anything
  smolbento puts there (for example `/run/smolbento`) has to be recreated after each start.
  Persistent data goes on the machine's disk or in `/workspace`.
- **Images:** when the guest can't reach the registry, smolvm pulls the image on the host at
  the first start. That start still needs registry authorization; later starts don't contact the
  registry. `--image` also takes a local archive (`./img.tar`, or `-` for stdin) or an unpacked
  rootfs dir. smolvm boots images and never builds them.
- **Lifecycle:** read-only commands (`ls`, `status`, `images`) never change a VM's state.
  `machine stop` sends SIGTERM and waits up to the stop timeout (`--timeout SECS`; `0` kills
  immediately), while `delete` doesn't wait. `machine logs` has the workload's output, not
  `exec` output. `machine mount add` mounts into a running machine until it stops.
- **Defaults:** 4 CPUs, 8192 MiB memory, 20 GiB storage, 10 GiB overlay. Memory is elastic
  (balloon). Disks under 20 GiB need no host tools.
- **Secret refs** (`--secret-env GUEST=HOST_VAR`, `--secret-file`) resolve at launch and are
  never persisted. The HTTP API and `.smolmachine` packs refuse them.

## Layout

| Module | Responsibility |
|---|---|
| `main.rs` | argv[0] dispatch |
| `cli` | clap definitions mirroring sbx; thin handlers |
| `smolvm` | `Runner` trait, command builder, JSON types |
| `sandbox` | naming, labels, lifecycle, session tracking |
| `agents` | agent presets (data) |
| `workspace` | mounts; clone mode (host git, `sandbox-<name>` remote) |
| `config` | settings and precedence |
| `policy` | network rules, presets, compile to smolvm flags |
| `secrets` | sources, stores, resolve at start |
| `skills` | shared skills store; --skills modes; kit skill capabilities |
| `templates` | saved templates: smolvm packs, index, export archive |

Planned for later phases: `kits`, `hostsvc`
(host services and `_relay`), `mcp`, `tui`; `kits/` for shipped kits and `images/plus/` for the plus
image.

## Working

- Dev shell: `direnv allow` once (nix-direnv loads the flake). Shells without the direnv hook, such
  as agent tool shells, use `direnv exec . <cmd>`.
- `just build`, `just test` (nextest: unit, `insta` snapshots, sbx parity), `just lint` (prek),
  `just e2e` (boots real VMs; needs a hypervisor). e2e tests run two at a time (`just e2e 4` for
  more), so each needs its own sandbox names and config/cache dirs; one that changes global state
  (like the shared `_builder`) must be the only test that does.
- CI runs Linux only by default. VM tests (`just e2e`) run in CI only on x64 Linux: GitHub's
  arm64 Linux and macOS runners can't boot VMs. Run `just test` and `just e2e` on your Mac before
  pushing changes that affect macOS. A macOS unit-test job runs only on manual
  `workflow_dispatch` with `macos: true`.
- The macOS release binary is cross-compiled on Linux and never run in CI. Before merging a
  release-please PR, run `just test` and `just e2e` on a Mac. To build it natively instead,
  change its release matrix entry to `runner: macos-latest, builder: cargo`.
- New command or flag: add a parity line to `tests/parity/sbx-commands.txt` if it exists in sbx,
  a fake-`Runner` test asserting the smolvm argv, and update `--help` snapshots
  (`cargo insta review`).
- Reference smolvm source: `../smolvm-ref` (flags in `src/cli/machine.rs`, Smolfile in
  `docs/smolfile.md`, credentials in `docs/credential-substitution.md`, egress rules in
  `docs/throwaway-machine/README.md` and `docs/mediated-egress.md`, HTTP API in
  `docs/local-api/`; `docs/README.md` indexes the rest). Its `AGENTS.md` is the CLI quick
  reference.
- smolvm upstream (smol-machines/smolvm) acts on focused issues fast and merges small PRs.
  Propose a missing smolvm feature there (issue first, then a small PR) before building a
  workaround in smolbento.
- Conventional commits; release-please cuts releases.
