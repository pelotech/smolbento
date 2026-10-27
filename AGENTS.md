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
- **Interactive exec inherits stdio.** `run` and `exec -it` exec `smolvm machine exec -it`
  directly; never pipe a TTY through buffers.
- **Secrets (when they land):** store sources only (keychain, `op://`/aws ref, command). Resolve
  at `start` and pass as env to `smolvm machine start`. Never write values to disk, logs or argv.
- **Never use smolvm `--docker-socket`.** Docker in a sandbox is its own private dockerd, started
  by smolbento after each start.
- **sbx compatibility:** flags and output match the sbx CLI reference. Record intentional
  differences in `docs/sbx-compatibility.md` rather than diverging silently. smolbento-only
  commands must not collide with sbx command names, and are added only when implemented.
- macOS + Linux now; keep path handling in `workspace` so Windows can be added later.

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

Planned for later phases: `policy`, `secrets`, `kits`, `hostsvc`
(host services and `_relay`), `mcp`, `tui`; `kits/` for shipped kits and `images/plus/` for the plus
image.

## Working

- Dev shell: `direnv allow` once (nix-direnv loads the flake). Shells without the direnv hook, such
  as agent tool shells, use `direnv exec . <cmd>`.
- `just build`, `just test` (nextest: unit, `insta` snapshots, sbx parity), `just lint` (prek),
  `just e2e` (boots real VMs; needs a hypervisor).
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
  `docs/smolfile.md`, credentials in `docs/credential-substitution.md`).
- Conventional commits; release-please cuts releases.
