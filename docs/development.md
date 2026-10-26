# Development

## Dev shell

Tooling (Rust, cargo-nextest, cargo-insta, cargo-deny, just, prek, yamllint, actionlint, zizmor,
trivy, rcodesign) comes from the Nix flake. With [Nix](https://nixos.org) and
[direnv](https://direnv.net):

```sh
direnv allow
prek install --hook-type pre-commit --hook-type commit-msg
```

In shells without the direnv hook, run commands through it: `direnv exec . just test`. Without
direnv, use `nix develop`.

## Recipes

| Command | What it does |
|---|---|
| `just build` | Build the binary |
| `just test` | Unit, snapshot and sbx parity tests (nextest) |
| `just e2e` | End-to-end tests that boot real VMs; needs smolvm and a hypervisor |
| `just lint` | All pre-commit hooks: fmt, clippy, cargo-deny, yamllint, actionlint, zizmor |
| `just install` | Install into `~/.cargo/bin` with the `sbt`/`sbx`/`bento` links |
| `just release-build TARGET BUILDER` | Build a release tarball into `dist/` |

## Tests

- **Unit tests** sit next to the code. Command handlers are tested against a fake smolvm runner
  and assert the exact smolvm command lines.
- **Snapshots** (`insta`) cover every `--help` and the `ls` output. Review changes with
  `cargo insta review`.
- **Parity:** `tests/parity/sbx-commands.txt` lists sbx command lines that must keep parsing.
- **End-to-end** (`tests/e2e.rs`, ignored by default) boots small Alpine VMs: lifecycle, exec, same-path
  mounts, `run` auto-stop, `cp`, `diagnose`.

## CI

| Workflow | When | What |
|---|---|---|
| `build` | PRs, main | Build and test on Linux x86_64 and arm64; macOS only on manual dispatch with `macos: true` |
| `e2e` | PRs, main | Real-VM tests on `ubuntu-latest` (the only GitHub runner that can boot VMs) |
| `pre-commit` | PRs, main | `prek run --all-files` |
| `lint-pr-title` | PRs | Conventional-commit PR titles |
| `plan-nix-devshell` | PRs touching the flake | Comments the dev-shell package diff |
| `Release Please` | main | Release PRs; on release, signed binaries for all targets |

To save runner time:

- A new push to a PR cancels that PR's runs still in progress. Runs on `main` queue instead, so
  every merged commit gets a result, and a release is never cancelled mid-way.
- `build` and `e2e` run only when code or tooling changes (the paths in `.github/filters.yaml`).
  On a docs-only PR they show as skipped, which counts as passing for required checks.
- Cargo builds are cached with `Swatinem/rust-cache`. The cache is saved from `main` only; PRs
  restore it, so the first run after a dependency change on `main` is the slow one.
- Every job has a `timeout-minutes`.

macOS isn't tested in CI by default (it's expensive, and GitHub's Apple Silicon runners can't boot
VMs). Run `just test` and `just e2e` on a Mac before merging changes that affect macOS, and before
merging a release PR.

## Releases

release-please opens a release PR from conventional commits. Merging it tags the release, and the
workflow builds all three targets on Linux with cargo-zigbuild:

- Linux binaries target glibc 2.28 and are smoke-tested in a plain Debian container.
- The macOS binary is cross-compiled and ad-hoc signed with `rcodesign`. To build it natively
  instead, change its matrix entry to `runner: macos-latest, builder: cargo`.

Each tarball is signed with `cosign sign-blob` and uploaded to the release.
