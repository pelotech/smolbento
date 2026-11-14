# Development

## Dev shell

The Nix flake provides the tooling. With [Nix](https://nixos.org) and [direnv](https://direnv.net):

```sh
direnv allow
prek install --hook-type pre-commit --hook-type commit-msg
```

Without the direnv hook, prefix commands with `direnv exec .`. Without direnv, use `nix develop`.

## Recipes

| Command | Purpose |
|---|---|
| `just build` | Build the binary |
| `just test` | Unit, snapshot and sbx parity tests (nextest) |
| `just e2e` | Real-VM tests, two at a time. `just e2e 4` runs four; `just e2e 2 --partition slice:1/3` is one CI shard. Needs smolvm and a hypervisor |
| `just lint` | All pre-commit hooks: fmt, clippy, cargo-deny, yamllint, actionlint, zizmor |
| `just install` | Install to `~/.cargo/bin`, with the `sbt`/`sbx`/`bento` links |
| `just release-build TARGET BUILDER` | Build a release tarball into `dist/` |

## Tests

- **Unit tests** sit next to the code. Handlers run against a fake runner and assert the smolvm command lines.
- **Snapshots** (`insta`) cover every `--help` and `ls` output. Review with `cargo insta review`.
- **Parity:** `tests/parity/sbx-commands.txt` lists sbx command lines that must keep parsing.
- **End-to-end** (`tests/e2e/`, ignored by default) boots small Alpine VMs. It covers lifecycle, exec,
  mounts, `run` auto-stop, `cp`, `diagnose`, network policy, ports and secrets. The policy test reaches
  `example.com`; the secrets test reaches `httpbin.org`.

## Running tests

```sh
cargo nextest run publish_starts        # one unit test, by name substring
just e2e 2 bundled_skills_are           # one e2e test (boots VMs), by name substring
cargo insta test --accept               # run and accept changed snapshots
cargo insta review                      # or review them one by one
```

A handler test, from `src/cli/ports.rs`:

```rust
#[test]
fn publish_starts_a_stopped_sandbox_then_updates() {
    let mut t = test_env(&[]);
    t.sandbox("a1", "stopped", &[]);       // fake machine `sbx-a1`, state and labels
    t.sbt(&["ports", "a1", "--publish", "8080:80"]).unwrap();
    let lines = t.calls();                 // every smolvm call, as one line each
    assert!(lines.contains(&"machine start -n sbx-a1 --branchable".to_string()));
    assert_eq!(lines.last().unwrap(), "machine update -n sbx-a1 -p 8080:80");
}
```

`t.sbt_err` returns the error text of a command that must fail; `t.stdout()` returns output. Helpers
are in `src/testutil.rs`.

IDEs should use their own `CARGO_TARGET_DIR` or the Nix toolchain. Sharing `target/` between toolchains
forces a full rebuild on every switch, and it grows past 40 GB.

## CI

| Workflow | Runs on | Does |
|---|---|---|
| `build` | PRs, main | Build and test on Linux x86_64 and arm64; macOS only on manual dispatch with `macos: true` |
| `e2e` | PRs, main | Real-VM tests on `ubuntu-latest`, the only GitHub runner that boots VMs |
| `pre-commit` | PRs, main | `prek run --all-files` |
| `lint-pr-title` | PRs | Checks conventional-commit PR titles |
| `plan-nix-devshell` | PRs touching the flake | Comments the dev-shell package diff |
| `Release Please` | main | Opens release PRs; on release, builds signed binaries for all targets |

Runner time savings:

- A new push cancels that PR's runs in progress. Runs on `main` queue, so every merged commit gets a
  result and a release is never cancelled.
- `build` and `e2e` run only for code or tooling changes (paths in `.github/filters.yaml`). They show as
  skipped on docs-only PRs, which passes required checks.
- Cargo caches (`Swatinem/rust-cache`) are saved from `main` only. A dependency change makes the first
  `main` run slow.
- Every job has a `timeout-minutes`.

macOS isn't tested in CI: it's expensive, and GitHub's Apple Silicon runners can't boot VMs. Run
`just test` and `just e2e` on a Mac before merging changes that affect macOS and before merging a
release PR.

## Releases

Merging the release-please PR tags the release. The workflow then builds all three targets on Linux with
cargo-zigbuild:

- Linux binaries target glibc 2.28 and are smoke-tested in a plain Debian container.
- The macOS binary is cross-compiled and ad-hoc signed with `rcodesign`. To build it natively, change its
  matrix entry to `runner: macos-latest, builder: cargo`.

Each tarball is signed with `cosign sign-blob` and uploaded to the release.
