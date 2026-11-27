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
| `just e2e` | Real-VM tests, eight at a time (`just e2e 2` for fewer, on a smaller machine); `just e2e-shard 1` is one of CI's three shards, two at a time. Needs a hypervisor |
| `just e2e-dhi` | The e2e test that builds from `dhi.io`; needs a Docker Hardened Images login (`SMOLBENTO_E2E_DHI_USER` and `SMOLBENTO_E2E_DHI_TOKEN_FILE`), so `just e2e` leaves it out |
| `just conformance` | The kit spec's conformance suite against `tests/conformance` (see its README). Boots VMs |
| `just smolvm-pin VERSION` | Pin smolvm `VERSION`: rewrite `smolvm.lock` from that release's checksums |
| `just smolvm-lock-check` | Check `smolvm.lock` against its release (CI runs it) |
| `just smolvm-fork BASE` | Point `crates/egress-front` at the fork tag for `BASE` (see [below](#egress-fronts-smolvm-crates)) |
| `just demo` | Record the README demo (`docs/demo.tape`) into `dist/demo.gif`. Boots a VM; uses its own dirs, never yours |
| `just demo-publish` | Replace the GIF the README shows (the `demo` release's asset) |
| `just lint` | All pre-commit hooks: fmt, clippy, cargo-deny, yamllint, actionlint, zizmor |
| `just install` | Install to `~/.cargo/bin`, with the `bento` and `sbx` links |
| `just release-build TARGET BUILDER` | Build a release tarball into `dist/` |
| `just check-target TARGET` | Unoptimised build for TARGET in the release container (checks macOS-only code) |

Re-record the demo (`just demo`, check `dist/demo.gif`, then `just demo-publish`) when the output it
shows changes. The GIF stays out of git: only the tape is committed.

## Tests

- Unit tests sit next to the code. Handlers run against a fake runner and assert the smolvm command
  lines.
- Snapshots (`insta`) cover every `--help` and `ls` output. Review them with `cargo insta review`.
- The parity list, `tests/parity/sbx-commands.txt`, names the sbx command lines that must keep
  parsing.
- End-to-end tests (`tests/e2e/`, ignored by default) boot small Alpine VMs. They cover lifecycle,
  exec, mounts, `run` auto-stop, `cp`, `diagnose`, network policy, ports and secrets. The policy
  and secrets tests reach `httpbin.org`.
- The `real_*_kit` e2e tests pull the real `claude` and `shell` kits; every other test uses
  stand-ins (`SMOLBENTO_AGENT_KITS_DIR`).

## Running tests

```sh
# one unit test, by name substring
cargo nextest run publish_starts
# one e2e test (boots VMs), by name substring
just e2e 2 bundled_skills_are
# run and accept changed snapshots
cargo insta test --accept
# or review them one by one
cargo insta review
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

## smolvm versions

smolbento runs the smolvm release pinned in `smolvm.lock` ([Architecture](architecture.md#shape)).
e2e tests share the home `/tmp/sbt-e2e-<uid>`, apart from your own
`~/.smolbento`, and reach smolvm through `bento smolvm`.

- **Try a new release:** `just smolvm-pin 1.36.0`, then `just test` and `just e2e`. Commit
  `smolvm.lock` if they pass, or `git checkout smolvm.lock` to go back. Renovate opens a PR that
  bumps the version; CI fails it until someone runs `just smolvm-pin` on that branch.
- **Try a smolvm you built:** `SMOLBENTO_SMOLVM=../smolvm/target/release/smolvm just e2e`. Every
  test uses that binary except `the_pinned_smolvm_runs_from_smolbentos_home`.
- **Debug a test's VMs:** `SMOLBENTO_SMOLVM_HOME=/tmp/sbt-e2e-$(id -u) bento smolvm machine ls --json`.

### egress-front's smolvm crates

`crates/egress-front` takes smolvm's crates from a tag on the `josmo/smolvm` fork, made by
`just smolvm-fork BASE` (the tag's name says its base). A smolvm bump doesn't need a new tag; one
that egress-front needs newer smolvm-credentials code for does, and it updates the crate's `tag` and
the flake hash.

Fetching the smolvm git dependency may need `CARGO_NET_GIT_FETCH_WITH_CLI=true
GIT_LFS_SKIP_SMUDGE=1`: a user git config can rewrite https to ssh, and smolvm's repo carries
~800 MB of LFS the crate doesn't need.

## CI

| Workflow | Runs on | Does |
|---|---|---|
| `build` | PRs, main | Build and test on Linux x86_64 and arm64; macOS only on manual dispatch with `macos: true` |
| `build` / `release-build` | PRs changing build inputs, the release PR, manual dispatch | Cross-build every release target (nothing signed or uploaded) |
| `build` / `darwin-check` | Other PRs with code changes | Unoptimised `aarch64-apple-darwin` build, for macOS-only code |
| `e2e` | PRs, main | Real-VM tests on `ubuntu-latest`, the only GitHub runner that boots VMs |
| `pre-commit` | PRs, main | `prek run --all-files` |
| `lint-pr-title` | PRs | Checks conventional-commit PR titles |
| `plan-nix-devshell` | PRs touching the flake | Comments the dev-shell package diff |
| `Release Please` | main | Opens release PRs; on release, builds signed binaries for all targets |

`e2e` runs as three shards (`just e2e-shard N`). The slowest tests are placed by hand
(`e2e_heavy_*` in the justfile, kept in step with `.config/nextest.toml`), the rest by nextest's
`--partition slice:N/3`. So an e2e test can't rely on another having run on the same machine.

Runner time savings:

- A new push cancels that PR's runs in progress. Runs on `main` queue, so every merged commit gets a
  result and a release is never cancelled.
- `build` and `e2e` run only for code or tooling changes (paths in `.github/filters.yaml`). They show as
  skipped on docs-only PRs, which passes required checks.
- Cargo caches (`Swatinem/rust-cache`) are saved from `main` only. A dependency change makes the first
  `main` run slow.

macOS isn't tested in CI: GitHub's Apple Silicon runners can't boot VMs. Before merging a change
that affects macOS, or a release PR, run `just test` and `just e2e` on a Mac. Hosted egress's Linux
systemd units are tested in CI, and its macOS launchd units by running `just e2e` on a Mac.

## Releases

Merging the release-please PR tags the release. The workflow then builds all three targets on Linux with
cargo-zigbuild:

- Linux binaries target glibc 2.28 and are smoke-tested in a plain Debian container.
- The macOS binary is cross-compiled and ad-hoc signed with `rcodesign`. To build it natively, change its
  matrix entry to `runner: macos-latest, builder: cargo`.

Each tarball is signed with `cosign sign-blob` and uploaded to the release.
