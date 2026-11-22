# List recipes
default:
    @just --list

# Build the smolbento binary
build:
    cargo build --locked

# Run unit, snapshot and parity tests
test:
    cargo nextest run --locked --workspace

# The e2e test that builds from dhi.io: it needs a Docker Hardened Images login, so `e2e` leaves
# it out and `e2e-dhi` runs it (set SMOLBENTO_E2E_DHI_USER and SMOLBENTO_E2E_DHI_TOKEN_FILE).
needs_dhi := "test(local_kit_builds_from_a_registry_that_needs_a_login)"

# Run end-to-end tests against real smolvm VMs (needs a hypervisor), `threads` VMs at a time;
# further arguments go to nextest (e.g. `-E 'test(clone)'`)
e2e threads="2" *args:
    cargo nextest run --locked --run-ignored only --test-threads {{threads}} --no-fail-fast -E 'binary(e2e) & !({{needs_dhi}})' {{args}}

# The slowest e2e tests (CI, two at a time), dealt to `e2e-shard`'s shards by hand: nextest's
# `slice` deals by position, whatever a test takes, and once put most of them on one runner. CI
# times: nix 125s; claude 52s, local_v3 36s; shell 46s, fork 28s, clone 24s; the rest 23s or less.
# A renamed test just joins the rest. `.config/nextest.toml` starts these first (keep it in step).
e2e_heavy_1 := "test(=kits::real_claude_kit_binds_its_api_key_and_seeds_its_settings) | test(=kits::local_v3_kit_builds_in_the_builder_sandbox)"
e2e_heavy_2 := "test(=kits::real_shell_kit_runs_dockerd_across_restarts) | test(=fork_template::fork_round_trip) | test(=basics::clone_round_trip)"
e2e_heavy_3 := "test(=kits::nix_kit_works_for_an_agent_and_a_workload_image_user)"

# Run CI shard `shard` (1, 2 or 3) of `e2e`: its own heavy tests (e2e_heavy_N) and nextest's
# `slice:N/3` of the rest, in one nextest run so the heavy ones run beside the others.
e2e-shard shard threads="2" *args:
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{shard}}" in
        1) mine='{{e2e_heavy_1}}' ;;
        2) mine='{{e2e_heavy_2}}' ;;
        3) mine='{{e2e_heavy_3}}' ;;
        *) echo "shard is 1, 2 or 3" >&2; exit 2 ;;
    esac
    # Every test runs on exactly one shard. The heavy sets are disjoint and together are every
    # heavy test. `rest` is the same set on every shard (every e2e test that isn't heavy), and
    # nextest partitions after filtering, so slice 1, 2 and 3 of it are disjoint and cover it.
    rest=$(cargo nextest list --locked --run-ignored only --message-format oneline \
        --partition "slice:{{shard}}/3" \
        -E 'binary(e2e) & !({{needs_dhi}}) & !({{e2e_heavy_1}} | {{e2e_heavy_2}} | {{e2e_heavy_3}})' \
        | awk '{ printf " | test(=%s)", $2 }')
    cargo nextest run --locked --run-ignored only --test-threads {{threads}} --no-fail-fast \
        -E "binary(e2e) & ($mine$rest)" {{args}}

# Run the e2e test that builds from dhi.io (needs a Docker Hardened Images login; see needs_dhi)
e2e-dhi *args:
    cargo nextest run --locked --run-ignored only --no-fail-fast -E 'binary(e2e) & ({{needs_dhi}})' {{args}}

# Pin smolvm VERSION: rewrite smolvm.lock from that release's checksums.sha256
smolvm-pin version:
    #!/usr/bin/env bash
    set -euo pipefail
    lock=$(just _smolvm-lock {{version}})
    printf '%s\n' "$lock" > smolvm.lock
    sed -i.bak 's|version = "[0-9.]*", tag = "v[^"]*"|version = "{{version}}", tag = "v{{version}}"|' crates/egress-front/Cargo.toml && rm crates/egress-front/Cargo.toml.bak
    echo "pinned smolvm {{version}}; run cargo update -p smolvm-credentials, and refresh the smolvm-* outputHashes in flake.nix (the failing nix build prints them)"

# Check smolvm.lock's checksums against its version's release (fails a version bump until pinned)
smolvm-lock-check:
    #!/usr/bin/env bash
    set -euo pipefail
    v=$(sed -n 's/^version = "\(.*\)"/\1/p' smolvm.lock)
    if ! diff -u smolvm.lock <(just _smolvm-lock "$v"); then
        echo "error: smolvm.lock doesn't match smolvm $v's checksums; run \`just smolvm-pin $v\`" >&2
        exit 1
    fi

# Print smolvm.lock for VERSION, from that release's checksums.sha256
_smolvm-lock version:
    #!/usr/bin/env bash
    set -euo pipefail
    sums=$(curl -fsSL "https://github.com/smol-machines/smolvm/releases/download/v{{version}}/checksums.sha256")
    hash() { echo "$sums" | awk -v f="smolvm-{{version}}-$1.tar.gz" '$2 == f { print $1 }'; }
    echo "# smolvm release smolbento runs; \`just smolvm-pin VERSION\` rewrites this file."
    echo 'version = "{{version}}"'
    echo
    echo '[sha256]'
    for p in darwin-arm64 linux-arm64 linux-x86_64; do
        h=$(hash "$p"); [ -n "$h" ] || { echo "error: no $p asset in v{{version}}" >&2; exit 1; }
        echo "$p = \"$h\""
    done

# Run all pre-commit hooks
lint:
    prek run --all-files

# Install smolbento and its bento/sbx links into ~/.cargo/bin
install:
    cargo install --locked --path .
    for n in bento sbx; do ln -sf smolbento "$HOME/.cargo/bin/$n"; done

# Unoptimised build for TARGET in the release container: checks code only it compiles (macOS-only)
check-target target:
    just _zigbuild {{target}} --locked --target {{target}}

# `cargo zigbuild ARGS` for TARGET in the release cross-build container, whose image carries the
# macOS SDK the darwin target links against, on the Nix dev shell's rustc (the one tested in CI)
_zigbuild target *args:
    #!/usr/bin/env bash
    set -euo pipefail
    rust_ver=$(rustc -V | cut -d' ' -f2)
    docker run --rm -v "$PWD":/io -w /io -e MACOSX_DEPLOYMENT_TARGET=13.0 \
        -e RUSTUP_TOOLCHAIN="$rust_ver" \
        ghcr.io/rust-cross/cargo-zigbuild:0.23.4@sha256:d8313491ec5798de0633fdc1c5753761bff79967bea69076020dc78121b2cca8 \
        sh -c "rustup toolchain install $rust_ver --profile minimal --no-self-update -t {{target}} && cargo zigbuild {{args}}"
    sudo chown -R "$(id -u):$(id -g)" target

# Build a release tarball for TARGET into dist/ with BUILDER: cargo (native) or zigbuild (cross from Linux)
release-build target builder:
    #!/usr/bin/env bash
    set -euo pipefail
    bin="target/{{target}}/release/smolbento"
    if [ "{{builder}}" = zigbuild ]; then
        # Linux binaries link against glibc 2.28 (the `.2.28` suffix) rather than the build
        # host's, so they run on any mainstream distro; the output still lands in target/{{target}}.
        zig_target="{{target}}"
        case "{{target}}" in *-linux-gnu) zig_target="{{target}}.2.28" ;; esac
        just _zigbuild {{target}} --locked --release --target "$zig_target"
        case "{{target}}" in *-apple-darwin)
            # Apple Silicon refuses unsigned binaries; an ad-hoc signature is enough for a CLI.
            rcodesign sign "$bin"
            # `rcodesign verify` rejects ad-hoc signatures (they have no CMS blob), so check that a
            # code directory is present instead.
            rcodesign print-signature-info "$bin" | grep -q '^ *code_directory:' \
                || { echo "error: $bin has no code signature" >&2; exit 1; }
            ;;
        esac
    else
        cargo build --locked --release --target {{target}}
        "$bin" version
    fi
    stage="dist/smolbento-{{target}}"
    rm -rf "$stage" && mkdir -p "$stage"
    cp "$bin" LICENSE README.md "$stage/"
    for n in bento sbx; do ln -s smolbento "$stage/$n"; done
    tar -C dist -czf "dist/smolbento-{{target}}.tar.gz" "smolbento-{{target}}"
    # Smoke-test Linux binaries outside the build environment (no Nix store, stock glibc).
    case "{{target}}" in
        x86_64-unknown-linux-gnu)
            docker run --rm --platform linux/amd64 -v "$PWD/dist:/d:ro" debian:stable-slim \
                "/d/smolbento-{{target}}/smolbento" version
            ;;
        aarch64-unknown-linux-gnu)
            info=$(file "$stage/smolbento")
            echo "$info"
            grep -q 'interpreter /lib/ld-linux-aarch64.so.1' <<<"$info"
            ;;
    esac

# Run Docker's kit-spec conformance suite (ssh-agent@1, host-mount@1, lifecycle@1) against the adapter in
# tests/conformance. Boots real VMs and builds the suite's workload image (needs a hypervisor
# and the image builder); further arguments go to `kit-tck runtime` (e.g. `--verbose`).
conformance *args:
    #!/usr/bin/env bash
    set -euo pipefail
    # The suite runs at the spec commit the code implements (SPEC_COMMIT in src/kits/mod.rs).
    spec_commit=$(sed -n 's/^pub const SPEC_COMMIT: &str = "\(.*\)";$/\1/p' src/kits/mod.rs)
    [ -n "$spec_commit" ] || { echo "SPEC_COMMIT not found in src/kits/mod.rs" >&2; exit 1; }
    cache="${XDG_CACHE_HOME:-$HOME/.cache}/smolbento/conformance"
    spec="$cache/sandbox-kit-spec"
    mkdir -p "$cache"
    [ -d "$spec/.git" ] || git clone --quiet https://github.com/docker/sandbox-kit-spec "$spec"
    git -C "$spec" cat-file -e "$spec_commit^{commit}" 2>/dev/null || git -C "$spec" fetch --quiet origin
    git -C "$spec" checkout --quiet --detach "$spec_commit"
    cargo build --locked
    export SMOLBENTO_BIN="$PWD/target/debug/smolbento"
    adapter="$PWD/tests/conformance/smolbento-adapter"
    cd "$spec"
    GOWORK=off nix shell nixpkgs#go nixpkgs#jq -c go run ./cmd/kit-tck runtime --adapter "$adapter" --timeout 2h {{args}}

# Record the README demo into dist/demo.gif with VHS (boots a VM; needs Nix). Your own sandboxes,
# settings and secrets are untouched: the demo has its own dirs and a sandbox-scoped dummy secret.
demo:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release --locked
    # The demo sandbox's scoped secret is a keychain item every smolbento shares: never take over one.
    if [ "$(uname)" = Darwin ] &&
        security find-generic-password -s smolbento -a sandbox:claude-bento-demo/anthropic >/dev/null 2>&1; then
        echo "error: a secret for sandbox claude-bento-demo already exists; remove it first" >&2
        exit 1
    fi
    # A fixed path, since Claude shows it on screen; emptied first.
    export DEMO_DIR=/tmp/bento-demo
    rm -rf "$DEMO_DIR" && mkdir -p "$DEMO_DIR/bin" "$DEMO_DIR/bento-demo" dist
    ln -s "$PWD/target/release/smolbento" "$DEMO_DIR/bin/bento"
    export PATH="$DEMO_DIR/bin:$PATH"
    export SMOLBENTO_CONFIG_DIR="$DEMO_DIR/config" SMOLBENTO_DATA_DIR="$DEMO_DIR/data"
    # Short, and kept between recordings so the VM image stays warm.
    export SMOLBENTO_SMOLVM_HOME="/tmp/bento-demo-$(id -u)"
    cleanup() { bento rm -f claude-bento-demo >/dev/null 2>&1 || true; }
    trap 'cleanup; rm -rf "$DEMO_DIR"' EXIT
    # A run that was killed may have left its sandbox in the demo's smolvm home.
    cleanup
    # Off camera: boot once so the VM image is warm, then forget the policy so its prompt shows.
    (cd "$DEMO_DIR/bento-demo" && bento policy init balanced >/dev/null && bento create claude && cleanup)
    rm -f "$SMOLBENTO_CONFIG_DIR/policy.toml"
    nix run --inputs-from . nixpkgs#vhs -- docs/demo.tape
    ls -lh dist/demo.gif

# Replace the README demo: upload dist/demo.gif to the `demo` prerelease (record it with `just demo`)
demo-publish:
    test -f dist/demo.gif || { echo "error: no dist/demo.gif; run just demo first" >&2; exit 1; }
    gh release upload demo dist/demo.gif --clobber
