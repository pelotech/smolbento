# List recipes
default:
    @just --list

# Build the smolbento binary
build:
    cargo build --locked

# Run unit, snapshot and parity tests
test:
    cargo nextest run --locked

# Run end-to-end tests against real smolvm VMs (needs a hypervisor), `threads` VMs at a time;
# further arguments go to nextest (e.g. `--partition slice:1/3`)
e2e threads="2" *args:
    cargo nextest run --locked --run-ignored only --test-threads {{threads}} --no-fail-fast -E 'binary(e2e)' {{args}}

# Run all pre-commit hooks
lint:
    prek run --all-files

# Install smolbento and its sbt/sbx/bento links into ~/.cargo/bin
install:
    cargo install --locked --path .
    for n in sbt sbx bento; do ln -sf smolbento "$HOME/.cargo/bin/$n"; done

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
        # The image carries the macOS SDK (keyring links Security.framework in later phases).
        # Match the Nix dev shell's rustc so release builds use the same compiler tested in CI.
        rust_ver=$(rustc -V | cut -d' ' -f2)
        docker run --rm -v "$PWD":/io -w /io -e MACOSX_DEPLOYMENT_TARGET=13.0 \
            -e RUSTUP_TOOLCHAIN="$rust_ver" \
            ghcr.io/rust-cross/cargo-zigbuild:0.23.4@sha256:d8313491ec5798de0633fdc1c5753761bff79967bea69076020dc78121b2cca8 \
            sh -c "rustup toolchain install $rust_ver --profile minimal --no-self-update -t {{target}} && cargo zigbuild --locked --release --target $zig_target"
        sudo chown -R "$(id -u):$(id -g)" target
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
    for n in sbt sbx bento; do ln -s smolbento "$stage/$n"; done
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

# Run Docker's kit-spec conformance suite (ssh-agent@1 only) against the adapter in
# tests/conformance. Boots real VMs and builds the suite's workload image (needs a hypervisor
# and the image builder); further arguments go to `kit-tck runtime` (e.g. `--verbose`).
conformance *args:
    #!/usr/bin/env bash
    set -euo pipefail
    # sandbox-kit-spec commit the suite is taken from; bump it deliberately.
    spec_commit=06ac386a1b5d570daff36bba4232fb9e71e45d50
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
    GOWORK=off nix shell nixpkgs#go -c go run ./cmd/kit-tck runtime --adapter "$adapter" --timeout 2h {{args}}
