# List recipes
default:
    @just --list

# Build the smolbento binary
build:
    cargo build --locked

# Run unit, snapshot and parity tests
test:
    cargo nextest run --locked

# Run end-to-end tests against real smolvm VMs (needs a hypervisor)
e2e:
    cargo nextest run --locked --run-ignored only --test-threads 1 -E 'binary(e2e)'

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
        docker run --rm -v "$PWD":/io -w /io -e MACOSX_DEPLOYMENT_TARGET=13.0 \
            ghcr.io/rust-cross/cargo-zigbuild:0.23.4 \
            sh -c "rustup target add {{target}} && cargo zigbuild --locked --release --target $zig_target"
        sudo chown -R "$(id -u):$(id -g)" target
        case "{{target}}" in *-apple-darwin)
            # Apple Silicon refuses unsigned binaries; an ad-hoc signature is enough for a CLI.
            rcodesign sign "$bin"
            rcodesign verify "$bin"
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
