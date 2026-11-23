# smolvm's crates for egress-front come from a tag on josmo/smolvm: an upstream base plus the request-filter hook
# (smolvm-credentials' RequestFilter and terminate_hosts), and an https .gitmodules until upstream has one, so
# cargo can fetch the submodules. Delete this file once the hook is in a smolvm release and smolvm-credentials is
# on crates.io: egress-front then takes a plain version.

smolvm_upstream := "https://github.com/smol-machines/smolvm"
smolvm_fork := "git@github.com:josmo/smolvm.git"

# Point egress-front at the tag for BASE (default: the release in smolvm.lock) plus the request-filter hook on josmo/smolvm.
# A missing tag is only created and pushed with `push` as the second argument.
smolvm-fork base="" push="":
    #!/usr/bin/env bash
    set -euo pipefail
    base="{{ base }}"
    push="{{ push }}"
    [ -n "$base" ] || base="v$(sed -n 's/^version = "\(.*\)"/\1/p' smolvm.lock)"
    root=$PWD
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    export GIT_LFS_SKIP_SMUDGE=1
    git clone -q --filter=blob:none --no-checkout {{ smolvm_upstream }} "$work"
    cd "$work"
    git fetch -q {{ smolvm_fork }} request-filter-hook:hook v1.36.1-https-submodules:https
    rev=$(git rev-parse -q --verify "$base^{commit}" || git rev-parse --verify "origin/$base^{commit}")
    # named for its base and the hook commit, so a hook fix on the same base gets a tag of its own
    hook=hook$(git rev-parse --short=8 hook)
    case "$base" in
        v[0-9]*) tag="bento-$base-$hook" ;;
        *) tag="bento-${base//\//-}-$(git rev-parse --short=8 "$rev")-$hook" ;;
    esac
    git checkout -q --detach "$rev"
    if git ls-remote --exit-code --tags {{ smolvm_fork }} "refs/tags/$tag" >/dev/null; then
        echo "$tag already on the fork"
        git fetch -q {{ smolvm_fork }} "refs/tags/$tag:refs/tags/$tag"
    else
        if [ "$push" != push ]; then
            echo "$tag is not on the fork: run \`just smolvm-fork ${base} push\` to create and push it" >&2
            exit 1
        fi
        # the https .gitmodules, until upstream's uses https
        if grep -q 'git@github.com:' .gitmodules; then
            git cherry-pick https >/dev/null
        fi
        git cherry-pick "$(git merge-base origin/main hook)..hook" >/dev/null || {
            echo "error: the request-filter hook doesn't apply to $base; rebase request-filter-hook onto it first" >&2
            exit 1
        }
        git tag "$tag"
        GIT_LFS_SKIP_PUSH=1 git push -q {{ smolvm_fork }} "refs/tags/$tag"
        echo "pushed $tag"
    fi
    git checkout -q "$tag"
    version=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/smolvm-credentials/Cargo.toml | head -1)
    cd "$root"
    sed -i.bak -E "s#^(smolvm-(credentials|protocol)) = \{.*\}#\1 = { git = \"https://github.com/josmo/smolvm\", tag = \"$tag\", version = \"$version\" }#" crates/egress-front/Cargo.toml
    rm crates/egress-front/Cargo.toml.bak
    # the git CLI, so a url.insteadOf rewrite to ssh authenticates as git itself does
    CARGO_NET_GIT_FETCH_WITH_CLI=true cargo update -q -p smolvm-credentials -p smolvm-protocol
    # flake.nix pins the checkout's hash: write a dummy, build, and take the hash nix reports
    dummy=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    sed -i.bak -E "s#(\"smolvm-(credentials|protocol)-[0-9.]+\" = )\"sha256-[^\"]*\"#\1\"$dummy\"#" flake.nix
    rm flake.nix.bak
    hash=$(nix build --no-link .#default 2>&1 | sed -n 's/^ *got: *//p' | head -1 || true)
    if [ -z "$hash" ]; then
        echo "error: nix reported no hash; set the two smolvm-* outputHashes in flake.nix by hand" >&2
        exit 1
    fi
    sed -i.bak "s#$dummy#$hash#g" flake.nix
    rm flake.nix.bak
    echo "egress-front now uses josmo/smolvm $tag (crates $version); run just test"
