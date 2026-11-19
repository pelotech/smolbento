#!/bin/sh
# Hunt (temporary): smolbento's create of a kit with a `build:` stanza, by hand, on a fresh kit
# builder. REGISTRY=1 first starts the local registry VM the e2e tests start (registry:2, one CPU,
# 512 MiB, a published port) and leaves it running through the create.
#
#   BENTO=target/debug/smolbento SMOLVM_HOME=/tmp/sbt-e2e-1001 REGISTRY=1 sh bento-builder.sh
set -u
BENTO=${BENTO:-target/debug/smolbento}
SMOLVM_HOME=${SMOLVM_HOME:?}
REGISTRY=${REGISTRY:-}
w=$(mktemp -d)
export SMOLBENTO_CONFIG_DIR="$w/config" SMOLBENTO_CACHE_DIR="$w/cache" SMOLBENTO_DATA_DIR="$w/data"
export SMOLBENTO_DOCKER=false SMOLBENTO_SMOLVM_HOME="$SMOLVM_HOME"
sm() { "$BENTO" smolvm "$@" </dev/null; }

sm machine delete -f -n sbx-_builder >/dev/null 2>&1
"$BENTO" policy init allow-all >/dev/null || exit 1
if [ -n "$REGISTRY" ]; then
  sm machine delete -f -n hunt-registry >/dev/null 2>&1
  sm machine run -d -n hunt-registry --image registry:2 --cpus 1 --mem 512 --net -p 45123:5000 || exit 1
  for i in $(seq 1 60); do curl -fsS http://127.0.0.1:45123/v2/ >/dev/null 2>&1 && break; sleep 1; done
  echo "registry: $(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:45123/v2/)"
fi
mkdir -p "$w/built" "$w/ws"
cat >"$w/built/built.yaml" <<'EOF'
# syntax=docker/sandbox-kit:3
schemaVersion: "3"
kind: mixin
version: "1.0.0"
provides: [e2e-built]
build: |
  FROM busybox:1.37 AS build
  RUN mkdir -p /out/opt/e2e-built && echo "built in the builder" > /out/opt/e2e-built/hello
  FROM scratch
  COPY --from=build /out/ /
EOF

start=$(date +%s)
timeout 420 "$BENTO" create --kit "$w/built" --name hunt shell "$w/ws" </dev/null >"$w/create.log" 2>&1
rc=$?
echo "smolbento create (registry: ${REGISTRY:-no}): exit $rc after $(( $(date +%s) - start ))s"
[ "$rc" -eq 0 ] || tail -n 6 "$w/create.log"
"$BENTO" rm -f hunt </dev/null >/dev/null 2>&1
[ -z "$REGISTRY" ] || sm machine delete -f -n hunt-registry >/dev/null 2>&1
sm machine delete -f -n sbx-_builder >/dev/null 2>&1
exit 0
