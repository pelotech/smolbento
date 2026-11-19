#!/bin/sh
# Hunt (temporary): let smolbento make and start its kit builder, stop smolbento once its build
# stalls, then build the same kit in that builder with plain smolvm calls. Tells a builder machine
# that smolbento leaves broken from a build call of smolbento's that breaks it.
#
#   BENTO=target/debug/smolbento SMOLVM_HOME=/tmp/sbt-e2e-1001 sh bento-builder.sh
set -u
BENTO=${BENTO:-target/debug/smolbento}
SMOLVM_HOME=${SMOLVM_HOME:?}
w=$(mktemp -d)
export SMOLBENTO_CONFIG_DIR="$w/config" SMOLBENTO_CACHE_DIR="$w/cache" SMOLBENTO_DATA_DIR="$w/data"
export SMOLBENTO_DOCKER=false SMOLBENTO_SMOLVM_HOME="$SMOLVM_HOME"
vm() { "$BENTO" smolvm machine exec --name sbx-_builder -u root -- sh -c "$1" </dev/null; }

"$BENTO" policy init allow-all >/dev/null || exit 1
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

echo "=== smolbento create (stopped after 210s: its build stalls at 180s)"
start=$(date +%s)
timeout 210 "$BENTO" create --kit "$w/built" --name hunt shell "$w/ws" </dev/null 2>&1 | tail -n 5
echo "smolbento create: exit $? after $(( $(date +%s) - start ))s"
sleep 5
"$BENTO" smolvm machine status -n sbx-_builder --json </dev/null | cut -c1-200

echo "=== the same build in smolbento's builder, by hand"
vm 'pkill -f "buildx build"; mkdir -p /hunt'
vm 'printf "%s\n" "# syntax=docker/sandbox-kit:3" "schemaVersion: \"3\"" "kind: mixin" "version: \"1.0.0\"" \
  "provides: [e2e-built]" "build: |" "  FROM busybox:1.37 AS build" \
  "  RUN mkdir -p /out/opt/e2e-built && echo \"built in the builder\" > /out/opt/e2e-built/hello" \
  "  FROM scratch" "  COPY --from=build /out/ /" > /hunt/built.yaml'
for i in 1 2 3; do
  start=$(date +%s)
  vm "timeout 120 docker buildx build --no-cache --progress=plain -f /hunt/built.yaml \
    --output type=oci,dest=/hunt/kit.tar /hunt </dev/null >/hunt/build.log 2>&1"
  rc=$?
  echo "by hand $i: exit $rc in $(( $(date +%s) - start ))s"
  [ "$rc" -eq 0 ] || vm 'tail -n 4 /hunt/build.log'
done
echo "=== dockerd session failures"
vm 'grep -E "error reading preface|healthcheck failed fatally" /var/log/dockerd.log | cut -c1-160 | tail -n 12'
