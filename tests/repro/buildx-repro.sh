#!/bin/sh
# Repro: `docker buildx build` inside a smolvm machine loses its BuildKit session as a build
# frontend starts, and the build then waits forever. Seen every time on Linux with smolvm 1.35.4;
# 1.35.3 passes. Uses only smolvm.
#
#   SMOLVM=/path/to/smolvm RUNS=3 sh buildx-repro.sh
#
# Replays, call for call, what smolbento's kit builder does on a fresh machine: Docker's
# docker.io/sbx/shell image, the builder's create flags, an allow-list reset, startup files copied
# in with `machine cp`, dockerd started from them, the build context copied in as a tar, and
# buildx run in the background while a loop watches its log. IMAGE swaps the image.
set -u
SMOLVM=${SMOLVM:-smolvm}
RUNS=${RUNS:-3}
IMAGE=${IMAGE:-}
[ -n "$IMAGE" ] || IMAGE=docker.io/sbx/shell:latest@sha256:89ed5d63def6bfb2373d408e3ab6ad55aa5c010f884a182a78299fcf85ea42d1
NAME=buildx-repro
host=$(mktemp -d)
trap 'rm -rf "$host"' EXIT
sm() { "$SMOLVM" --error-format json "$@"; }
vm() { sm machine exec --name "$NAME" -u root -- "$@"; }

"$SMOLVM" --version
sm machine delete -f --name "$NAME" >/dev/null 2>&1
echo "image: $IMAGE"
sm machine create --name "$NAME" --image "$IMAGE" --net --net-backend virtio-net \
  --deny-cidr 127.0.0.0/8 --deny-cidr ::1/128 -v /var/lib/docker -v /var/lib/containerd \
  --cpus 4 --mem 4096 -u root -- sleep infinity || exit 1
sm machine update --name "$NAME" --net --reset-allow-list || exit 1
sm machine start --name "$NAME" || exit 1

# First-start steps.
vm sh -c "grep -q ' host.docker.internal\$' /etc/hosts || printf '\n%s\n' '100.96.0.1 host.docker.internal' >> /etc/hosts"
vm sh -c 'cd /usr/local/bin 2>/dev/null || exit 0
for f in pbcopy clip.exe xdg-open wl-copy wl-paste xclip xsel; do
  if grep -qsx "# smolbento bridge shim" "$f"; then rm -f "$f"; fi
done'
vm sh -c 'mkdir -p /etc/smolbento /etc/smolbento/startup.d'
cat >"$host/hook" <<'EOF'
pgrep -x dockerd >/dev/null || { rm -f /var/run/docker.pid; exec dockerd >/var/log/dockerd.log 2>&1; }
EOF
cat >"$host/startup" <<'EOF'
#!/bin/sh
cd /
d=nohup; command -v setsid >/dev/null 2>&1 && d=setsid
$d sh -c 'if { sh /etc/smolbento/startup.d/01-docker.sh; }; then :; else echo "hook failed (exit $?)"; fi' &
echo "ok $0 hook 1"
EOF
sm machine cp "$host/hook" "$NAME:/etc/smolbento/startup.d/01-docker.sh" || exit 1
sm machine cp "$host/startup" "$NAME:/etc/smolbento/startup" || exit 1
vm sh -c 'chmod 644 /etc/smolbento/startup.d/01-docker.sh && chmod 755 /etc/smolbento/startup'
vm sh -c '[ -x /etc/smolbento/startup ] || exit 0; exec /etc/smolbento/startup'
# smolbento then runs the docker hook once more itself, straight away, before polling docker.
vm sh -c 'cd /
d=nohup; command -v setsid >/dev/null 2>&1 && d=setsid
$d sh -c "if { sh /etc/smolbento/startup.d/01-docker.sh; }; then :; else echo hook failed; fi" &
echo "ok $0 hook 1"'
ok=
for i in $(seq 1 60); do vm docker info >/dev/null 2>&1 && { ok=1; break; }; sleep 1; done
[ -n "$ok" ] || { echo "dockerd did not start"; vm tail -n 20 /var/log/dockerd.log; exit 1; }

# The kit smolbento's e2e test stalls on: a `build:` stanza, so a nested Dockerfile build.
mkdir -p "$host/ctx"
cat >"$host/ctx/built.yaml" <<'EOF'
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
tar -cf "$host/ctx.tar" -C "$host/ctx" .

# smolbento's watch loop: buildx in the background, its log polled; stop after SECS of silence.
watch='log=$1; secs=$2; shift 2
"$@" </dev/null >"$log" 2>&1 &
pid=$!; last=-1; idle=0
while kill -0 $pid 2>/dev/null; do
  sleep 1
  size=$(wc -c <"$log")
  if [ "$size" = "$last" ]; then idle=$((idle + 1)); else idle=0; last=$size; fi
  if [ $idle -ge $secs ]; then kill $pid; sleep 2; kill -9 $pid 2>/dev/null; tail -n 4 "$log"; exit 124; fi
done
wait $pid'

hung=0
i=1
while [ "$i" -le "$RUNS" ]; do
  d=/build/repro-$i
  vm mkdir -p "$d/ctx"
  sm machine cp "$host/ctx.tar" "$NAME:$d/ctx.tar" || exit 1
  vm tar -xf "$d/ctx.tar" -C "$d/ctx"
  start=$(date +%s)
  vm sh -c "$watch" watch "$d/buildx.log" 120 docker buildx build -f "$d/ctx/built.yaml" \
    --output "type=oci,dest=$d/kit.tar" --progress=plain "$d/ctx"
  rc=$?
  echo "run $i: exit $rc in $(( $(date +%s) - start ))s"
  [ "$rc" -eq 124 ] && hung=$((hung + 1))
  vm rm -rf "$d"
  i=$((i + 1))
done

echo "--- $hung of $RUNS builds hung (120s without output)"
echo "--- BuildKit session failures in dockerd.log (a few after each build are normal; a hung build"
echo "    has one within seconds of starting):"
vm sh -c 'grep -E "error reading preface|healthcheck failed fatally" /var/log/dockerd.log | cut -c1-160'
sm machine delete -f --name "$NAME" >/dev/null 2>&1
