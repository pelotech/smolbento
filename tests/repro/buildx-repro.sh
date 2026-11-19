#!/bin/sh
# Repro: `docker buildx build` inside a smolvm machine loses its BuildKit session as a build
# frontend starts, and the build then waits forever. Seen every time on Linux with smolvm 1.35.4;
# 1.35.3 passes. Uses only smolvm.
#
#   SMOLVM=/path/to/smolvm RUNS=3 sh buildx-repro.sh
set -u
SMOLVM=${SMOLVM:-smolvm}
RUNS=${RUNS:-3}
NAME=buildx-repro
vm() { "$SMOLVM" machine exec --name "$NAME" -u root -- sh -c "$1"; }

"$SMOLVM" --version
"$SMOLVM" machine delete -f --name "$NAME" >/dev/null 2>&1
"$SMOLVM" machine create --name "$NAME" --image docker:29-dind --net --net-backend virtio-net \
  -v /var/lib/docker --cpus 4 --mem 4096 -u root -- sleep infinity || exit 1
"$SMOLVM" machine start --name "$NAME" || exit 1

# dockerd in its own session, as a startup hook would start it.
vm 'setsid dockerd >/var/log/dockerd.log 2>&1 </dev/null &
for i in $(seq 1 60); do docker info >/dev/null 2>&1 && exit 0; sleep 1; done
echo "dockerd did not start"; tail -n 20 /var/log/dockerd.log; exit 1' || exit 1

# Two builds that each go through an external frontend: Docker's sandbox kit (what failed) and a
# plain Dockerfile with a syntax line.
vm 'mkdir -p /kit /df
printf "%s\n" "# syntax=docker/sandbox-kit:3" "schemaVersion: \"3\"" "kind: mixin" "version: \"1.0.0\"" \
  "provides: [repro]" "capabilities:" "  - type: com.docker.sandbox/lifecycle@1" \
  "    config: {files: [{path: /var/tmp/repro, content: ok}]}" > /kit/repro.yaml
printf "%s\n" "# syntax=docker/dockerfile:1" "FROM busybox" "RUN echo built > /built" > /df/Dockerfile'

hung=0
i=1
while [ "$i" -le "$RUNS" ]; do
  for case in kit dockerfile; do
    if [ "$case" = kit ]; then
      build="docker buildx build --no-cache --progress=plain -f /kit/repro.yaml --output type=oci,dest=/tmp/kit.tar /kit"
    else
      build="docker buildx build --no-cache --progress=plain /df"
    fi
    start=$(date +%s)
    vm "timeout 120 $build </dev/null >/tmp/build.log 2>&1"
    rc=$?
    secs=$(( $(date +%s) - start ))
    echo "run $i $case: exit $rc in ${secs}s"
    if [ "$rc" -eq 124 ]; then
      hung=$((hung + 1))
      vm 'echo "  last build output:"; tail -n 4 /tmp/build.log | sed "s/^/    /"'
    fi
  done
  i=$((i + 1))
done

echo "--- $hung of $((RUNS * 2)) builds hung (timeout 120s)"
echo "--- BuildKit session failures in dockerd.log (a few after each build are normal; a hung build"
echo "    has one within seconds of starting):"
vm 'grep -E "error reading preface|healthcheck failed fatally" /var/log/dockerd.log | cut -c1-160'
"$SMOLVM" machine delete -f --name "$NAME" >/dev/null 2>&1
