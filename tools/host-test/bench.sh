#!/usr/bin/env bash
# Benchmark of the native capture engine on a Linux host, with a real TUN device (see
# run.sh for the functional test). Prints JSON: throughput, round trips, engine CPU and
# idle wake-ups. Needs root (CAP_NET_ADMIN), cmake + ninja + gcc, iproute2 and python3.
#
#   sudo tools/host-test/bench.sh [result.json]
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-$(mktemp -d)}
OUT=${1:-}
mkdir -p "$WORK"
source "$HERE/netns.sh"

cleanup() {
  [[ -n "${CAP_PID:-}" ]] && kill "$CAP_PID" 2>/dev/null || true
  [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null || true
  delete_namespaces
}
trap cleanup EXIT

echo "== build ($WORK)" >&2
cmake -S "$HERE" -B "$WORK/build" -G Ninja -DCMAKE_BUILD_TYPE=Release > "$WORK/cmake.log"
cmake --build "$WORK/build" > "$WORK/build.log" || { cat "$WORK/build.log"; exit 1; }

create_namespaces
ip netns exec "$SRV" python3 "$HERE/bench.py" server 10.88.0.2 &
SRV_PID=$!

# The batches go to /dev/null: on Android they go to the app (see the JVM benchmark).
ip netns exec "$CLI" "$WORK/build/host_capture" tal0 10000 10.77.0.2 10.88.0.2 /dev/null > "$WORK/capture.log" 2>&1 &
CAP_PID=$!
wait_for_engine "$WORK/capture.log"
route_through_tun
sleep 1

echo "== benchmark" >&2
ip netns exec "$CLI" python3 "$HERE/bench.py" client 10.88.0.2 "$CAP_PID" | tee "${OUT:-/dev/null}"
