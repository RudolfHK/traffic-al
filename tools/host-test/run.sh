#!/usr/bin/env bash
# End-to-end test of the native capture engine on a Linux host, using a real TUN
# device and two network namespaces (app side and server side). Needs root
# (CAP_NET_ADMIN), gcc, iproute2 and python3 (scapy optional, for a pcap dump).
#
#   sudo tools/host-test/run.sh
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
CPP="$HERE/../../app/src/main/cpp"
WORK=${WORK:-$(mktemp -d)}
CLI=talcli
SRV=talsrv

cleanup() {
  [[ -n "${CAP_PID:-}" ]] && kill "$CAP_PID" 2>/dev/null || true
  [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null || true
  ip netns del "$CLI" 2>/dev/null || true
  ip netns del "$SRV" 2>/dev/null || true
}
trap cleanup EXIT

echo "== build ($WORK)"
CFLAGS=(-O2 -D_LITTLE_ENDIAN -I"$CPP" -I"$CPP/zdtun")
# zdtun is third-party code: build it without warnings, ours with -Werror.
gcc "${CFLAGS[@]}" -w -c "$CPP/zdtun/zdtun.c" -o "$WORK/zdtun.o"
gcc "${CFLAGS[@]}" -w -c "$CPP/zdtun/utils.c" -o "$WORK/zdtun_utils.o"
gcc "${CFLAGS[@]}" -Wall -Wextra -Werror -Wno-unused-parameter \
  "$CPP/capture_engine.c" "$HERE/host_capture.c" "$WORK/zdtun.o" "$WORK/zdtun_utils.o" \
  -o "$WORK/host_capture" -lpthread

echo "== network"
ip netns add "$CLI"
ip netns add "$SRV"
ip link add vcli type veth peer name vsrv
ip link set vcli netns "$CLI"
ip link set vsrv netns "$SRV"
ip -n "$SRV" addr add 10.88.0.2/24 dev vsrv
ip -n "$CLI" addr add 10.88.0.1/24 dev vcli
for ns in "$CLI" "$SRV"; do ip -n "$ns" link set lo up; done
ip -n "$SRV" link set vsrv up
ip -n "$CLI" link set vcli up

mkdir -p "$WORK/www"
head -c 50M /dev/urandom > "$WORK/www/blob"
head -c 256K /dev/urandom > "$WORK/www/small"
: > "$WORK/dot.log" # the port-853 listener logs every connection it accepts here
ip netns exec "$SRV" python3 "$HERE/servers.py" 10.88.0.2 "$WORK/www" "$WORK/dot.log" &
SRV_PID=$!

ip netns exec "$CLI" "$WORK/host_capture" tal0 10000 10.77.0.2 10.88.0.2 "$WORK/batches.bin" > "$WORK/capture.log" 2>&1 &
CAP_PID=$!
for _ in $(seq 50); do grep -q ready "$WORK/capture.log" 2>/dev/null && break; sleep 0.1; done

# Like Android's VpnService: the TUN gets an address and the "apps" route through it,
# while sockets marked by protect_socket() bypass it.
ip -n "$CLI" addr add 10.77.0.1/24 dev tal0
ip -n "$CLI" link set tal0 mtu 10000 up
ip -n "$CLI" rule add fwmark 0x77 lookup main pref 100
ip -n "$CLI" rule add to 10.88.0.0/24 lookup 177 pref 200
ip -n "$CLI" route add default dev tal0 table 177
ip netns exec "$CLI" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.tal0.rp_filter=0
sleep 1

echo "== client"
EXPECTED=$(printf '{"blob": "%s", "small": "%s"}' \
  "$(sha256sum "$WORK/www/blob" | cut -d' ' -f1)" "$(sha256sum "$WORK/www/small" | cut -d' ' -f1)")
status=0
ip netns exec "$CLI" python3 "$HERE/client.py" "$EXPECTED" || status=$?

echo "== kernel counters"
ip -n "$CLI" -s link show tal0 | sed -n '/RX:/,+1p'
echo "app side:"
ip netns exec "$CLI" nstat -az TcpExtTCPOFODrop TcpExtTCPRcvQDrop TcpExtTCPZeroWindowDrop TcpExtTCPBacklogDrop | tail -n +2
echo "server side:"
ip netns exec "$SRV" nstat -az TcpExtListenOverflows TcpExtListenDrops | tail -n +2

echo "== stop"
kill -TERM "$CAP_PID"
wait "$CAP_PID" || status=$?
CAP_PID=
cat "$WORK/capture.log"
dot_connections=$(wc -l < "$WORK/dot.log")
echo "DoT listener connections: $dot_connections"
[[ "$dot_connections" -eq 0 ]] || status=1

echo "== capture"
python3 "$HERE/analyze.py" "$WORK/batches.bin" ${PCAP_OUT:+"$PCAP_OUT"}
exit $status
