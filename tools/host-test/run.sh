#!/usr/bin/env bash
# End-to-end test of the native capture engine on a Linux host, using a real TUN
# device and two network namespaces (app side and server side). Needs root
# (CAP_NET_ADMIN), cmake + ninja + gcc, iproute2, iptables and python3.
#
#   sudo tools/host-test/run.sh
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-$(mktemp -d)}
mkdir -p "$WORK"
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
cmake -S "$HERE" -B "$WORK/build" -G Ninja -DCMAKE_BUILD_TYPE=Release > "$WORK/cmake.log"
cmake --build "$WORK/build" > "$WORK/build.log" || { cat "$WORK/build.log"; exit 1; }
cp "$WORK/build/host_capture" "$WORK/host_capture"

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
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=tls.example.test" \
  -keyout "$WORK/tls.pem" -out "$WORK/tls.pem.crt" 2> /dev/null
cat "$WORK/tls.pem.crt" >> "$WORK/tls.pem"
ip netns exec "$SRV" python3 "$HERE/servers.py" 10.88.0.2 "$WORK/www" "$WORK/dot.log" "$WORK/tls.pem" &
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
# The app's kernel may drop segments the engine wrote to the TUN (e.g. receive queue
# full, TCPRcvQDrop). TCP recovers from that only if the engine retransmits, so drop a
# share of the server-to-app HTTP packets on purpose.
DROP_RATE=${DROP_RATE:-0.005}
ip netns exec "$CLI" iptables -A INPUT -i tal0 -p tcp --sport 8080 \
  -m statistic --mode random --probability "$DROP_RATE" -j DROP
sleep 1

echo "== client"
EXPECTED=$(printf '{"blob": "%s", "small": "%s"}' \
  "$(sha256sum "$WORK/www/blob" | cut -d' ' -f1)" "$(sha256sum "$WORK/www/small" | cut -d' ' -f1)")
status=0
FAILED_PORTS_FILE="$WORK/failed_ports" ip netns exec "$CLI" \
  python3 "$HERE/client.py" "$EXPECTED" "$WORK/www/small" || status=$?

echo "== kernel counters"
ip -n "$CLI" -s link show tal0 | sed -n '/RX:/,+1p'
ip netns exec "$CLI" iptables -L INPUT -v -n | awk '/statistic/ { print "injected drops: " $1 }'
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
python3 "$HERE/analyze.py" "$WORK/batches.bin" "$WORK/failed_ports" ${PCAP_OUT:+"$PCAP_OUT"}
exit $status
