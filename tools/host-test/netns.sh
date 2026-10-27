# Network setup shared by run.sh and bench.sh (sourced): an app namespace whose traffic
# goes through the engine's TUN device, and a server namespace, linked by a veth pair.
CLI=talcli
SRV=talsrv

create_namespaces() {
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
}

delete_namespaces() {
  ip netns del "$CLI" 2>/dev/null || true
  ip netns del "$SRV" 2>/dev/null || true
}

# Waits until the engine (started in $CLI, logging to $1) has opened the TUN device.
wait_for_engine() {
  for _ in $(seq 50); do grep -q ready "$1" 2>/dev/null && return; sleep 0.1; done
}

# Like Android's VpnService: the TUN gets an address and the "apps" route through it,
# while sockets marked by protect_socket() bypass it.
route_through_tun() {
  ip -n "$CLI" addr add 10.77.0.1/24 dev tal0
  ip -n "$CLI" link set tal0 mtu 10000 up
  ip -n "$CLI" rule add fwmark 0x77 lookup main pref 100
  ip -n "$CLI" rule add to 10.88.0.0/24 lookup 177 pref 200
  ip -n "$CLI" route add default dev tal0 table 177
  ip netns exec "$CLI" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.tal0.rp_filter=0
}
