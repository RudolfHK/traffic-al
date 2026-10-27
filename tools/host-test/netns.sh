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
  # A ULA IPv6 pair as well, to exercise the engine's IPv6 path (nodad: skip the ~1s
  # duplicate-address detection, this is a private link). Best effort: some kernels have
  # no IPv6, and the IPv6 leg is then skipped (HOST_IPV6 unset) instead of failing.
  if ip -n "$SRV" addr add fd00:88::2/64 dev vsrv nodad 2>/dev/null; then
    ip -n "$CLI" addr add fd00:88::1/64 dev vcli nodad
    export HOST_IPV6=1
  else
    echo "IPv6 unavailable in this kernel; skipping the IPv6 leg" >&2
    export HOST_IPV6=
  fi
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
  if [[ -n "${HOST_IPV6:-}" ]]; then
    # The same for IPv6: the engine's marked sockets reach the server directly, everything
    # else to the server goes through the TUN (::/0 default in table 177), like ::/0 on Android.
    ip -n "$CLI" addr add fd00:77::1/64 dev tal0 nodad
    ip -n "$CLI" -6 rule add fwmark 0x77 lookup main pref 100
    ip -n "$CLI" -6 rule add to fd00:88::/64 lookup 177 pref 200
    ip -n "$CLI" -6 route add default dev tal0 table 177
  fi
}
