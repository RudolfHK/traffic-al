"""Phase 3 acceptance check: the flows tracked by FlowTracker must match tshark's
conversations on the exported PCAPNG, and nDPI must have classified the test traffic.

Usage: validate_flows.py <capture.pcapng> <flows.json>
"""
import json
import re
import subprocess
import sys
from collections import defaultdict

pcap, flows_file = sys.argv[1:3]
flows = json.load(open(flows_file))
failures = []

# --- tshark conversations --------------------------------------------------------
UNITS = {"bytes": 1, "kB": 10**3, "MB": 10**6, "GB": 10**9}
CONV = re.compile(
    r"^(\S+):(\d+)\s+<->\s+(\S+):(\d+)\s+"
    r"(\d+) ([\d,]+) (bytes|kB|MB|GB)\s+(\d+) ([\d,]+) (bytes|kB|MB|GB)\s+"
)
tshark = subprocess.run(
    ["tshark", "-r", pcap, "-q", "-z", "conv,tcp", "-z", "conv,udp"],
    capture_output=True, text=True, check=True,
).stdout

conversations = {}
proto = None
for line in tshark.splitlines():
    if line.startswith("TCP Conversations"):
        proto = 6
    elif line.startswith("UDP Conversations"):
        proto = 17
    elif (m := CONV.match(line)) and proto:
        a, pa, b, pb = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
        # "<-" is B to A, "->" is A to B
        to_a = (int(m.group(5)), int(m.group(6).replace(",", "")), m.group(7))
        to_b = (int(m.group(8)), int(m.group(9).replace(",", "")), m.group(10))
        conversations[(proto, a, pa, b, pb)] = (to_a, to_b)

# Several flows can share a 5-tuple (port reuse after close); tshark merges them.
ours = defaultdict(lambda: [0, 0, 0, 0])
for f in flows:
    if f["protocol"] not in (6, 17):
        continue
    key = (f["protocol"], f["local"], f["localPort"], f["remote"], f["remotePort"])
    totals = ours[key]
    totals[0] += f["packetsOut"]
    totals[1] += f["bytesOut"]
    totals[2] += f["packetsIn"]
    totals[3] += f["bytesIn"]


def same_bytes(exact, shown, unit):
    # tshark prints SI units without decimals
    return exact // UNITS[unit] == shown or round(exact / UNITS[unit]) == shown


matched = 0
for (proto, a, pa, b, pb), (to_a, to_b) in conversations.items():
    if (proto, a, pa, b, pb) in ours:
        out_pkts, out_bytes, in_pkts, in_bytes = ours.pop((proto, a, pa, b, pb))
        app_to_server, server_to_app = to_b, to_a
    elif (proto, b, pb, a, pa) in ours:
        out_pkts, out_bytes, in_pkts, in_bytes = ours.pop((proto, b, pb, a, pa))
        app_to_server, server_to_app = to_a, to_b
    else:
        failures.append(f"tshark conversation without flow: {a}:{pa} <-> {b}:{pb}")
        continue
    if (app_to_server[0], server_to_app[0]) != (out_pkts, in_pkts) or not (
        same_bytes(out_bytes, app_to_server[1], app_to_server[2])
        and same_bytes(in_bytes, server_to_app[1], server_to_app[2])
    ):
        failures.append(
            f"{a}:{pa} <-> {b}:{pb}: tshark out/in {app_to_server}/{server_to_app}, "
            f"flow {out_pkts} pkts {out_bytes} B / {in_pkts} pkts {in_bytes} B"
        )
    else:
        matched += 1
for key in ours:
    failures.append(f"flow without tshark conversation: {key}")

print(f"tshark conversations: {len(conversations)}, matching flows: {matched}")

# --- nDPI classification of the test traffic ------------------------------------
EXPECTED = [
    # (description, flow filter, check)
    ("DNS to the virtual DNS server", lambda f: f["remotePort"] == 53 and f["protocol"] == 17,
     lambda f: f["appProtocol"] == "DNS"),
    ("HTTP on port 8080", lambda f: f["remotePort"] == 8080 and f["packetsIn"] > 0,
     lambda f: (f["appProtocol"] or "").startswith("HTTP")),
    ("TLS with SNI", lambda f: f["remotePort"] == 8443,
     lambda f: (f["appProtocol"] or "").startswith("TLS") and f["sni"] == "tls.example.test"),
    ("QUIC with SNI", lambda f: f["remotePort"] == 4433,
     lambda f: (f["appProtocol"] or "").startswith("QUIC") and f["serverName"] == "quic.example.test"),
]
for description, select, check in EXPECTED:
    selected = [f for f in flows if select(f)]
    good = [f for f in selected if check(f)]
    print(f"{description}: {len(good)}/{len(selected)} flows ok"
          + (f", e.g. {selected[0]['appProtocol']!r} {selected[0]['sni'] or selected[0]['serverName']!r}"
             if selected else ""))
    if not selected or len(good) != len(selected):
        bad = [f for f in selected if not check(f)][:3]
        failures.append(f"{description}: {len(good)}/{len(selected)} ok, e.g. {bad}")

for failure in failures:
    print("FAIL", failure)
sys.exit(1 if failures else 0)
