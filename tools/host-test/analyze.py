"""Decodes the engine's packet batches and checks what was captured."""
import json
import struct
import sys
from collections import Counter

HEADER = struct.Struct("<QiHBB")  # timestamp_us, uid, length, direction, flags (little-endian host)
data = open(sys.argv[1], "rb").read()
pos = 0
records = []
while pos < len(data):
    ts, uid, length, direction, flags = HEADER.unpack_from(data, pos)
    pos += HEADER.size
    records.append((ts, uid, direction, flags, data[pos:pos + length]))
    pos += length
assert pos == len(data), "trailing bytes in batch file"


def ipv4(pkt):
    proto = pkt[9]
    ihl = (pkt[0] & 0x0F) * 4
    src, dst = ".".join(map(str, pkt[12:16])), ".".join(map(str, pkt[16:20]))
    sport = dport = 0
    if proto in (6, 17):
        sport, dport = struct.unpack("!HH", pkt[ihl:ihl + 4])
    return proto, src, sport, dst, dport


stats = Counter()
for ts, uid, direction, flags, pkt in records:
    proto, src, sport, dst, dport = ipv4(pkt)
    stats["packets"] += 1
    stats["bytes_out" if direction == 1 else "bytes_in"] += len(pkt)
    if uid == 4242:
        stats["attributed"] += 1
    if flags & 1:
        stats[f"blocked:{dst}:{dport}"] += 1
    if direction == 0 and proto == 17 and sport == 53:
        stats["dns_replies_from_" + src] += 1
    if direction == 1 and proto == 6 and dport == 53:
        stats["dns_tcp_out"] += 1

timestamps = [r[0] for r in records]
stats["timestamps_monotonic"] = int(all(a <= b for a, b in zip(timestamps, timestamps[1:])))
print(json.dumps(stats, indent=2, sort_keys=True))

if len(sys.argv) > 2:
    from scapy.all import IP, wrpcap
    wrpcap(sys.argv[2], [IP(r[4]) for r in records])
