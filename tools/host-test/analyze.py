"""Decodes the engine's packet batches and checks what was captured."""
import json
import struct
import sys
from collections import Counter

HEADER = struct.Struct("<QiHBB")  # timestamp_us, uid, length, direction, flags (little-endian host)
data = open(sys.argv[1], "rb").read()
pos = 0
records = []
detections = []
while pos < len(data):
    ts, uid, length, direction, flags = HEADER.unpack_from(data, pos)
    pos += HEADER.size
    if direction == 2:  # capture_flow_info_t: nDPI result of a connection
        detections.append((ts, uid, data[pos:pos + length]))
    else:
        records.append((ts, uid, direction, flags, data[pos:pos + length]))
    pos += length
assert pos == len(data), "trailing bytes in batch file"


def flow_info(info):
    ipver, proto, sport, dport = struct.unpack_from("<BBHH", info)
    src = ".".join(map(str, info[6:10]))
    dst = ".".join(map(str, info[22:26]))
    strings, p = [], 44
    for _ in range(3):
        n = info[p]
        strings.append(info[p + 1:p + 1 + n].decode())
        p += 1 + n
    return f"{proto:>2} {src}:{sport} -> {dst}:{dport} {strings[0]} [{strings[1]}] {strings[2]!r}"


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

stats["detections"] = len(detections)
timestamps = [r[0] for r in records]
stats["timestamps_monotonic"] = int(all(a <= b for a, b in zip(timestamps, timestamps[1:])))
print(json.dumps(stats, indent=2, sort_keys=True))
seen = set()
for ts, uid, info in detections:
    line = flow_info(info)
    summary = line.split(" ", 1)[1].split(":", 1)[0] + line.split("->", 1)[1].split(" ", 2)[2]
    if summary not in seen:  # one line per kind of detection
        seen.add(summary)
        print("nDPI:", line)

# Timeline of the connections whose download failed (local ports written by client.py).
try:
    failed_ports = {int(p) for p in open(sys.argv[2]).read().split()}
except (IndexError, FileNotFoundError):
    failed_ports = set()

TCP_FLAGS = "FSRPAU"
for port in sorted(failed_ports):
    print(f"--- failed connection, app port {port}")
    isn = ack_base = None
    for ts, uid, direction, flags, pkt in records:
        proto, src, sport, dst, dport = ipv4(pkt)
        if proto != 6 or port not in (sport, dport):
            continue
        ihl = (pkt[0] & 0x0F) * 4
        seq, ack, off, tcp_flags, win = struct.unpack("!IIBBH", pkt[ihl + 4:ihl + 16])
        payload = len(pkt) - ihl - (off >> 4) * 4
        names = "".join(n for i, n in enumerate(TCP_FLAGS) if tcp_flags & (1 << i))
        if direction == 0:  # engine -> app
            if isn is None:
                isn = seq
            print(f"{ts % 10**8:>10} engine->app seq={(seq - isn) % 2**32:>7} len={payload:>5} {names}")
        else:
            if ack_base is None and isn is not None:
                ack_base = isn
            rel_ack = (ack - ack_base) % 2**32 if ack_base is not None else ack
            print(f"{ts % 10**8:>10} app->engine ack={rel_ack:>7} win={win:>5} len={payload:>4} {names}")

if len(sys.argv) > 3:
    from scapy.all import IP, wrpcap
    wrpcap(sys.argv[3], [IP(r[4]) for r in records])
