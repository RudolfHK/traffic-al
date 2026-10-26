"""App-side checks for the host test; runs in the namespace whose traffic is captured."""
import concurrent.futures
import hashlib
import json
import socket
import struct
import sys
import time

VIRTUAL_DNS = "10.77.0.2"
SERVER = "10.88.0.2"
PROTECT_MARK = 0x77
EXPECTED = json.loads(sys.argv[1])  # {"blob": sha256, "small": sha256}

results = {}
failures = []


def check(name, ok, detail=""):
    results[name] = {"ok": bool(ok), "detail": detail}
    if not ok:
        failures.append(name)


def dns_query(name, tcp=False):
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    if tcp:
        with socket.create_connection((VIRTUAL_DNS, 53), timeout=3) as s:
            s.sendall(struct.pack("!H", len(query)) + query)
            length = struct.unpack("!H", s.recv(2))[0]
            reply = b""
            while len(reply) < length:
                reply += s.recv(length - len(reply))
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(query, (VIRTUAL_DNS, 53))
            reply = s.recv(4096)
    return socket.inet_ntoa(reply[-4:])


def http_get(path, mark=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if mark is not None:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
    s.settimeout(20)
    s.connect((SERVER, 8080))
    s.sendall(f"GET /{path} HTTP/1.0\r\nHost: {SERVER}\r\n\r\n".encode())
    chunks = []
    while True:
        chunk = s.recv(1 << 16)
        if not chunk:
            break
        chunks.append(chunk)
    s.close()
    data = b"".join(chunks)
    return data[data.index(b"\r\n\r\n") + 4:]


def timed_download(mark=None):
    start = time.monotonic()
    body = http_get("blob", mark)
    elapsed = time.monotonic() - start
    return body, len(body) * 8 / elapsed / 1e6


check("dns_udp", dns_query("tracker.example.test") == SERVER)
check("dns_tcp", dns_query("cdn.example.test", tcp=True) == SERVER)

body, captured_mbps = timed_download()
check("download_through_tun", hashlib.sha256(body).hexdigest() == EXPECTED["blob"], f"{captured_mbps:.0f} Mbit/s")
body, direct_mbps = timed_download(PROTECT_MARK)
check("download_direct", hashlib.sha256(body).hexdigest() == EXPECTED["blob"], f"{direct_mbps:.0f} Mbit/s")

with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
    hashes = list(pool.map(lambda _: hashlib.sha256(http_get("small")).hexdigest(), range(80)))
check("parallel_downloads", all(h == EXPECTED["small"] for h in hashes), f"{len(hashes)} requests")

try:
    socket.create_connection((SERVER, 853), timeout=2).close()
    check("dot_blocked", False, "connected to port 853")
except OSError as e:
    check("dot_blocked", True, type(e).__name__)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(1)
    s.sendto(b"probe", (VIRTUAL_DNS, 5353))
    try:
        s.recv(100)
        check("virtual_dns_other_port_blocked", False, "got a reply")
    except socket.timeout:
        check("virtual_dns_other_port_blocked", True)

print(json.dumps(results, indent=2))
sys.exit(1 if failures else 0)
