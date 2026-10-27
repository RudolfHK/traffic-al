"""App-side checks for the host test; runs in the namespace whose traffic is captured."""
import concurrent.futures
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import time

VIRTUAL_DNS = "10.77.0.2"
SERVER = "10.88.0.2"
PROTECT_MARK = 0x77
EXPECTED = json.loads(sys.argv[1])  # {"blob": sha256, "small": sha256}
RCVBUF = int(os.environ.get("SLOW_READER_RCVBUF", "0"))

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


def http_get(path, mark=None, slow=False, ports=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if mark is not None:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
    if slow and RCVBUF:
        # A tiny receive buffer makes the app's kernel drop segments (TCPRcvQDrop).
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF)
    s.settimeout(20)
    s.connect((SERVER, 8080))
    if ports is not None:
        ports.append(s.getsockname()[1])
    s.sendall(f"GET /{path} HTTP/1.0\r\nHost: {SERVER}\r\n\r\n".encode())
    chunks = []
    while True:
        # A slow reader lets the receive queue fill up, like a busy app.
        chunk = s.recv(4096 if slow else 1 << 16)
        if not chunk:
            break
        chunks.append(chunk)
        if slow:
            time.sleep(0.002)
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

for name, mark in (("download_through_tun", None), ("download_direct", PROTECT_MARK)):
    try:
        body, mbps = timed_download(mark)
        check(name, hashlib.sha256(body).hexdigest() == EXPECTED["blob"], f"{mbps:.0f} Mbit/s")
    except OSError as e:
        check(name, False, type(e).__name__)

def upload_then_half_close(size):
    """Sends size bytes and closes the sending side (FIN) at once; the server echoes the count.
    The engine must deliver everything before the FIN, also data it still has queued."""
    with socket.create_connection((SERVER, 8081), timeout=20) as s:
        s.sendall(os.urandom(size))
        s.shutdown(socket.SHUT_WR)
        return int(s.recv(32).decode())


def download_after_half_close():
    """Requests the blob and closes the sending side at once, like `nc`: the engine must
    keep the connection, and retransmit to the app, until the app has everything."""
    with socket.create_connection((SERVER, 8080), timeout=20) as s:
        s.sendall(f"GET /blob HTTP/1.0\r\nHost: {SERVER}\r\n\r\n".encode())
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while chunk := s.recv(1 << 16):
            chunks.append(chunk)
    data = b"".join(chunks)
    return data[data.index(b"\r\n\r\n") + 4:]


try:
    body = download_after_half_close()
    check("download_after_half_close", hashlib.sha256(body).hexdigest() == EXPECTED["blob"], f"{len(body)} bytes")
except (OSError, ValueError) as e:
    check("download_after_half_close", False, type(e).__name__)

try:
    received = upload_then_half_close(32 * 1024 * 1024)
    check("upload_half_close", received == 32 * 1024 * 1024, f"server received {received} bytes")
except (OSError, ValueError) as e:
    check("upload_half_close", False, type(e).__name__)

SMALL = open(sys.argv[2], "rb").read() if len(sys.argv) > 2 else None


def describe_mismatch(body):
    if SMALL is None:
        return "content mismatch"
    if len(body) != len(SMALL):
        return f"length {len(body)} != {len(SMALL)}"
    first = next(i for i, (a, b) in enumerate(zip(body, SMALL)) if a != b)
    return f"corrupt from byte {first}"


FAILED_PORTS = os.environ.get("FAILED_PORTS_FILE")


def small_download(i):
    ports = []
    try:
        body = http_get("small", slow=i % 2 == 1, ports=ports)
        digest = hashlib.sha256(body).hexdigest()
        result = digest if digest == EXPECTED["small"] else describe_mismatch(body)
    except OSError as e:
        result = type(e).__name__
    if result != EXPECTED["small"]:
        result += f" (port {ports[0] if ports else '?'})"
        if FAILED_PORTS and ports:
            with open(FAILED_PORTS, "a") as f:
                f.write(f"{ports[0]}\n")
    return result


rounds = int(os.environ.get("PARALLEL_ROUNDS", "1"))
with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
    hashes = list(pool.map(small_download, range(80 * rounds)))
bad = [h for h in hashes if h != EXPECTED["small"]]
check("parallel_downloads", not bad, f"{len(hashes)} requests, {len(bad)} failed {sorted(set(bad))}")

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

# TLS with SNI (nDPI and the Kotlin SNI parser must both see "tls.example.test")
try:
    tls = ssl.create_default_context()
    tls.check_hostname = False
    tls.verify_mode = ssl.CERT_NONE
    with socket.create_connection((SERVER, 8443), timeout=5) as raw, \
            tls.wrap_socket(raw, server_hostname="tls.example.test") as s:
        s.sendall(b"GET /small HTTP/1.0\r\nHost: tls.example.test\r\n\r\n")
        body = b""
        while chunk := s.recv(1 << 16):
            body += chunk
    ok = hashlib.sha256(body[body.index(b"\r\n\r\n") + 4:]).hexdigest() == EXPECTED["small"]
    check("tls_download", ok)
except OSError as e:
    check("tls_download", False, type(e).__name__)

# QUIC: the client Initial carries the SNI; no QUIC server is needed for detection.
try:
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection

    quic = QuicConnection(configuration=QuicConfiguration(
        is_client=True, alpn_protocols=["h3"], server_name="quic.example.test"))
    quic.connect((SERVER, 4433), now=time.time())
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        sent = 0
        for datagram, address in quic.datagrams_to_send(now=time.time()):
            s.sendto(datagram, address)
            sent += 1
    check("quic_initial", sent > 0, f"{sent} datagrams")
except ImportError:
    check("quic_initial", False, "aioquic is not installed (pip install aioquic)")

print(json.dumps(results, indent=2))
sys.exit(1 if failures else 0)
