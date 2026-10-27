"""Benchmark of the capture engine, see bench.sh.

  bench.py server <address>                 in the server namespace
  bench.py client <server> <engine-pid>     in the app namespace; prints JSON

The client compares connections through the TUN interface (captured by the engine) with
connections that bypass it (SO_MARK, like sockets protected on Android).
"""
import json
import os
import socket
import statistics
import sys
import threading
import time

PORT = 9001
PROTECT_MARK = 0x77
CHUNK = 1 << 20
MB = 1024 * 1024
TICKS = os.sysconf("SC_CLK_TCK")


# ---------------------------------------------------------------- server

def serve(conn):
    with conn:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        command = conn.recv(9)
        if not command:
            return
        kind, size = command[:1], int.from_bytes(command[1:9].ljust(8, b"\0"), "big")
        if kind == b"D":  # download: send size bytes
            block = os.urandom(CHUNK)
            left = size
            while left > 0:
                left -= conn.send(memoryview(block)[:min(left, CHUNK)])
        elif kind == b"U":  # upload: read size bytes, then report the count
            buf = bytearray(CHUNK)
            total = 0
            while total < size and (n := conn.recv_into(buf, min(CHUNK, size - total))):
                total += n
            conn.sendall(total.to_bytes(8, "big"))
        elif kind == b"E":  # echo single bytes until EOF
            while data := conn.recv(64):
                conn.sendall(data)


def server(address):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, PORT))
    listener.listen(1024)
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


# ---------------------------------------------------------------- client

class Engine:
    """CPU time and context switches of the engine process."""

    def __init__(self, pid):
        self.pid = pid

    def cpu_seconds(self):
        with open(f"/proc/{self.pid}/stat") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / TICKS  # utime + stime

    def switches(self):
        total = 0
        for task in os.listdir(f"/proc/{self.pid}/task"):
            with open(f"/proc/{self.pid}/task/{task}/status") as f:
                for line in f:
                    if line.startswith(("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches")):
                        total += int(line.split()[1])
        return total


def connect(server, direct, command=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if direct:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, PROTECT_MARK)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(30)
    s.connect((server, PORT))
    if command:
        s.sendall(command)
    return s


def download(server, direct, size):
    start = time.monotonic()
    with connect(server, direct, b"D" + size.to_bytes(8, "big")) as s:
        buf = bytearray(CHUNK)
        total = 0
        while n := s.recv_into(buf):
            total += n
    elapsed = time.monotonic() - start
    assert total == size, f"downloaded {total} of {size} bytes"
    return size * 8 / elapsed / 1e6


def upload(server, direct, size):
    block = os.urandom(CHUNK)
    start = time.monotonic()
    with connect(server, direct, b"U" + size.to_bytes(8, "big")) as s:
        left = size
        while left > 0:
            left -= s.send(memoryview(block)[:min(left, CHUNK)])
        received = int.from_bytes(s.recv(8), "big")
    elapsed = time.monotonic() - start
    assert received == size, f"server received {received} of {size} bytes"
    return size * 8 / elapsed / 1e6


def round_trips(server, direct, count):
    """Round-trip times of one-byte request/response exchanges, in milliseconds."""
    times = []
    with connect(server, direct, b"E" + bytes(8)) as s:
        for _ in range(count):
            start = time.perf_counter()
            s.sendall(b"x")
            if s.recv(1) != b"x":
                raise OSError("echo failed")
            times.append((time.perf_counter() - start) * 1000)
    return times


def summary(times):
    ordered = sorted(times)
    return {
        "median_ms": round(statistics.median(ordered), 3),
        "p99_ms": round(ordered[int(len(ordered) * 0.99) - 1], 3),
        "max_ms": round(ordered[-1], 3),
    }


def echo(s):
    s.sendall(b"x")
    return s.recv(1) == b"x"


def alive(s):
    try:
        return echo(s)
    except OSError:
        return False


def connection_rate(server, count):
    start = time.monotonic()
    for _ in range(count):
        with connect(server, False, b"E" + bytes(8)) as s:
            s.sendall(b"x")
            s.recv(1)
    return count / (time.monotonic() - start)


def client(server, pid):
    engine = Engine(pid)
    size = int(os.environ.get("BENCH_MB", "1024")) * MB
    results = {}

    # Apps keep connections open for minutes without traffic (e.g. push notifications).
    idle = connect(server, False, b"E" + bytes(8))
    idle_since = time.monotonic()
    echo(idle)

    def measure(name, fn):
        cpu = engine.cpu_seconds()
        start = time.monotonic()
        value = fn()
        results[name] = value
        results[name + "_engine_cpu_share"] = round((engine.cpu_seconds() - cpu) / (time.monotonic() - start), 2)
        return value

    for direct in (True, False):
        path = "direct" if direct else "tun"
        download(server, direct, 64 * MB)  # warm up
        measure(f"download_{path}_mbps", lambda: round(download(server, direct, size)))
        measure(f"upload_{path}_mbps", lambda: round(upload(server, direct, size)))
        results[f"rtt_{path}"] = summary(round_trips(server, direct, 2000))

    # Round trips through the engine while it forwards a bulk download.
    stop = threading.Event()

    def load():
        while not stop.is_set():
            download(server, False, 256 * MB)

    loader = threading.Thread(target=load)
    loader.start()
    time.sleep(0.5)
    results["rtt_tun_under_load"] = summary(round_trips(server, False, 2000))
    stop.set()
    loader.join()

    results["connections_per_s"] = round(measure("connections", lambda: connection_rate(server, 2000)))
    del results["connections"]
    results["connections_per_s_engine_cpu_share"] = results.pop("connections_engine_cpu_share")

    # Many open connections, like the apps of a phone: do they all work, and what do they
    # cost the others?
    count = int(os.environ.get("BENCH_CONNECTIONS", "300"))
    opened = []
    try:
        for _ in range(count):
            opened.append(connect(server, False, b"E" + bytes(8)))
            echo(opened[-1])
    except OSError as e:
        results["open_connections_error"] = f"{type(e).__name__} after {len(opened)}"
    measure(f"download_tun_with_{count}_open_mbps", lambda: round(download(server, False, size)))
    results[f"open_connections_alive"] = f"{sum(alive(s) for s in opened)}/{count}"
    for s in opened:
        s.close()

    # The connection opened at the start, after more than a minute without traffic.
    time.sleep(max(0.0, 75 - (time.monotonic() - idle_since)))
    results["idle_connection_alive_after_s"] = round(time.monotonic() - idle_since) if alive(idle) else None
    idle.close()

    time.sleep(1)  # let the engine finish closing connections
    switches = engine.switches()
    cpu = engine.cpu_seconds()
    idle_seconds = 5
    time.sleep(idle_seconds)
    results["idle_wakeups_per_s"] = round((engine.switches() - switches) / idle_seconds, 1)
    results["idle_engine_cpu_share"] = round((engine.cpu_seconds() - cpu) / idle_seconds, 3)

    results["engine_cpu_seconds_per_gb_download"] = None  # filled in below
    gb_cpu = engine.cpu_seconds()
    download(server, False, size)
    results["engine_cpu_seconds_per_gb_download"] = round((engine.cpu_seconds() - gb_cpu) / (size / (1024 * MB)), 2)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    if sys.argv[1] == "server":
        server(sys.argv[2])
    else:
        client(sys.argv[2], int(sys.argv[3]))
