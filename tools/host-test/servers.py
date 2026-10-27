"""Test servers for the host test: a DNS stub (UDP+TCP), an HTTP server and a DoT-port listener."""
import http.server
import os
import socket
import socketserver
import ssl
import struct
import sys
import threading

ADDR = sys.argv[1]
WEBROOT = sys.argv[2]
DOT_LOG = sys.argv[3]
TLS_CERT = sys.argv[4]  # PEM with certificate and key
ADDR6 = sys.argv[5] if len(sys.argv) > 5 else None


def dns_answer(query: bytes) -> bytes:
    # Echo the question and answer A with ADDR and AAAA with ADDR6.
    qid, flags, qdcount = struct.unpack("!HHH", query[:6])
    pos = 12
    while query[pos] != 0:
        pos += query[pos] + 1
    question = query[12:pos + 5]
    qtype = struct.unpack("!H", query[pos + 1:pos + 3])[0]
    answer = b""
    if qtype == 1:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ADDR)
    elif qtype == 28 and ADDR6:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, ADDR6)
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1 if answer else 0, 0, 0)
    return header + question + answer


def udp_dns():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ADDR, 53))
    while True:
        data, peer = sock.recvfrom(4096)
        sock.sendto(dns_answer(data), peer)


class TcpDns(socketserver.BaseRequestHandler):
    def handle(self):
        length = struct.unpack("!H", self.request.recv(2))[0]
        query = b""
        while len(query) < length:
            query += self.request.recv(length - len(query))
        reply = dns_answer(query)
        self.request.sendall(struct.pack("!H", len(reply)) + reply)


class CountingSink(socketserver.BaseRequestHandler):
    """Reads until the client closes its side, then answers with the byte count."""

    def handle(self):
        total = 0
        while data := self.request.recv(1 << 16):
            total += len(data)
        self.request.sendall(str(total).encode())


BANNER = os.urandom(256 * 1024)


class Banner(socketserver.BaseRequestHandler):
    """Speaks first, like SSH or SMTP servers: sends BANNER as soon as it accepts, then closes."""

    def handle(self):
        self.request.sendall(BANNER)


class DotListener(socketserver.BaseRequestHandler):
    def handle(self):
        with open(DOT_LOG, "a") as f:
            f.write("connection\n")


# socketserver listens with a backlog of 5 by default; the client opens 40 connections
# at once, and accept-queue overflows then cost SYN-ACK retransmissions of seconds.
BACKLOG = 512


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = BACKLOG


class HttpServer(http.server.ThreadingHTTPServer):
    request_queue_size = BACKLOG


class HttpServer6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    request_queue_size = BACKLOG


threading.Thread(target=udp_dns, daemon=True).start()
threading.Thread(target=Server((ADDR, 53), TcpDns).serve_forever, daemon=True).start()
threading.Thread(target=Server((ADDR, 853), DotListener).serve_forever, daemon=True).start()
threading.Thread(target=Server((ADDR, 8081), CountingSink).serve_forever, daemon=True).start()
threading.Thread(target=Server((ADDR, 8082), Banner).serve_forever, daemon=True).start()

os.chdir(WEBROOT)
handler = http.server.SimpleHTTPRequestHandler
handler.log_message = lambda *args: None

# HTTPS on 8443, for TLS detection (SNI)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(TLS_CERT)
https = HttpServer((ADDR, 8443), handler)
https.socket = tls.wrap_socket(https.socket, server_side=True)
threading.Thread(target=https.serve_forever, daemon=True).start()

# Plain HTTP over IPv6 as well, to test the engine's IPv6 forwarding (same web root).
if ADDR6:
    threading.Thread(target=HttpServer6((ADDR6, 8080), handler).serve_forever, daemon=True).start()

HttpServer((ADDR, 8080), handler).serve_forever()
