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


def dns_answer(query: bytes) -> bytes:
    # Echo the question and answer every A query with ADDR.
    qid, flags, qdcount = struct.unpack("!HHH", query[:6])
    pos = 12
    while query[pos] != 0:
        pos += query[pos] + 1
    question = query[12:pos + 5]
    qtype = struct.unpack("!H", query[pos + 1:pos + 3])[0]
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1 if qtype == 1 else 0, 0, 0)
    answer = b""
    if qtype == 1:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ADDR)
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


threading.Thread(target=udp_dns, daemon=True).start()
threading.Thread(target=Server((ADDR, 53), TcpDns).serve_forever, daemon=True).start()
threading.Thread(target=Server((ADDR, 853), DotListener).serve_forever, daemon=True).start()

os.chdir(WEBROOT)
handler = http.server.SimpleHTTPRequestHandler
handler.log_message = lambda *args: None

# HTTPS on 8443, for TLS detection (SNI)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(TLS_CERT)
https = HttpServer((ADDR, 8443), handler)
https.socket = tls.wrap_socket(https.socket, server_side=True)
threading.Thread(target=https.serve_forever, daemon=True).start()

HttpServer((ADDR, 8080), handler).serve_forever()
