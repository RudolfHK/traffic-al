"""A minimal aioquic HTTP/3 client for the host test: one GET /small, writing the TLS keys
to the key log so the capture's QUIC can be decrypted. Prints the response body.

It binds its own IPv4 datagram socket (aioquic's connect() forces IPv6, which the capture
namespace may not have), then drives the connection with QuicConnectionProtocol.

Usage: quic_client.py <server> <keylog>
"""
import asyncio
import ssl
import sys

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

SERVER = sys.argv[1]
KEYLOG = sys.argv[2]


class Http3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self.done = asyncio.Event()
        self.body = b""

    def get(self, path):
        stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(stream_id, [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"quic.example.test"), (b":path", path.encode()),
        ], end_stream=True)
        self.transmit()

    def quic_event_received(self, event):
        for e in self._http.handle_event(event):
            if isinstance(e, DataReceived):
                self.body += e.data
                if e.stream_ended:
                    self.done.set()


async def main():
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], server_name="quic.example.test")
    config.verify_mode = ssl.CERT_NONE
    config.secrets_log_file = open(KEYLOG, "a")

    loop = asyncio.get_event_loop()
    quic = QuicConnection(configuration=config)
    _, client = await loop.create_datagram_endpoint(lambda: Http3Client(quic), local_addr=("0.0.0.0", 0))
    try:
        client.connect((SERVER, 4433))
        await client.wait_connected()
        client.get("/small")
        await asyncio.wait_for(client.done.wait(), timeout=10)
        sys.stdout.write(client.body.decode(errors="replace"))
    finally:
        client.close()


asyncio.run(main())
