"""A minimal aioquic HTTP/3 server for the host test: answers any request with a short
plaintext body so the in-app QUIC decryptor can be checked end to end."""
import asyncio
import sys

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated

ADDR = sys.argv[1]
CERT = sys.argv[2]  # PEM with certificate and key


class Http3Server(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic)
        if self._http is None:
            return
        for e in self._http.handle_event(event):
            if isinstance(e, HeadersReceived):
                path = next((v for k, v in e.headers if k == b":path"), b"/")
                self._http.send_headers(e.stream_id, [(b":status", b"200"), (b"content-type", b"text/plain")])
                self._http.send_data(e.stream_id, b"quic ok " + path + b"\n", end_stream=True)
                self.transmit()


async def main():
    config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    config.load_cert_chain(CERT, CERT)  # the PEM holds both the certificate and the key
    await serve(ADDR, 4433, configuration=config, create_protocol=Http3Server)
    await asyncio.Future()  # serve forever


asyncio.run(main())
