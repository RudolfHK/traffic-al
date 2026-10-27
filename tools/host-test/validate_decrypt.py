#!/usr/bin/env python3
"""Phase 8: confirm that tshark decrypts the host test's HTTPS traffic (port 8443) using
only the TLS key log embedded in the PCAPNG as a Decryption Secrets Block (DSB) by
tools/host-test (via core's decryptCheck). No external key-log file is given to tshark,
so a decrypted request proves the DSB pipeline works end to end.

Usage: validate_decrypt.py <decrypted.pcapng>
"""
import subprocess
import sys

pcap = sys.argv[1]


def tshark(display_filter, *fields):
    cmd = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return [line for line in out.stdout.splitlines() if line.strip()]

# The decrypted request to /small on the TLS port. Plaintext HTTP is on 8080, so scoping
# to tcp.port==8443 means a match can only come from decryption with the embedded keys.
requests = tshark("tcp.port==8443 && http.request", "http.request.method", "http.request.uri")
print("decrypted HTTPS requests on port 8443:", requests)
if not any("GET" in r and "/small" in r for r in requests):
    handshakes = tshark("tcp.port==8443 && tls.handshake.type==1", "tls.handshake.type")
    hint = "the TLS handshake is not even in the capture" if not handshakes \
        else "the handshake is captured but was not decrypted (keys missing or unmatched)"
    sys.exit(f"tshark did not decrypt the HTTPS request on port 8443: {hint}")

print("OK: HTTPS on port 8443 decrypted from the embedded TLS key log")
