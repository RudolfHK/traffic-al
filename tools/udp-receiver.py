#!/usr/bin/env python3
"""Receives the UDP live export of Traffic AL and writes it as one capture.

Both stream formats work: PCAP (the same as PCAPdroid's UDP exporter, so PCAPdroid's
udp_receiver.py works too) and PCAPNG with the app of each packet as its comment.
Show the traffic live in Wireshark:

    python3 udp-receiver.py -p 1234 | wireshark -k -i -

or save it:

    python3 udp-receiver.py -p 1234 -w capture.pcapng

Restart the receiver after switching the format in the app.
"""
import argparse
import socket
import struct
import sys

PCAP_HEADER = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000065000000")
PCAPNG_SECTION_HEADER = 0x0A0D0D0A
PCAPNG_ENHANCED_PACKET = 0x00000006
LINKTYPE_RAW = 101


def pcapng_header():
    """Section header + interface description, for a receiver that started late."""
    shb = struct.pack("<IIIHHqI", PCAPNG_SECTION_HEADER, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    idb = struct.pack("<IIHHII", 1, 20, LINKTYPE_RAW, 0, 65535, 20)
    return shb + idb


def kind(datagram):
    if len(datagram) == len(PCAP_HEADER) and datagram[:16] == PCAP_HEADER[:16]:
        return "header", PCAP_HEADER
    if len(datagram) >= 12:
        block_type = struct.unpack_from("<I", datagram)[0]
        if block_type == PCAPNG_SECTION_HEADER:
            return "header", None
        if block_type == PCAPNG_ENHANCED_PACKET:
            return "packet", pcapng_header()
    return "packet", PCAP_HEADER


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-p", "--port", type=int, default=1234, help="UDP port (default 1234)")
    parser.add_argument("-b", "--bind", default="0.0.0.0", help="address to listen on")
    parser.add_argument("-w", "--write", default="-", metavar="FILE", help="output file (default stdout)")
    parser.add_argument("--idle-exit", type=float, metavar="SECONDS",
                        help="exit when nothing arrived for this long after the first datagram")
    parser.add_argument("-v", "--verbose", action="store_true", help="report counts on stderr")
    args = parser.parse_args()

    out = sys.stdout.buffer if args.write == "-" else open(args.write, "wb")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind((args.bind, args.port))

    header_written = False
    packets = 0
    try:
        while True:
            if args.idle_exit and header_written:
                sock.settimeout(args.idle_exit)
            try:
                datagram = sock.recv(65535)
            except socket.timeout:
                break
            what, header = kind(datagram)
            if what == "header":
                if header_written:
                    continue  # the app started a new capture: keep one header
                header_written = True
            else:
                if not header_written:
                    out.write(header)
                    header_written = True
                packets += 1
            out.write(datagram)
            out.flush()
    except KeyboardInterrupt:
        pass
    finally:
        if args.verbose:
            sys.stderr.write(f"{packets} packets\n")
        if out is not sys.stdout.buffer:
            out.close()


if __name__ == "__main__":
    main()
