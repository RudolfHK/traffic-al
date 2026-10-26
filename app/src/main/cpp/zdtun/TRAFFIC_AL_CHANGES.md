# Local changes to zdtun

This directory is a copy of [zdtun](https://github.com/emanuele-f/zdtun) by Emanuele
Faranda at commit `80b7941d4e685d8354346820878eaec0e35b6b1e`, licensed under the GNU
Lesser General Public License v3.0 (see `COPYING`). It was modified in 2026 for
Traffic AL; every change in `zdtun.c`/`zdtun.h` is marked with "Traffic AL". To see the
full diff, compare with the upstream commit:

    git diff a023c1a -- app/src/main/cpp/zdtun

## Why

zdtun terminates the apps' TCP connections and relays them over normal sockets.
Upstream never retransmits data it has written to the app, because a TUN interface
does not lose packets by itself. The app's kernel may still drop segments that are
inside the advertised window, e.g. when its receive memory is exhausted
(`TcpExtTCPRcvQDrop`). With normal TCP the sender would retransmit; with zdtun the
connection stalls forever. CI on a fast runner hit this with 16 of 80 parallel downloads.

## What

- Data sent to the app is kept until the app acknowledges it (at most 256 KB per
  connection, which also caps the data in flight).
- Three duplicate ACKs trigger a fast retransmission, partial ACKs during recovery
  resend the next segment (NewReno). `zdtun_tcp_retransmit_timeouts()` resends all
  unacknowledged data and the FIN after 200 ms, with exponential backoff; the capture
  engine calls it on every loop iteration.
- The window computation no longer underflows when the app advertises less than what
  is in flight.
- A lost SYN+ACK is resent when the app repeats its SYN, and data or a FIN that the app
  retransmits because zdtun's ACK was lost is acknowledged again.

The host test (`tools/host-test/run.sh`) drops 0.5% of the server-to-app packets on
purpose to verify this; without the changes two drops are enough to stall a download.
