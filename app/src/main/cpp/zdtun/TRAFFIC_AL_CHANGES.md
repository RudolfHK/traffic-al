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
  engine calls it every 50 ms.
- The window computation no longer underflows when the app advertises less than what
  is in flight (upstream then ignored the app's window entirely). A zero window now stops
  reading from the server until the app reopens it; before, `recv()` was called with a
  length of 0, returned 0 and the connection was closed as if the server had finished,
  truncating the download (seen on CI as 107 KB of a 256 KB file followed by a FIN).
- A lost SYN+ACK is resent when the app repeats its SYN, and data or a FIN that the app
  retransmits because zdtun's ACK was lost is acknowledged again.

The host test (`tools/host-test/run.sh`) drops 0.5% of the server-to-app packets on
purpose to verify this; without the changes two drops are enough to stall a download.

## Performance check (docs/PERFORMANCE.md)

The engine benchmark (`tools/host-test/bench.sh`) found these, now changed:

- **Idle connections were reset after 60 s** (UDP: 30 s). Apps keep connections open
  without traffic for many minutes (push notifications, messengers), so they were cut
  every minute and reconnected. The idle timeouts are now those a NAT must at least
  allow: 2 h 4 min for TCP (RFC 5382), 4 min once a side has closed, 2 min for UDP
  (RFC 4787).
- **Only 128 sockets**: above that the least recently used connections were reset. A
  phone's apps keep hundreds open; the limit is now 512 (socket fds must stay below
  `FD_SETSIZE`, 1024). An idle connection releases its retransmission buffer.
- **Uploads that end with a half close lost data**: when the app sent its FIN while
  data was still queued for the server, the socket was shut down first, the queued sends
  failed with `EPIPE` and the connection was reset. The FIN now waits for the queue
  (and the FIN segment's own data, which was dropped). `run.sh` checks this.
- **A connection closed by both sides was dropped at once**, with its retransmission
  buffer, although the app may not have acknowledged the last 256 KB yet. Now it is
  closed when the app has acknowledged everything, including the FIN (found while
  reviewing the half-close path; rare, as a segment to the app must be lost at the very
  end).
- **Every packet cost time per open connection**: `zdtun_handle_fd()` iterated over all
  connections; it now looks the ready sockets up by fd. `on_socket_close` is called
  before the socket is closed (as documented), so the engine can keep an epoll set in
  sync with zdtun's fd sets instead of calling `select()`, which checks every socket.
