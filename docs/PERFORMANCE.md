# Performance

The check asked for in *"Check the performance of the app if it's working good"*: the
budgets and the reasoning are in [PROMPT.md](PROMPT.md#performance-check-improved). This
page has the results, what they found and what was changed.

**Verdict.** Forwarding and processing are fast enough. A single core handles more than a
phone's network can deliver. But the check found five problems that made the app work
worse than it should, all fixed:

1. Connections without traffic for 60 s were **reset** (push notifications, messengers).
2. Above 128 open connections, the oldest ones were **reset**.
3. Uploads that end with a half close **lost data** and were reset.
4. Every packet took longer the more connections were open (300 open: −30%).
5. The capture thread, which also forwards all traffic, built the UI's connection list
   on every batch and held its lock while the dashboard was computed. The packet buffer
   ignored the heap limit: 64 MB of packets on a device that grants 16 MB.

## Where and how

| Level | Tool | What it covers |
| --- | --- | --- |
| Native engine | `sudo tools/host-test/bench.sh` | The C engine (zdtun, nDPI, batches) on a real Linux TUN device in network namespaces: throughput, round trips, CPU, idle wake-ups, many and idle connections |
| Kotlin | `./gradlew -p core benchmark --args="<assets>"` | The capture thread's batch processing, connection list, search, dashboard, IP lookups, encrypted recording, on synthetic traffic (`SyntheticTraffic`: DNS, TLS with SNI, downloads, nDPI results) |
| App on ART | `PerformanceTest` (instrumented) | The capture pipeline of the app on Android 10 (emulator, 16 MB heap) with the connection list on screen |
| Whole app | `tools/emulator/bench.py <apk>` | Download through the real VPN vs. without, start time, CPU, memory, frame drops |

CI runs all four and uploads the numbers (`performance-host`, `device-test-reports`). It
fails if connections are reset, the app dies during the capture, or the pipeline on ART
handles fewer than 50,000 packets/s. Throughput on shared runners varies by ±20%, so
throughput itself isn't a CI gate.

The dev machine and the CI runners are x86 servers. A phone core (the P30 Pro's
Cortex-A76) is roughly 2–3 times slower for this work.

## Native engine (host, one core)

| | Before | After | Budget |
| --- | --- | --- | --- |
| Download through the engine | 2,165–2,835 Mbit/s | 2,686 Mbit/s | ≥ 1,000 |
| Upload through the engine | 1,652–1,747 Mbit/s | 1,802 Mbit/s | ≥ 1,000 |
| Same, bypassing the engine | 7,500–8,500 Mbit/s | | |
| Round trip, idle (median / p99) | 0.11 / 0.24 ms (direct 0.06 / 0.16) | 0.11 / 0.25 ms | +0.5 ms |
| Round trip during a download (median / p99 / max) | 0.16 / 0.59 / 5.6 ms | 0.15 / 0.56 / 3.2 ms | p99 < 20 ms |
| New connections (sequential) | 2,193/s | 2,224/s | |
| 300 open connections: still working | **109/300** | 300/300 | all |
| Download with 300 connections open | 1,534 Mbit/s (109 open) | 2,323 Mbit/s | ≥ 1,000 |
| Connection idle for 75 s | **reset** | works | works |
| Upload ending with a half close (`run.sh`) | **reset, data lost** | complete | complete |
| Wake-ups with no traffic | 4/s | 4/s | ≤ 5/s |
| Engine CPU per GB downloaded | 3.7 s | 3.9 s | |

The engine's throughput is bounded by one core: 3.9 CPU-seconds per GB means about
2 Gbit/s per x86 core, so several hundred Mbit/s on the phone's core before the Kotlin
side (below) takes its share.

What changed (details in
[TRAFFIC_AL_CHANGES.md](../app/src/main/cpp/zdtun/TRAFFIC_AL_CHANGES.md)):
- Idle timeouts as a NAT must at least allow: TCP 2 h 4 min (RFC 5382), 4 min after a
  close, UDP 2 min (RFC 4787). Before: TCP 60 s, UDP 30 s.
- Up to 512 sockets instead of 128. An idle connection frees its retransmission buffer.
- The app's FIN waits until the data queued for the server is sent. A connection both
  sides have closed is kept until the app has acknowledged everything, so lost segments
  can still be resent (before, up to 256 KB in flight were dropped with it).
- The engine waits with `epoll` instead of `select()`, and zdtun finds the ready sockets
  by fd instead of visiting every connection. The retransmission timers are checked every
  50 ms instead of after every packet. Before, `select()` alone made 300 open connections
  cost 64% of the throughput (839 Mbit/s with only the other fixes).

## Kotlin (JVM)

162,000 packets of 3,000 connections (134 MB), median of several runs:

| | Before | After | Budget |
| --- | --- | --- | --- |
| Capture thread: decode, flows, timeline, buffer | 520,000 packets/s (3.4 Gbit/s) | 430,000–535,000 packets/s | ≥ 200,000 |
| Connection list, 2,000 connections with destinations | 1.6–6 ms, **on the capture thread for every batch** | 2–3 ms, on another thread, at most twice a second | ≤ 50 ms |
| Search ("google") over 2,000 connections | **30.7 ms** | 3.5–5.5 ms | ≤ 20 ms |
| Dashboard | 4–15 ms, **all of it holding the capture lock** | 4 ms, 0.6 ms holding the lock | ≤ 20 ms |
| IP lookups | 3.7–13 million/s | | |
| Encrypted recording | 588 MB/s | 573–649 MB/s | ≥ 100 MB/s |
| Heap per buffered packet | 116 B for a 54 B packet, 1,503 B for 1,440 B | | |

What changed:
- **The capture thread does no UI work.** Before, while a screen was open, it rebuilt the
  connection list for every batch (up to 25 per second at full speed): 2,000 objects
  with IP lookups, while the packets waited. Now it only signals that the list changed;
  the list is rebuilt on a background thread at most every 500 ms.
- The dashboard, the connection detail and the history saves hold the capture's lock
  only to copy what they need (0.6 ms instead of the whole computation). Saving the history
  every 10 s copies the connections updated since the last save instead of all 10,000.
- **The packet buffer fits the heap**: at most 64 MB or a quarter of the heap Android
  grants, counting the ~60 bytes each packet takes besides its data. Before, small packets
  (ACKs) took twice the counted memory, and on a 16 MB heap the buffer alone would have
  run out of memory (the emulator showed this limit with the IP database in phase 7).
- Search splits the search text once instead of per connection, builds the searched
  texts only until one matches, and caches the country names (`Locale` lookups were
  most of the 30 ms).
- Recording caches each app's packet comment instead of formatting it per packet.

## The app on the emulator (CI)

Android 10, x86_64, 16 MB heap, software rendering. Run in CI after these changes:

*(filled in from the first CI run)*

## On the phone

Only the P30 Pro can show these; worth a check after installing this version:

1. **Speed**: a speed test (e.g. fast.com) with the capture off, then on. With capture it
   should reach at least 80% of the speed without.
2. **Notifications**: leave the capture running in the background with the screen off for
   an hour; messages (WhatsApp, Signal, e-mail push) should arrive on time. Before this
   check, their connections were reset after a minute without traffic.
3. **Battery**: after a day of background capture, *Settings → Battery → App launch / usage*:
   Traffic AL should be in the low single-digit percent. Its engine wakes up at most 4
   times a second while there is no traffic and does nothing else.
4. **Memory**: *Settings → System → Developer options → Running services*: the app's
   memory should stay the same over hours (all buffers have fixed limits).
