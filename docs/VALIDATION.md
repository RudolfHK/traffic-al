# Validation (phase 9)

Phase 9 checks that the whole capture works on known traffic and on the edge cases the
plan calls out: known destinations, IPv6, a VPN conflict, strict Private DNS, Huawei
battery handling, and a large sustained download. Most of it is automated; the rest only
a real phone on a real network can show, and those are the manual checks below.

## Automated (CI)

| Check | Where | What it proves |
| --- | --- | --- |
| Known traffic (DNS, HTTP, TLS+SNI, QUIC+SNI) matches `tshark` | `tools/host-test` (real TUN, netns) | Every flow the tracker reports equals tshark's conversation (frames and bytes per direction), and nDPI classified each kind |
| **IPv6** forwarding: AAAA lookup and a download over IPv6 | `tools/host-test` (best effort) | The engine parses, forwards, NATs and tracks IPv6 as well as IPv4. Runs where the kernel has IPv6; skipped (not failed) where it doesn't |
| Large download under capture, hash verified | `tools/host-test` (50 MB blob, with induced packet loss) | Bulk TCP stays byte-exact through the engine, including retransmission of dropped segments |
| Half close, server-speaks-first, 300 open connections, 75 s idle | `tools/host-test` | The TCP edge cases from the performance check stay fixed (docs/PERFORMANCE.md) |
| Strict Private DNS (DoT on 853) | `tools/host-test` (`dot_blocked`) | Port 853 is blocked so "automatic" Private DNS falls back to plain DNS; strict stays untouched |
| Recordings and TLS decryption | `tools/host-test` + `core` | Exports open in tshark, encrypted segments hold no cleartext, and a key log decrypts the TLS (docs/DECRYPTION.md) |
| The app on an Android 10 emulator | `app/src/androidTest` + `tools/emulator` | Download through the real VPN, the capture pipeline, memory and stability (docs/PERFORMANCE.md) |

## On the phone (manual)

These need the device and a real network; worth a pass after installing this version.

1. **Known traffic is attributed correctly.** Open a few apps and a browser to known sites.
   Each connection should show the right app, and its domain (SNI or the DNS name). Export
   a recording and open it in Wireshark: the packets and apps match what the app showed.
2. **A large download.** Download about 1 GB (a big file, or a long video) with the capture
   on. It should complete, byte-for-byte, at a normal speed; memory should stay flat
   (Developer options → Running services).
3. **IPv6.** On a network with IPv6 (most mobile networks; check the connection shows an
   IPv6 server address), traffic to IPv6-only or dual-stack sites should work and be
   tracked with its IPv6 address. Without a global IPv6 address the app routes IPv4 only,
   by design.
4. **VPN conflict.** Start another VPN app. Only one VPN runs per profile, so either Traffic
   AL stops (its capture ends cleanly, no crash) or the other app is refused — whichever you
   confirm second. Starting Traffic AL again should recover.
5. **Strict Private DNS.** Set *Settings → Network → Private DNS* to a specific provider
   (strict). DNS then bypasses the VPN and lookups won't appear in the app, but the internet
   keeps working and connections still show their SNI. Set it back to *Automatic* and the
   DNS lookups appear again.
6. **Huawei background capture.** *Settings → Battery → App launch → Traffic AL → Manage
   manually*, all three switches on. Then with the screen off for an hour, the capture keeps
   running and the recording covers the hour (EMUI kills background services otherwise).
