# Traffic AL

An Android app that shows which apps on **your own device** send data where. It runs
entirely on the phone through Android's `VpnService` API: a local TUN interface, no
remote VPN server, no root required. The project prompt and phase plan are in
[docs/PROMPT.md](docs/PROMPT.md).

## Status

| Phase | Scope | State |
| --- | --- | --- |
| 1 | Project setup, VPN consent, foreground service, start/stop | done |
| 2a | DNS-only capture: per-app DNS queries, live list, app summary, PCAPNG export | done (needs on-device test) |
| 2b | Full capture with a user-space TCP/UDP forwarder | next |
| 3–9 | Flow tracking, analysis UI, encrypted storage, enrichment, TLS, validation | planned |

## How phase 2a works

```
app ──DNS query──▶ 10.215.173.2 (virtual DNS, routed into TUN)
                      │
                      ▼
            CaptureVpnService ── getConnectionOwnerUid ──▶ "which app?"
                      │
                      ├── relay to the network's real resolver (protected socket)
                      ├── write the answer back into the TUN
                      └── record query + answer (live list, PCAPNG buffer)
```

Only the virtual DNS server address is routed into the VPN, so all other traffic keeps
flowing normally. This answers "which app talks to which domain" without a TCP/IP
stack. Phase 2b routes everything.

## Install

1. Open the latest successful run of
   [Android CI](https://github.com/RudolfHK/traffic-al/actions/workflows/android.yml) and download the
   `traffic-al-debug-apk` artifact.
2. `adb install app-debug.apk` (or copy the APK to the phone and open it).
3. Start the app and tap **Start**, then accept the VPN dialog.
4. On Huawei/EMUI: Settings → Battery → App launch → Traffic AL → *Manage manually*, so
   the capture isn't killed in the background.

## Build

```
./gradlew -p core test        # protocol code, plain JVM, no Android SDK needed
./gradlew :app:assembleDebug  # needs the Android SDK (ANDROID_HOME)
```

`core/` is a standalone pure-Kotlin build (packet parsing, DNS, PCAPNG writer) included
into the app through a Gradle composite build.

## Limitations (phase 2a)

- **Private DNS "strict"** (a hostname set under Settings → Network → Private DNS)
  bypasses the VPN's DNS server; nothing is captured. "Automatic" works.
- Apps that use their own DNS-over-HTTPS (e.g. Chrome's "Secure DNS" with a custom
  provider) don't show up; their traffic becomes visible in phase 2b.
- DNS over TCP to the virtual server is not answered yet (rare: only for truncated responses).
- App attribution needs Android 10+ (`getConnectionOwnerUid`). On Android 8–9 queries
  show as "Unknown app".
- Captured data lives in memory only (last 5,000 queries / 20,000 packets) until the
  encrypted storage of phase 6 exists.
- Only one VPN can be active per Android profile.
