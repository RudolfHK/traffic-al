# Traffic AL

An Android app that shows which apps on **your own device** send data where. It runs
entirely on the phone through Android's `VpnService` API: a local TUN interface, no
remote VPN server, no root required. The project prompt and phase plan are in
[docs/PROMPT.md](docs/PROMPT.md).

## Status

| Phase | Scope | State |
| --- | --- | --- |
| 1 | Project setup, VPN consent, foreground service, start/stop | done |
| 2a | DNS-only capture | replaced by 2b |
| 2b | Full capture through zdtun: every connection per app, DNS, SNI, PCAPNG export | done (needs on-device test) |
| 3 | Flow tracking (bytes, SNI, DNS name per connection) | basic version done with 2b |
| 4–9 | Analysis UI, encrypted storage, enrichment, TLS decryption, validation | planned |

## How it works

```
apps ──all IP traffic──▶ TUN (VPN, 10.215.173.1, DNS 10.215.173.2)
                            │
                            ▼
                native engine (C, app/src/main/cpp)
                  ├─ zdtun: terminates TCP/UDP/ICMP locally and relays every
                  │  connection over normal sockets (this app is excluded from its VPN)
                  ├─ DNS to 10.215.173.2:53 → redirected to the network's real resolver
                  ├─ port 853 (DNS-over-TLS/QUIC) → blocked, see "Encrypted DNS"
                  └─ every packet + owning app uid → batches to Kotlin every 250 ms
                            │
                            ▼
                FlowTracker (core/, pure Kotlin)
                  connections per app with bytes, TLS server name (SNI) and the DNS
                  name the app resolved; DNS lookups; 64 MB packet buffer → PCAPNG
```

The app uid of each connection comes from `ConnectivityManager.getConnectionOwnerUid`
(Android 10+).

## Encrypted DNS (Private DNS, DoH)

| Situation | What you see |
| --- | --- |
| Private DNS **off** or **automatic** | Everything: Android tries DNS-over-TLS to the VPN's DNS server, the engine blocks port 853, Android falls back to plain DNS. |
| Private DNS **strict** (a hostname is set) | The connections and their server names (SNI), but not the DNS queries themselves. Tap **Switch to automatic while capturing**: with root (Magisk prompt) or a one-time adb grant the app switches to automatic and restores your setting when the capture stops. |
| An app with its own DNS-over-HTTPS (e.g. a custom provider in Chrome) | The connection to the DoH server is marked *encrypted DNS*; the following connections still show their SNI. Reading the queries themselves needs TLS decryption (phase 8, root). |

One-time grant instead of root:

```
adb shell pm grant io.github.rudolfhk.traffical android.permission.WRITE_SECURE_SETTINGS
```

## Install

1. Open the latest successful run of
   [Android CI](https://github.com/RudolfHK/traffic-al/actions/workflows/android.yml) and download the
   `traffic-al-debug-apk` artifact.
2. `adb install app-debug.apk` (or copy the APK to the phone and open it).
3. Start the app and tap **Start**, then accept the VPN dialog.
4. On Huawei/EMUI: Settings → Battery → App launch → Traffic AL → *Manage manually*, so
   the capture isn't killed in the background.

## Build and test

```
git submodule update --init         # zdtun
./gradlew -p core test               # protocol code, plain JVM, no Android SDK needed
sudo tools/host-test/run.sh          # native engine end-to-end on a Linux TUN device
./gradlew :app:assembleDebug         # needs the Android SDK and NDK
```

The host test builds the engine with gcc, routes a network namespace through a real
TUN device and checks DNS over UDP/TCP, a 50 MB download (checksum), 80 parallel
connections, DoT blocking and app attribution of every captured packet. CI runs all three.

## Limitations

- Only one VPN can be active per Android profile.
- IPv6 is routed through the capture only if the network has a global IPv6 address.
- QUIC (HTTP/3) connections show their domain via DNS, not via SNI.
- Captured data lives in memory only (last 2,000 connections in the list, 64 MB of
  packets for export) until the encrypted storage of phase 6 exists.

## License

Traffic AL is licensed under the [GNU General Public License v3.0](LICENSE) or later.
It includes [zdtun](https://github.com/emanuele-f/zdtun) by Emanuele Faranda
(LGPL-3.0, git submodule in `app/src/main/cpp/zdtun`), the user-space TCP/IP forwarder
also used by PCAPdroid.
