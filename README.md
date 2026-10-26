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
| 3 | Connection tracking: protocol/service/category via nDPI, QUIC and HTTP server names, flows verified against tshark | done (needs on-device test) |
| 4 | Analysis UI: dashboard, live throughput, filters, connection detail with hex dump, tracker highlighting | done (needs on-device test) |
| 5 | Background capture, recordings on storage, settings, light/dark theme | done (needs on-device test) |
| 6 | Encrypted recordings and connection history (Android Keystore, Tink, SQLCipher), app lock with PIN and fingerprint | done (needs on-device test) |
| 7–9 | Enrichment, TLS decryption, validation | planned |

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
                  ├─ nDPI: protocol, service and category of each connection,
                  │  server name from TLS/QUIC SNI or the HTTP Host header
                  └─ every packet + owning app uid + nDPI results → Kotlin every 250 ms
                            │
                            ▼
                FlowTracker (core/, pure Kotlin)
                  one record per connection: app, endpoints, protocol (e.g.
                  "TLS.YouTube"), category, server name (SNI, QUIC, HTTP Host or the
                  DNS name the app resolved), bytes and packets per direction, first/last
                  seen; DNS lookups; 64 MB packet buffer → PCAPNG
                     │                                   │
                     ▼                                   ▼
          recorder (own thread)               history (own thread)
            encrypted PCAPNG files with         connections and DNS lookups in an
            the app per packet, storage limit   SQLCipher database, saved every 10 s
```

The app uid of each connection comes from `ConnectivityManager.getConnectionOwnerUid`
(Android 10+).

## Screens

- **Overview**: start/stop, the recordings, a time range (1 min to all), sent and received bytes
  with the current rate, the number of connections and of connections that need
  attention, a live throughput chart (sent/received per interval, refreshed every
  second) and the apps ranked by data or by connections. Tapping an app opens its
  connections.
- **Connections**: free-text search over app, package, domain, SNI, IP, protocol,
  category and port (all words must match), quick filters for the app, *needs
  attention*, the most frequent protocols and the time range.
- **Connection detail**: app, every name known for the server (domain, TLS SNI,
  QUIC/HTTP server name, resolved DNS name), nDPI protocol, category and rating,
  endpoints, start, duration, bytes, packets and average rate, then the connection's
  packets from the capture buffer with TCP flags and a hex dump of each payload (tap to
  expand).
- **DNS**: every lookup with its app, answers or error and latency.
- **Recordings** (from the overview): the saved recordings with start, duration and
  size, export (system file picker) and delete, the storage used, and an export of the
  packets in memory.
- **Settings**: theme (system, light, dark), background capture, recording and its
  storage limit, app lock, erase all data.

The app is English only and has its own light and dark color schemes (the same on
every Android version).

A connection *needs attention* when nDPI rates it as a tracker or advertisement
(red, *tracker*), as unsafe, dangerous, malware or mining (red, *risky*), or when the
app connected over TCP/UDP to a bare IP address that no DNS lookup, SNI or HTTP Host
header named (*IP only*). Bundled tracker lists come with phase 7.

## Background capture

The capture keeps running with the app closed, swiped away from the recent apps, and
the screen off, until you stop it:

- **Stop** in the app, in the notification or on the **Traffic capture** Quick Settings
  tile (add it via the pencil icon in the quick settings), which also starts it.
- The notification is silent and sits folded at the bottom of the shade without a
  status-bar icon. Android always shows its VPN key icon while any VPN runs; that's system
  UI and stays.
- If Android kills the process, it restarts the service (`START_STICKY`) and the capture
  continues in a new recording. An app update restarts a running capture too.
- **Settings → Start capture when the phone starts** starts it after boot (once the VPN
  permission was granted in the app).
- More robust: **Always-on VPN**. Settings → VPN settings → gear next to Traffic AL →
  *Always-on VPN*: Android itself starts the capture at boot and restarts it.
- Battery: **Settings → Battery optimization → Turn off**. On Huawei/EMUI also
  Settings → Battery → App launch → Traffic AL → *Manage manually*, all three switches
  on; otherwise EMUI stops background apps regardless.

While no screen of the app is visible, it does no UI work: the connection list is only
built when a screen shows it. Memory stays bounded however long the capture runs
(10,000 connections, 5,000 DNS lookups, 64 MB of packets); everything else goes to the
recording and the history. If Android kills the app, the connections and lookups saved
so far are listed again when it restarts.

## Recordings

Every packet is saved as PCAPNG with the app as each packet's comment
(`uid=10123 app=com.android.chrome`), encrypted (see below). A recording is a folder of
files of up to 64 MB; when all recordings reach the storage limit (250 MB, 1 GB or 4 GB),
the oldest files are deleted. **Export** decrypts a recording into one PCAPNG file (one
section per file) that opens in Wireshark; a running recording can be exported too (up
to the moment of the export). If Android killed the capture while it was writing a file,
that file is exported up to its last complete packet.

## Encryption and app lock

- **Encrypted storage.** Recordings are encrypted with [Tink](https://github.com/tink-crypto/tink-java)
  streaming AEAD (AES-256-GCM, a fresh key per file derived from the recording key). The
  history of connections and DNS lookups is an [SQLCipher](https://www.zetetic.net/sqlcipher/)
  database whose random key is stored encrypted. All keys are wrapped by a master key in
  the Android Keystore, which never hands it out: copying the app's files (via root, adb
  or a backup) gives nothing readable. The keys need no fingerprint or PIN, because the
  capture writes while the phone is locked. So anyone who can use the unlocked app can
  read the data; the app lock is for that. Recordings of version 0.5 are encrypted on
  the first start. Exported files are plain PCAPNG.
- **App lock** (Settings → Privacy): a PIN of 4 to 12 digits, optionally the
  fingerprint.
  - The app asks for it when it opens and after a minute in the background; the capture
    keeps running meanwhile.
  - After five wrong PINs it waits 30 s, then doubles the wait.
  - The PIN is stored as a salted PBKDF2 hash, itself encrypted with a Keystore key.
  - While the lock is on, screenshots of the app are blocked and the recent apps
    overview shows no content.
  - *Forgot the PIN?* on the lock screen erases all recordings and the history and
    removes the lock.

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
   `traffic-al-debug-apk` artifact (signed in to GitHub). CI runs on GitHub-hosted
   runners, free for public repositories: no runner of your own is needed.
2. `adb install app-debug.apk` (or copy the APK to the phone and open it).
3. Start the app and tap **Start**, then accept the VPN dialog.
4. For background capture, see [Background capture](#background-capture).

## Build and test

```
./gradlew -p core test               # protocol code, plain JVM, no Android SDK needed
sudo tools/host-test/run.sh          # native engine end-to-end on a Linux TUN device
./gradlew :app:assembleDebug         # needs the Android SDK and NDK
./gradlew -p tools/ui-preview render # screenshots of the screens, no Android SDK needed
./gradlew :app:connectedDebugAndroidTest  # on a device or emulator: Keystore, Tink, SQLCipher
```

The screens in `app/src/main/java/.../ui/common` use only Compose APIs that also exist
on Compose Desktop, and their strings come in through `UiText`. `tools/ui-preview`
compiles them together with `core` for the desktop and renders them with sample data
to `tools/ui-preview/build/screens/*.png` (light and dark). CI uploads these as the
`ui-screens` artifact.

The host test builds the engine (with nDPI) on Linux, routes a network namespace
through a real TUN device and checks DNS over UDP/TCP, a 50 MB download (checksum), 80
parallel connections (half of them slow readers), TLS, a QUIC Initial, DoT blocking and
app attribution of every captured packet, while dropping 0.5% of the packets to the
app on purpose (`DROP_RATE`).

`tools/host-test/validate.sh <work dir>` then turns the capture into a PCAPNG file and
flow records with the Kotlin core and checks that every flow matches tshark's
conversations (`tshark -z conv,tcp -z conv,udp`: frames and bytes per direction) and
that nDPI classified DNS, HTTP, TLS (SNI) and QUIC (SNI) and rated every classified
flow. It also writes the packets as recordings and exports them:
- in small files;
- with a storage limit that forces deleting old files;
- encrypted like in the app;
- encrypted with the last file cut off, as when Android kills the capture.

tshark must read every export without errors, with the same packet lengths and the app
comments, and the encrypted files must contain no plaintext. CI runs all of it.

A second CI job runs the instrumented tests (`app/src/androidTest`) on an Android 10
emulator: recordings encrypted with the Keystore-backed keys, the migration of plain
recordings, the SQLCipher history (written, reopened, file not readable as SQLite) and
the PIN.

## Limitations

- Only one VPN can be active per Android profile.
- IPv6 is routed through the capture only if the network has a global IPv6 address.
- nDPI classifies a connection from its first 12 packets; protocols that reveal
  themselves later stay "Unknown".
- The overview's totals and throughput chart cover the time since the app last started;
  the connection list and DNS lookups include earlier runs (from the history).
- Encryption at rest doesn't help against someone who can unlock the app; use the app
  lock. On a rooted phone, root can do what the app can, including using its Keystore
  keys on the device.
- Android shows its VPN key icon whenever a VPN runs; the app does not hide it.

## License

Traffic AL is licensed under the [GNU General Public License v3.0](LICENSE) or later.
It includes [zdtun](https://github.com/emanuele-f/zdtun) by Emanuele Faranda
(LGPL-3.0), the user-space TCP/IP forwarder also used by PCAPdroid, in
`app/src/main/cpp/zdtun`. That copy adds retransmission of data sent to the apps, see
[TRAFFIC_AL_CHANGES.md](app/src/main/cpp/zdtun/TRAFFIC_AL_CHANGES.md). Protocol detection
uses [nDPI](https://github.com/ntop/nDPI) 5.0 by ntop (LGPL-3.0), unmodified, in
`app/src/main/cpp/ndpi` (see [NDPI_ORIGIN.md](app/src/main/cpp/ndpi/NDPI_ORIGIN.md)).
