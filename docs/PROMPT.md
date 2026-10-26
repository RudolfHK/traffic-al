# Project prompt for Claude Code (improved)

This is the improved version of the prompt in the original German plan
("Netzwerk-Traffic-Analyse-App (Android) – Prompt & Claude-Code-Plan"). The original was
a good *what*, but it asked for a plan instead of a build, mixed must-haves with
nice-to-haves, and left the build setup, acceptance criteria and phase order open.
This version is meant to be pasted into Claude Code **one phase at a time**.

## What changed compared to the original prompt

| Original | Improved | Why |
| --- | --- | --- |
| "Deliver a feasibility note, then a phased plan" | "Implement phase N, push, keep CI green" | The feasibility analysis is already done (see the plan); the agent should build. |
| Phase 2 = full TCP/IP stack (zdtun + NDK) before anything is visible | New **Phase 2a: DNS-only capture** before the full stack | A local VPN that routes everything breaks the internet until forwarding works. Routing only a virtual DNS server gives "which app talks to which domain" on day one, with zero breakage. |
| Tech list without build or test setup | Gradle KTS + version catalog, pure-Kotlin `:core` module, GitHub Actions builds the APK | Parsing and export can be unit-tested without a phone or the Android SDK. The APK comes from CI as a downloadable artifact. |
| Target device implicit | Huawei P30 Pro, Android 10 (API 29), rooted; `minSdk 26`, `targetSdk 35` | `getConnectionOwnerUid` needs API 29; Android 10 still allows a system CA via root. |
| Root, enrichment, app lock and dashboard added later as appendices | Integrated as phases 6–10 with clear dependencies | The storage design (encrypted DB) must exist before persistent capture, not after. |
| No acceptance criteria | Every phase has a "done when" check that can be verified on the device | Phases become testable milestones. |
| PCAPdroid as "reference" | PCAPdroid/zdtun are **GPL-3.0**, nDPI is **LGPL-3.0** | Copying code from them makes this project GPL-3.0; that's fine for a private tool but has to be a conscious decision. |

## Additions after phase 4 (improved)

The request was: *"We need a light and dark mode for the app. Screens should be English
not German. And by the way if you haven't noticed I have no github runner so no ci will
succeed. Another feature would also be the silent sniffing meaning that the app runs in
the background and captures the traffic. In accordance with those additions continue with
phase 5."* Improved into concrete, checkable requirements:

| Request | Improved | Why |
| --- | --- | --- |
| "a light and dark mode" | App-defined light and dark color schemes (not dynamic color), and a theme setting *System / Light / Dark* that is remembered | Android 10 has no dynamic color, so the app needs its own schemes. A setting lets the app differ from the phone. |
| "Screens should be English not German" | English only: remove `values-de`, and limit library resources to English (`resourceConfigurations += "en"`) | The phone is set to German, so the app and Material components followed it. |
| "I have no GitHub runner so no CI will succeed" | Correction: the workflow runs on GitHub-hosted runners (`ubuntu-latest`), which are free for public repositories and need no runner of your own. The runs execute and pass; the APK is the run's `traffic-al-debug-apk` artifact. | The container has no Android SDK, so the CI run is the only place the Android code is compiled and linted. It stays the gate for every push. |
| "silent sniffing: the app runs in the background and captures" | Phase 5a below: the capture runs with the app closed, swiped away and the screen off. A minimal notification with no sound and no status-bar icon. Restart after the system kills it, always-on VPN, optional start at boot, a Quick Settings tile. | Android requires a foreground service for this. The VPN key icon and the consent dialog are system UI; hiding them is neither possible without modifying the system nor wanted for an audit of your own phone. |
| "continue with phase 5" | Phase 5 = background capture + recordings to storage + UDP live export + a settings screen | A capture running for hours in the background is only useful if every packet is kept, not just the last 64 MB in memory. |

## Additions for phase 6 (improved)

The request was: *"Continue with phase 6. Also I don't really need the live port to
wireshark the app is good enough for it with export only."*

| Request | Improved | Why |
| --- | --- | --- |
| "don't need the live port to Wireshark" | Remove the UDP live export entirely: the code, the setting, the receiver script and its CI check. Export of recordings stays. | Less code and nothing that sends captured traffic over the network. |
| "phase 6" (Room + SQLCipher, Keystore, BiometricPrompt + PIN, EncryptedSharedPreferences) | **Recordings** encrypted with Tink streaming AEAD; the existing plain recordings are migrated. **History** of connections and DNS lookups in Room on SQLCipher. **Keys:** a Keystore master key wraps the Tink keysets, the database key and the PIN record. **App lock:** a PIN with fingerprint as an option and *erase all data* when the PIN is forgotten. **Device tests** on an Android 10 emulator in CI. | Jetpack Security (EncryptedSharedPreferences/EncryptedFile) is deprecated, and Tink is what it was built on. The history is the part of "storage" that was still missing: connections were lost whenever Android killed the background capture. |
| (implicit) | The keys don't require the user to authenticate, and the lock protects the screens | The capture writes while the phone and the app are locked. Encryption at rest protects the files, e.g. copied via root or adb; the lock protects against someone holding the unlocked phone. |

## Phase 7 (improved)

The request was *"Continue with phase 7"*, whose plan named MaxMind GeoLite2 (or DB-IP
lite), reverse DNS/RDAP on demand and bundled tracker lists (Disconnect, EasyPrivacy).

| Plan | Improved | Why |
| --- | --- | --- |
| MaxMind GeoLite2 City + ASN | DB-IP Lite Country + ASN (CC BY 4.0) | GeoLite2 needs an account and its license limits redistribution; city-level data is 100+ MB and imprecise for servers. Country and network operator are what matter for a server. |
| Disconnect, EasyPrivacy | AdGuard companiesdb (WhoTracks.me, CC BY-SA 4.0): domain, tracker name, company, category | Disconnect's list is CC BY-NC-SA 4.0, which a GPL-3.0 app can't include. EasyPrivacy's domain-only part has shrunk to a few lines, and its other rules match URLs, which the app can't see. companiesdb adds the company, which answers "who" rather than only "a tracker". |
| (implicit) data format | Compact range tables (varint deltas, gzip; 4.5 MB for 1.2 M ranges) loaded lazily by the UI; a JVM tool builds them from the CSV/JSON sources; `tools/enrichment/update.sh` refreshes them | Fast offline lookups (binary search) without an MMDB library. A capture running in the background doesn't load the data. |
| reverse DNS / RDAP on demand | A button in the connection detail; rdap.org redirects to the right registry | It is the only traffic the app creates itself, so it only happens when the user asks. |

## The prompt

```markdown
# Role and goal
You are building "Traffic AL", an Android app for MY OWN device that shows which of my
apps send data where (a privacy audit). Everything runs locally via Android's VpnService
API (a local TUN interface, no remote VPN server). Only my device, only my traffic:
no Wi-Fi monitor mode, no capturing other devices.

# Target
- Device: Huawei P30 Pro, Android 10 (API 29), rooted with Magisk. Root is optional;
  every non-root feature must work without it.
- minSdk 26, targetSdk/compileSdk 35. Kotlin, Jetpack Compose (Material 3), Gradle KTS
  with a version catalog (gradle/libs.versions.toml).

# Repository layout and build (already set up in phases 1 and 2a)
- `core/`: standalone pure-Kotlin/JVM Gradle build: packet parsing (IPv4/IPv6/TCP/UDP),
  DNS, TLS-SNI, the PCAPNG writer. No Android imports, so it can be unit-tested with
  `./gradlew -p core test` (no SDK needed). Put all protocol logic here.
- `app/`: the Android app (VpnService, UI, storage); depends on `core` via a composite build.
- `.github/workflows/android.yml`: runs core tests, `assembleDebug`, `lintDebug`, and
  uploads the debug APK as an artifact. CI must stay green after every phase.
- UI strings live in resources, English only (no translations; resources of libraries are
  limited to English too).
- Theme: the app's own light and dark color schemes; a setting chooses System, Light or
  Dark.
- CI runs on GitHub-hosted runners (free for public repositories). This dev container has
  no Android SDK, so the Android code is only compiled and linted there: push, then read
  the run before calling a phase done.

# Working rules
- Implement exactly ONE phase per request, then summarize what to test on the phone.
- Add unit tests in `core` for every parser or format (with real packet hex dumps).
- Keep the tool itself private: no analytics, no crash reporting, offline databases
  only. The only network traffic the app itself creates is forwarding the captured
  traffic, plus owner lookups (RDAP, reverse DNS) when I ask for one.
- Don't copy GPL code (PCAPdroid, zdtun) unless I explicitly approve relicensing to GPL-3.0.
  Reading it for reference is fine.
- Document every platform limitation you hit in README.md ("Limitations").

# Phases (each one is done when its check passes on the device)
1. Project setup and VPN skeleton. Done when the consent dialog appears, the VPN key icon
   shows, and Stop tears it down.
2a. DNS-only capture: route only a virtual DNS server (10.215.173.2/32) into the TUN, relay
   queries to the real resolver, attribute each query to its app via
   `ConnectivityManager.getConnectionOwnerUid`, and show a live list plus per-app summary;
   export buffered packets as PCAPNG. Done when opening a website shows its domain under
   the browser's name, the internet keeps working, and the export opens in Wireshark.
2b. Full capture: route 0.0.0.0/0 and ::/0. Implement a user-space TCP/UDP forwarder
   (terminate TCP locally, relay over protected sockets), or integrate zdtun via the NDK if
   relicensing is approved. Done when browsing, streaming and app updates work for 30 min
   with capture on, and throughput is at least 80% of the throughput without it.
3. Connection tracking: one record per flow (app, src/dst IP:port, protocol, SNI from the
   TLS ClientHello, the DNS name that resolved to the IP, bytes up/down, start/end time).
   Done when the flows match `tshark -z conv,tcp` on the exported PCAPNG.
4. Analysis UI: dashboard sorted by bytes/connections per app, filters (app, domain, IP,
   protocol, port, time range, free text), live throughput chart (Vico), flow detail with
   hex dump, highlighting of unknown or tracker destinations.
5. Background ("silent") capture and recordings.
   a. Background capture:
      - The capture keeps running with the app closed, swiped away from recents and the
        screen off.
      - Its foreground notification is minimal: its own channel with IMPORTANCE_MIN, so no
        sound and no status-bar icon, plus a Stop action. Android's VPN key icon and
        consent dialog are system UI and stay.
      - START_STICKY: if the system kills a running capture, it restarts.
      - Always-on VPN is supported (the system starts the service without the app's
        action). Optional start at boot, once VPN consent has been given.
      - A Quick Settings tile starts and stops the capture without opening the app.
      - A button requests the battery-optimization exemption, next to the EMUI hint.
      - While no screen is visible, the app does no UI work.
      - Memory stays bounded over days.
   b. Recordings:
      - Every packet goes to PCAPNG segments in app-private storage, with the app per
        packet as the comment.
      - Each segment is a complete file of at most 64 MB. A total limit (256 MB, 1 GB or
        4 GB) deletes the oldest segments.
      - A recordings screen lists them (start, duration, size) with export and delete.
        Export goes through the system file picker as one multi-section PCAPNG.
      - Plain files until phase 6 encrypts them.
   c. (A UDP live export to Wireshark was built here and removed after phase 5: exporting
      recordings is enough.)
   d. Settings screen: theme, start at boot, battery optimization, a shortcut to the
      always-on VPN settings, recording on/off and its limit.

   Done when:
   - With the app swiped away and the screen off, the capture runs for an hour and the
     recording covers the whole hour.
   - An exported recording opens in Wireshark with app comments.
   - The tile starts and stops the capture.
   - In CI: unit tests cover the format, rotation and limits. The host test's capture,
     written as a segmented recording, is read by tshark with every packet.
6. Encrypted storage and app lock.
   a. Keys: a master key in the Android Keystore wraps Tink keysets kept in the app's
      preferences. No user authentication is required, so the capture can write while
      locked.
   b. Recordings: every segment is encrypted with Tink streaming AEAD (AES-256-GCM-HKDF,
      4 KB segments). Associated data is "<recording>/<segment>", so segments can't be
      swapped. Export decrypts to PCAPNG and copies whole blocks only, so a segment cut
      off by a killed process still exports cleanly. Plain recordings from phase 5 are
      encrypted on first start.
   c. History: connections and DNS lookups in Room on SQLCipher, with a random key
      stored encrypted. Saved every 10 s and when the capture stops; the newest 2,000 are
      shown after a restart; capped at 200,000 rows each. Clear deletes them too, after a
      confirmation.
   d. App lock (optional):
      - A 4 to 12 digit PIN, stored as salted PBKDF2-SHA256 and itself encrypted.
      - Fingerprint via BiometricPrompt, with "Use PIN" as the fallback.
      - Locks at start and after 60 s in the background.
      - Growing waits after 5 wrong PINs.
      - FLAG_SECURE while the lock is on.
      - *Forgot the PIN?* erases recordings and history and removes the lock.
   e. Settings: app lock, fingerprint, change PIN, an encryption note, erase all data.

   Done when:
   - After an update from phase 5, old recordings are encrypted and still export.
   - The recording files and the database file show no readable traffic (copy them via
     root).
   - Connections are still listed after Android killed the app.
   - The app asks for the PIN or fingerprint after a minute in the background.
   - In CI: JVM tests for the format (with Tink), PIN and lock rules; the host test's
     capture is encrypted, exported and cut off, then read by tshark. Instrumented tests
     on an Android 10 emulator cover the Keystore keys, recordings, SQLCipher and the PIN.
7. Destination enrichment (offline):
   - Country and network (ASN, organization) of every server's IPv4/IPv6 address, from
     DB-IP Lite (CC BY 4.0) converted to compact range tables bundled as assets.
   - Known trackers by server name (the domain or a parent domain) with name, company
     and category, from AdGuard companiesdb (CC BY-SA 4.0). Advertising, analytics and
     telemetry raise the *tracker* flag.
   - Shown in the connection list and detail, and searchable. The dashboard gets
     "Trackers contacted" per company.
   - Reverse DNS and RDAP owner lookup only when I tap it in the connection detail.
   - `tools/enrichment/update.sh` rebuilds the data.

   Done when:
   - 8.8.8.8 shows "Google LLC · AS15169, US".
   - An ad SDK's connection shows its company and is flagged.
   - The owner lookup names the registrant.
   - Unit tests cover the formats and parsers; real-data checks run in CI; the data
     loads from the APK on an emulator.
8. TLS decryption (optional, limited): local CA generated on device, an in-app or
   mitmproxy-based MITM for selected apps only, SSLKEYLOGFILE-style key export into the
   PCAPNG (Decryption Secrets Block). Without root: only my own debug apps
   (networkSecurityConfig trusting user CAs). With root on Android 10: install the CA
   into the system store via a Magisk module. Pinned apps stay opaque; document this.
9. Validation: known-traffic tests (curl/browser to known domains), IPv6, VPN conflict
   (only one VPN per profile), Private DNS "strict" (bypasses VPN DNS), Huawei battery
   optimizations (EMUI kills background services unless "Manage manually" is set),
   a 1 GB download under capture.
```

## Recommended usage

- Start each Claude Code session with the prompt above plus "Implement phase N".
- Phases 1 to 7 are implemented in this repository (phase 3 with nDPI 5.0 for
  protocol/service detection and QUIC/HTTP server names; flows and recordings are checked
  against tshark in CI, the encrypted storage and the bundled data on an Android 10
  emulator). Continue with **8** (TLS decryption).
- Decision taken for 4: the throughput chart is drawn with a Compose `Canvas` instead of
  Vico. The screens are shared with a Compose Desktop preview tool (tools/ui-preview)
  that renders them in CI without the Android SDK, and an area chart of two series does
  not justify a charting dependency on both platforms. Tracker highlighting uses nDPI's
  category and rating until the bundled lists of phase 7 exist.
- Decision taken for 2b: zdtun via the NDK, vendored with a retransmission fix
  (app/src/main/cpp/zdtun/TRAFFIC_AL_CHANGES.md). zdtun itself is LGPL-3.0; the project is
  licensed GPL-3.0-or-later, which also allows reusing PCAPdroid code later. The
  "Don't copy GPL code" rule in the prompt no longer applies.
- The native engine is tested on a Linux host with a real TUN device
  (`tools/host-test/run.sh`), so most of it can be verified without a phone.
