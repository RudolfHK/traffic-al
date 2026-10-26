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
  traffic and, when I switch it on, the UDP live export to the host I enter.
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
5. Background ("silent") capture, recordings and live export.
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
   c. Live export over UDP to a host and port I enter:
      - PCAP with LINKTYPE_RAW, exactly like PCAPdroid's UDP exporter: a 24-byte header
        datagram, then one record per datagram. PCAPdroid's `udp_receiver.py` must work
        with it.
      - Or PCAPNG with the app comment on each packet.
      - `tools/udp-receiver.py` handles both and pipes into `wireshark -k -i -`.
   d. Settings screen: theme, start at boot, battery optimization, a shortcut to the
      always-on VPN settings, recording on/off and its limit, and the UDP export.

   Done when:
   - With the app swiped away and the screen off, the capture runs for an hour and the
     recording covers the whole hour.
   - An exported recording opens in Wireshark with app comments.
   - The live stream shows up in Wireshark on the PC.
   - The tile starts and stops the capture.
   - In CI: unit tests cover the formats, rotation and limits. The host test's capture,
     written as a segmented recording and sent over UDP to the receiver script, is read
     by tshark with every packet.
6. Encrypted storage and app lock: Room + SQLCipher, key in Android Keystore,
   BiometricPrompt + PIN, EncryptedSharedPreferences. Captures on disk are encrypted.
7. Destination enrichment (offline): MaxMind GeoLite2 City + ASN (or DB-IP lite),
   reverse DNS / RDAP on demand, tracker lists (e.g. Disconnect, EasyPrivacy) bundled.
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
- Phases 1 to 5 are implemented in this repository (phase 3 with nDPI 5.0 for
  protocol/service detection and QUIC/HTTP server names; flows, recordings and the UDP
  stream are checked against tshark in CI). Continue with **6** (encrypted storage and
  app lock).
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
