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
- UI strings live in resources: English default + German (`values-de`); lint fails on
  missing translations.

# Working rules
- Implement exactly ONE phase per request, then summarize what to test on the phone.
- Add unit tests in `core` for every parser or format (with real packet hex dumps).
- Keep the tool itself private: no analytics, no crash reporting, offline databases
  only. The only network traffic the app itself creates is forwarding the
  captured traffic.
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
5. PCAPNG export of full captures with per-packet app comments; optional streaming to a
   remote Wireshark over UDP (PCAPdroid-compatible "UDP exporter").
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
- Phases 1, 2a and 2b are implemented in this repository, with a basic version of
  phase 3 (per-connection bytes, SNI and DNS name). Continue with the rest of **3**
  (nDPI protocol detection, QUIC SNI) or **4**.
- Decision taken for 2b: zdtun via the NDK, vendored with a retransmission fix
  (app/src/main/cpp/zdtun/TRAFFIC_AL_CHANGES.md). zdtun itself is LGPL-3.0; the project is
  licensed GPL-3.0-or-later, which also allows reusing PCAPdroid code later. The
  "Don't copy GPL code" rule in the prompt no longer applies.
- The native engine is tested on a Linux host with a real TUN device
  (`tools/host-test/run.sh`), so most of it can be verified without a phone.
