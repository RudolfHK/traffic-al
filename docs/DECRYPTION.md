# TLS decryption (phase 8)

Traffic AL can show HTTPS traffic **decrypted** in Wireshark — but only for TLS sessions
whose keys you, the owner of the device, already have. This is for auditing your own
phone: seeing what your own apps actually send inside TLS.

**Traffic AL never breaks any cryptography and never terminates or forges a TLS
connection.** The keys stay inside the apps that made the connection; you supply a copy of
them, and Traffic AL only packages the ones for the sessions in a recording into the
exported file, as a PCAPNG *Decryption Secrets Block* (DSB). Wireshark reads that block and
decrypts. No key, no plaintext. **Certificate pinning is unaffected: pinned apps (most
banking and messenger apps) stay opaque, and that is by design.**

## Turning it on

Settings → *TLS decryption* → **Embed TLS keys into exports**.

Then place a key log (NSS `SSLKEYLOGFILE` format — the one Wireshark, curl, Firefox and
Chrome use) at the path shown in that section, which is:

```
/data/data/io.github.rudolfhk.traffical/files/tls/keylog.txt
```

From then on, every recording you export and every in-memory export carries the keys for
the TLS sessions it contains. Open the file in Wireshark and the HTTPS is decrypted
automatically — no Wireshark settings needed.

The settings screen shows how many TLS sessions the placed key log covers.

**In the app, too.** Once the key log is in place, the connection detail (live and in a
recording) shows a **Decrypted** section for connections it has keys for: the request and
the response in the clear, right next to the Decoded/Hex packet views. This needs no export
and no Wireshark. It covers:

- **TLS 1.2 and 1.3** over TCP, with an AES-GCM or ChaCha20-Poly1305 cipher.
- **QUIC** over UDP (the HTTP/3 application streams), as long as the connection's handshake
  packets are still in the buffer. The decrypted QUIC stream is shown as its bytes: HTTP/3
  DATA (the body) is readable, but HTTP/3 request/response headers are QPACK-compressed and
  are not yet decoded in the app — for those, open the recording in Wireshark with the
  exported key log.

Legacy TLS 1.2 CBC ciphers and QPACK header decoding are not handled, and pinned apps stay
opaque.

## The data-flow audit (phase 12)

The connection detail shows one connection at a time. The **Audit** (a button on the
dashboard) answers the cybersecurity question across *all* of your traffic at once: **which
apps send what data where.** It decrypts every connection it has keys for — automatically, in
the background, refreshing while it is open and re-reading your key log live — and groups the
result per app:

- each **destination** the app sent HTTP-bearing traffic to (host, country, tracker/company),
- the **sensitive data** found in the decrypted requests — email, phone, precise location,
  device and advertising IDs, `Authorization`/token/JWT/cookie material, card-like numbers —
  each shown with the value truncated, never in full,
- and an honest tally of what could **not** be read: connections that stayed encrypted
  because there are no keys for them or the app pins its certificate.

It reads HTTP/1.x, HTTP/2 (including HPACK-compressed headers) and HTTP/3 stream data, and it
reads plaintext HTTP (port 80) with no keys at all. Findings are evidence, not accusations:
an app sending your email or a token to its own backend is normal — the value is seeing
*which* app sends *what* to *which* destination. Everything is decrypted and analysed on the
device; nothing is written in the clear and nothing leaves the phone. Connections with no
keys are reported as unreadable, never as clean.

The audit also shows a **Decryptability** breakdown (phase 13): overall and per app, how much
of your web traffic (connections and bytes) is readable versus encrypted and impossible to
decrypt (no keys, or the app pins), with the most opaque apps listed first. It is the honest
answer to "what of mine can I actually read, and what stays opaque".

## MITM with mitmproxy (phase 13)

To read apps you have no other key for, you can route them through your own
[mitmproxy](https://mitmproxy.org) and let the audit show the result. This terminates TLS at a
proxy *you* run — a deliberate exception to Traffic AL's "never terminate TLS" rule, for your
own device and your own apps. It only reaches apps that honor the VPN's HTTP proxy and that
trust your CA; **pinned apps stay opaque, and QUIC/HTTP-3 is not proxied.**

1. Run mitmproxy on your computer (same network as the phone) with a key log:
   `mitmproxy` (then set `tls_keylog_file`), or `SSLKEYLOGFILE=keylog.txt mitmproxy`.
2. In Traffic AL's **Audit** screen, turn on **MitM via mitmproxy** and enter your computer's
   IP and mitmproxy's port. Start (or restart) the capture: the VPN sets that HTTP proxy
   (`VpnService.setHttpProxy`, Android 10+), so proxy-aware apps go through mitmproxy.
3. Install mitmproxy's CA so apps accept it: `tools/decryption/system-ca.sh <mitmproxy-ca.pem>`
   (Magisk, system store) or a user certificate for apps that accept user CAs.
4. Copy mitmproxy's key log to Traffic AL's key-log path. Traffic AL captures the
   phone↔mitmproxy TLS and decrypts it with those keys, so the real request and response show
   up in the audit — and the Decryptability stats move those apps from opaque to readable.

Nothing here reaches the network on Traffic AL's behalf; it routes to the proxy you run and
reads the result through the same owner-key pipeline as everything else.

## Getting the keys

You need the TLS keys for the traffic you want to read. There are three ways, all under
your control, none of which Traffic AL does for you.

### 1. Your own app, built with `SSLKEYLOGFILE`

If you build the app yourself (or it honors `SSLKEYLOGFILE`), point it at a file the key
store can read and let it write its own session keys. No CA, no proxy, no pinning problem.
For your own debug build, allow user-installed trust and the key-log file in that app's
`res/xml/network_security_config.xml` — this goes in **your** app, not in Traffic AL:

```xml
<network-security-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
            <certificates src="system" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

### 2. An external TLS proxy you run against your own device

Run a TLS-intercepting proxy you control — for example [mitmproxy](https://mitmproxy.org)
on your computer — and send the phone's traffic through it. mitmproxy terminates TLS with
its own CA and can write an `SSLKEYLOGFILE`; copy that key log to the path above (via the
Files app, `adb push`, or root).

For apps to accept the proxy's certificate you install the proxy's CA on your phone:

- **User certificate** (no root): *Settings → Security → Encryption & credentials → Install
  a certificate → CA certificate*. Only apps that opt into user CAs will trust it.
- **System certificate** (root, Android 10): some apps trust only system CAs. On your
  rooted phone you can add the proxy's CA to the system store with a Magisk module:

  ```
  tools/decryption/system-ca.sh <proxy-ca.pem>
  ```

  Flash the resulting `system-ca-magisk.zip` in the Magisk app and reboot; remove it there
  to undo. It only places one file you generated; it changes nothing else.

### 3. A key logger on your own rooted device

On a rooted phone you can read the TLS keys an app exports itself, without a proxy or a CA,
by hooking its TLS library. This repo ships a small Frida script for exactly that:

```
tools/keycapture/keylog.js       # hooks BoringSSL/OpenSSL SSL_CTX_set_keylog_callback
tools/keycapture/capture.py      # runs it from your computer, writes keylog.txt
```

It does **not** weaken TLS, defeat pinning, or touch any app but the one you name — it only
asks the app's own TLS library for the key-log lines it already knows how to emit (the same
hook `SSLKEYLOGFILE` uses). On your computer:

```
pip install frida-tools
# start frida-server on the rooted device (matching your frida version), then:
python tools/keycapture/capture.py <package-name> keylog.txt
```

Use the app so it makes connections, press Ctrl-C, and copy the resulting `keylog.txt` to
Traffic AL's key-log path with root:

```
adb push keylog.txt /data/local/tmp/keylog.txt
adb shell su -c 'cp /data/local/tmp/keylog.txt \
  /data/data/io.github.rudolfhk.traffical/files/tls/keylog.txt'
```

This is the only way to read a closed-source app that does not pin. Apps that strip these
symbols or detect instrumentation won't yield keys this way, and **pinned apps still stay
opaque** — for stripped or hardened apps, [friTap](https://github.com/fkie-cad/friTap) is a
more capable, maintained tool that writes the same key-log format; point it at the same
path. See `tools/keycapture/README.md` for details and limits.

## What you can and cannot see

- **Can:** your own apps (via 1), and apps that trust a CA you install and don't pin
  (via 2), and non-pinned apps under a key logger (via 3).
- **Cannot:** anything that pins its certificate, QUIC/HTTP3 unless the key log covers it,
  and anything whose keys you do not have. Traffic AL will not and cannot work around this.

## How it is tested

`tools/host-test` captures a real TLS 1.3 session (the client writes an `SSLKEYLOGFILE`,
like an app built with it), embeds the matching keys as a DSB with the same code the app
uses (`core` `decryptCheck`), and checks that `tshark` decrypts the HTTPS request from the
embedded keys alone (`validate_decrypt.py`). The key-log parsing, the DSB format and the
client-random matching have unit tests in `core`.

For phase 12, the host test's TLS request carries a planted email (in the query) and an auth
token (in the header); the `tlsDecrypt` tool decrypts the session, dissects the request, and
the audit's sensitive-data scan flags both, which `validate.sh` asserts. The HPACK decoder
(RFC 7541 vectors), the HTTP/1/2/3 dissector, the sensitive-data rules and the per-app
aggregator all have unit tests in `core`.
