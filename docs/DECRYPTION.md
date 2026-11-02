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
