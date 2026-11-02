# keycapture — TLS keys from your own apps (rooted device)

A small [Frida](https://frida.re) key logger for reading the TLS session keys an app on
**your own rooted device** exports, so Traffic AL can show that app's encrypted traffic in
the clear. This is option 3 in [`docs/DECRYPTION.md`](../../docs/DECRYPTION.md): auditing
your own phone — seeing what your own apps actually send inside TLS.

```
keylog.js    Frida script: hooks the app's TLS library and emits NSS SSLKEYLOGFILE lines
capture.py   host runner: loads keylog.js into the app and writes keylog.txt
```

## What it does, and what it does not

It installs a **key-log callback** on the app's TLS library (BoringSSL / OpenSSL — what
Conscrypt, Cronet, Flutter and most Android apps use), via the library's own
`SSL_CTX_set_keylog_callback`. That is the same mechanism curl, Firefox and Chrome use when
you set `SSLKEYLOGFILE`. Each key-log line is sent to your computer and written to
`keylog.txt`.

It does **not**:

- weaken, downgrade or terminate TLS — the app's encryption is unchanged;
- defeat certificate pinning — a pinned app completes its own handshake or none at all, and
  either way you only ever see keys it derived itself;
- touch any process but the one you name.

It is, in short, the app telling you its own keys. Nothing is forged and nothing is
intercepted.

## Requirements

- A rooted device (needed to run `frida-server` and to place the key log where Traffic AL
  reads it).
- `frida-server` running on the device, matching the `frida` version on your computer.
- `pip install frida-tools` on your computer. The device is reached over USB (adb).

## Use

```
# 1. start frida-server on the device (as root), then on your computer:
pip install frida-tools
python tools/keycapture/capture.py <package-name> keylog.txt

# 2. use the app so it makes network connections, then press Ctrl-C.

# 3. put the key log where Traffic AL reads it (needs root):
adb push keylog.txt /data/local/tmp/keylog.txt
adb shell su -c 'cp /data/local/tmp/keylog.txt \
  /data/data/io.github.rudolfhk.traffical/files/tls/keylog.txt'
```

`capture.py` takes a package name (it spawns the app) or the pid/name of an
already-running process. From then on, Traffic AL's connection detail shows the
**Decrypted** section for that app's TLS 1.2/1.3 and QUIC connections, and its exports carry
the keys as a PCAPNG Decryption Secrets Block (see `docs/DECRYPTION.md`).

## Limits

- **Pinned apps stay opaque.** Most banking and messenger apps pin; this does not change
  that, by design.
- **Stripped or hardened apps.** If the app statically links and strips BoringSSL, or detects
  instrumentation, `keylog.js` finds no symbols and emits a `# no TLS keylog symbols` note.
  For those, use [friTap](https://github.com/fkie-cad/friTap) — a maintained tool that finds
  the key material by pattern and handles many hardened apps. It writes the same NSS key-log
  format, so copy its output to the same path.
- **QPACK headers.** QUIC/HTTP-3 request and response *headers* are QPACK-compressed and are
  not decoded in the app; the DATA (body) is readable. Open the recording in Wireshark with
  the exported key log for full HTTP/3.
- **Your device only.** This is for auditing a phone you own and control.
