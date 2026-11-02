'use strict';
/*
 * Frida script: capture TLS session keys from an app on YOUR OWN rooted device, so Traffic
 * AL can show that app's encrypted traffic (phase 11, docs/DECRYPTION.md). It installs a
 * key-log callback on the app's TLS library (BoringSSL / OpenSSL, as used by Conscrypt,
 * Cronet, Flutter and most apps) and sends each NSS SSLKEYLOGFILE line to the host, where
 * capture.py writes the key log.
 *
 * It reads keys the app itself exports through the standard BoringSSL keylog hook; it does
 * not weaken TLS, defeat pinning, or touch other apps. Apps that strip these symbols or
 * detect instrumentation won't yield keys (use friTap for those: https://github.com/fkie-cad/friTap).
 *
 * Run it with capture.py (preferred) or: frida -U -f <package> -l keylog.js
 */

// BoringSSL/OpenSSL: void SSL_CTX_set_keylog_callback(SSL_CTX*, void (*cb)(const SSL*, const char* line))
function hook(moduleName) {
  var setCb = Module.findExportByName(moduleName, 'SSL_CTX_set_keylog_callback');
  var ctxNew = Module.findExportByName(moduleName, 'SSL_CTX_new');
  if (setCb === null || ctxNew === null) {
    return false;
  }
  var setKeylog = new NativeFunction(setCb, 'void', ['pointer', 'pointer']);
  // The callback the library calls with each key-log line; forward it to the host.
  var callback = new NativeCallback(function (ssl, line) {
    try {
      send(line.readUtf8String());
    } catch (e) {}
  }, 'void', ['pointer', 'pointer']);

  // Every SSL context the app creates gets our key-log callback.
  Interceptor.attach(ctxNew, {
    onLeave: function (retval) {
      if (!retval.isNull()) {
        setKeylog(retval, callback);
      }
    },
  });
  send('# keylog hook installed on ' + moduleName);
  return true;
}

var hooked = false;
['libssl.so', 'libboringssl.so'].forEach(function (name) {
  if (hook(name)) hooked = true;
});
// Apps often bundle their own TLS library (Cronet, Flutter, OpenSSL): try those modules too.
Process.enumerateModules().forEach(function (m) {
  if (/ssl|boringssl|cronet|flutter|openssl/i.test(m.name)) {
    if (hook(m.name)) hooked = true;
  }
});
if (!hooked) {
  send('# no TLS keylog symbols found; this app may be statically stripped or pinned (try friTap)');
}
