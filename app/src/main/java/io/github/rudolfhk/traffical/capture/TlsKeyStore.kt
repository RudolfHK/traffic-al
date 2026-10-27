package io.github.rudolfhk.traffical.capture

import android.content.Context
import android.util.Log
import io.github.rudolfhk.traffical.core.tls.TlsKeyLog
import java.io.File

/**
 * The TLS key log the device owner supplies so recordings can be opened decrypted in
 * Wireshark (phase 8, docs/DECRYPTION.md). Traffic AL never derives TLS keys — it only
 * reads a key log the owner places on their own device:
 *
 *  - their own app built to write `SSLKEYLOGFILE`, or
 *  - a key log written by a root tool,
 *
 * copied (via the Files app, `adb push` or root) to [path]. When a recording or capture is
 * exported with this enabled, the keys for the TLS sessions in it are embedded as a PCAPNG
 * Decryption Secrets Block. Nothing here reaches the network, and pinned apps stay opaque.
 */
object TlsKeyStore {
    private const val TAG = "TlsKeyStore"
    private lateinit var file: File

    fun init(context: Context) {
        file = File(context.filesDir, "tls/keylog.txt")
    }

    /** Where the owner places the key log. */
    val path: String get() = file.absolutePath

    /** The key log as text (empty if none was placed or it can't be read). */
    fun text(): String = try {
        if (file.isFile) file.readText() else ""
    } catch (e: Exception) {
        Log.w(TAG, "cannot read the TLS key log", e)
        ""
    }

    /** How many TLS sessions the key log covers, for the settings screen. */
    fun sessionCount(): Int = TlsKeyLog.parse(text()).sessions.size
}
