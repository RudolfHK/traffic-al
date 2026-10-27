package io.github.rudolfhk.traffical.core.tls

/**
 * TLS key material in the NSS **SSLKEYLOGFILE** format, the one Wireshark, curl, Firefox
 * and Chrome read and write. Each line is `<label> <client_random hex> <secret hex>`; the
 * client random identifies the TLS session.
 *
 * Traffic AL never derives these secrets and cannot: they stay inside the TLS endpoints.
 * The device owner supplies them for sessions on their own device — their own app built
 * with `SSLKEYLOGFILE`, or a key log placed with root — and the app only copies the ones
 * that belong to sessions actually in a recording into the file, as a PCAPNG Decryption
 * Secrets Block, so Wireshark can show that traffic decrypted. No key, no plaintext.
 */
class TlsKeyLog private constructor(val entries: List<Entry>) {

    /** One key-log line. [clientRandom] and [secret] are lowercase hex. */
    data class Entry(val label: String, val clientRandom: String, val secret: String) {
        fun format(): String = "$label $clientRandom $secret"
    }

    /** The TLS sessions this key log has secrets for (client randoms, lowercase hex). */
    val sessions: Set<String> by lazy { entries.mapTo(HashSet()) { it.clientRandom } }

    val isEmpty: Boolean get() = entries.isEmpty()

    /** The key-log text for [wanted] sessions only (empty string if none match). */
    fun textFor(wanted: Set<String>): String = text(entries.filter { it.clientRandom in wanted })

    /** The whole key-log text. */
    fun text(): String = text(entries)

    private fun text(lines: List<Entry>): String =
        if (lines.isEmpty()) "" else lines.joinToString("\n", postfix = "\n") { it.format() }

    companion object {
        /** Labels that key material by the 32-byte client random (TLS 1.2 and 1.3). */
        private val LABELS = setOf(
            "CLIENT_RANDOM",
            "CLIENT_EARLY_TRAFFIC_SECRET",
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
            "EARLY_EXPORTER_SECRET",
            "EXPORTER_SECRET",
        )

        fun parse(text: String): TlsKeyLog {
            val entries = ArrayList<Entry>()
            val seen = HashSet<String>()
            for (line in text.lineSequence()) {
                val trimmed = line.trim()
                if (trimmed.isEmpty() || trimmed[0] == '#') continue
                val parts = trimmed.split(' ')
                if (parts.size != 3) continue
                val (label, random, secret) = parts
                if (label !in LABELS || random.length != 64 || !isHex(random) || secret.isEmpty() || !isHex(secret)) continue
                if (seen.add(trimmed)) entries += Entry(label, random.lowercase(), secret.lowercase())
            }
            return TlsKeyLog(entries)
        }

        private fun isHex(s: String): Boolean = s.isNotEmpty() && s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
    }
}

/** The client random of a TLS session, read from the first bytes a client sends. */
object TlsClientHello {
    private const val CONTENT_HANDSHAKE = 0x16
    private const val HANDSHAKE_CLIENT_HELLO = 1
    private const val RANDOM_OFFSET = 11 // record header (5) + handshake header (4) + client_version (2)
    private const val RANDOM_LENGTH = 32
    private val HEX = "0123456789abcdef".toCharArray()

    /**
     * The 32-byte client random as lowercase hex, if [buf] at [offset] begins with a TLS
     * ClientHello; null otherwise. The random sits at a fixed offset, before the
     * variable-length fields, so one packet is always enough.
     */
    fun clientRandom(buf: ByteArray, offset: Int = 0, length: Int = buf.size - offset): String? {
        if (length < RANDOM_OFFSET + RANDOM_LENGTH) return null
        if (buf[offset].toInt() and 0xff != CONTENT_HANDSHAKE) return null
        if (buf[offset + 5].toInt() and 0xff != HANDSHAKE_CLIENT_HELLO) return null
        val start = offset + RANDOM_OFFSET
        val out = CharArray(RANDOM_LENGTH * 2)
        for (i in 0 until RANDOM_LENGTH) {
            val b = buf[start + i].toInt() and 0xff
            out[i * 2] = HEX[b ushr 4]
            out[i * 2 + 1] = HEX[b and 0xf]
        }
        return String(out)
    }
}
