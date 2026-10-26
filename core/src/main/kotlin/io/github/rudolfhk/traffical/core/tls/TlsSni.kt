package io.github.rudolfhk.traffical.core.tls

sealed interface SniResult {
    data class Found(val hostname: String) : SniResult

    /** Not a TLS ClientHello, or one without a server_name extension. */
    data object Absent : SniResult

    /** Looks like a ClientHello, but more bytes are needed. */
    data object Incomplete : SniResult
}

/** Extracts the Server Name Indication (RFC 6066) from the first bytes a TLS client sends. */
object TlsSni {
    private const val CONTENT_HANDSHAKE = 0x16
    private const val HANDSHAKE_CLIENT_HELLO = 1
    private const val EXTENSION_SERVER_NAME = 0
    private const val NAME_TYPE_HOST = 0

    fun parse(buf: ByteArray, offset: Int = 0, length: Int = buf.size - offset): SniResult {
        if (length < 1) return SniResult.Incomplete
        if (buf[offset].toInt() and 0xff != CONTENT_HANDSHAKE) return SniResult.Absent
        if (length < 9) return SniResult.Incomplete

        val recordEnd = offset + 5 + u16(buf, offset + 3)
        val available = offset + length
        if (buf[offset + 5].toInt() and 0xff != HANDSHAKE_CLIENT_HELLO) return SniResult.Absent

        return try {
            Reader(buf, offset + 9, minOf(recordEnd, available)).serverName()
        } catch (outOfData: OutOfData) {
            if (available < recordEnd) SniResult.Incomplete else SniResult.Absent
        }
    }

    private class OutOfData : Exception()

    private class Reader(private val buf: ByteArray, private var pos: Int, private val end: Int) {

        fun serverName(): SniResult {
            skip(2 + 32) // client_version, random
            skip(u8()) // session_id
            skip(u16()) // cipher_suites
            skip(u8()) // compression_methods
            if (pos == end) return SniResult.Absent // no extensions

            val extensionsEnd = pos + 2 + u16()
            while (pos < extensionsEnd) {
                val type = u16()
                val extensionLength = u16()
                if (type != EXTENSION_SERVER_NAME) {
                    skip(extensionLength)
                    continue
                }
                val listEnd = pos + 2 + u16()
                while (pos < listEnd) {
                    val nameType = u8()
                    val nameLength = u16()
                    need(nameLength)
                    if (nameType == NAME_TYPE_HOST) {
                        val name = String(buf, pos, nameLength, Charsets.US_ASCII)
                        return if (name.isNotEmpty() && name.all { it in '!'..'~' }) {
                            SniResult.Found(name.lowercase())
                        } else {
                            SniResult.Absent
                        }
                    }
                    pos += nameLength
                }
                return SniResult.Absent
            }
            return SniResult.Absent
        }

        private fun u8(): Int {
            need(1)
            return buf[pos++].toInt() and 0xff
        }

        private fun u16(): Int {
            need(2)
            val value = u16(buf, pos)
            pos += 2
            return value
        }

        private fun skip(count: Int) {
            need(count)
            pos += count
        }

        private fun need(count: Int) {
            if (pos + count > end) throw OutOfData()
        }
    }

    private fun u16(buf: ByteArray, index: Int) =
        ((buf[index].toInt() and 0xff) shl 8) or (buf[index + 1].toInt() and 0xff)
}
