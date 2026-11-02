package io.github.rudolfhk.traffical.core.quic

import io.github.rudolfhk.traffical.core.tls.TlsKeyLog
import java.io.ByteArrayOutputStream

/**
 * Decrypts a QUIC v1 connection's application streams from keys the device owner supplies
 * (the phase-11 key log). It derives the Initial keys from the client's connection ID to
 * read the ClientHello (for the client random), then uses the 1-RTT application traffic
 * secrets from the key log to decrypt the short-header packets, and reassembles the QUIC
 * STREAM frames per stream. The TLS 1.3 cipher suite is found by trying the three QUIC v1
 * suites. Nothing leaves the device.
 *
 * This handles the common case (a single connection, no migration, no key update). HTTP/3
 * and QPACK sit on top of the reassembled streams (see QuicHttp3); packets that do not
 * authenticate are skipped. See docs/DECRYPTION.md.
 */
object QuicDecryptor {

    class Transcript(val clientToServer: ByteArray, val serverToClient: ByteArray, val packets: Int) {
        val isEmpty: Boolean get() = clientToServer.isEmpty() && serverToClient.isEmpty()
    }

    private const val LONG_HEADER = 0x80
    private const val TYPE_INITIAL = 0x00

    fun decrypt(clientDatagrams: List<ByteArray>, serverDatagrams: List<ByteArray>, keyLog: TlsKeyLog): Transcript? {
        // The client's first Initial packet: its DCID derives the Initial keys, its SCID is
        // the connection id the server will use, and its CRYPTO frames hold the ClientHello.
        val firstInitial = clientDatagrams.firstOrNull()?.let { parseLongHeader(it, 0) } ?: return null
        if (firstInitial.type != TYPE_INITIAL) return null
        val (clientInitial, serverInitial) = QuicCrypto.initialKeys(firstInitial.dcid)

        val clientHello = reassembleCrypto(clientDatagrams, clientInitial, TYPE_INITIAL) ?: return null
        // QUIC carries the TLS handshake in CRYPTO frames without the record layer, so the
        // ClientHello starts with the handshake message directly (type 0x01, length, version, random).
        val clientRandom = clientRandomOf(clientHello) ?: return null
        val secrets = keyLog.entries.filter { it.clientRandom == clientRandom }.associate { it.label to it.secret }
        val clientSecret = secrets["CLIENT_TRAFFIC_SECRET_0"]?.let(::hex) ?: return null
        val serverSecret = secrets["SERVER_TRAFFIC_SECRET_0"]?.let(::hex) ?: return null

        // The server's SCID is the DCID of the client's short-header packets, and vice versa.
        val serverScid = serverDatagrams.firstNotNullOfOrNull { parseLongHeader(it, 0)?.scid } ?: ByteArray(0)
        val clientScid = firstInitial.scid

        return try {
            val suite = findSuite(clientDatagrams, clientSecret, serverScid.size) ?: return null
            val toServer = decryptApp(clientDatagrams, QuicCrypto.keysFromSecret(clientSecret, suite), serverScid.size)
            val toClient = decryptApp(serverDatagrams, QuicCrypto.keysFromSecret(serverSecret, suite), clientScid.size)
            Transcript(toServer.first, toClient.first, toServer.second + toClient.second)
        } catch (e: Exception) {
            null
        }
    }

    /** Finds the cipher suite by trying each on the client's first decryptable 1-RTT packet. */
    private fun findSuite(datagrams: List<ByteArray>, secret: ByteArray, dcidLen: Int): QuicCrypto.Suite? {
        for (suite in QuicCrypto.SUITES.values) {
            val keys = QuicCrypto.keysFromSecret(secret, suite)
            for (datagram in datagrams) {
                var off = 0
                while (off < datagram.size) {
                    if (datagram[off].toInt() and LONG_HEADER != 0) {
                        off = skipLongHeaderPacket(datagram, off) ?: break
                        continue
                    }
                    if (decryptShort(datagram, off, keys, dcidLen) != null) return suite
                    break // one short-header packet per datagram, at the end
                }
            }
        }
        return null
    }

    /** Decrypts the short-header packets in [datagrams] and reassembles their STREAM frames. */
    private fun decryptApp(datagrams: List<ByteArray>, keys: QuicCrypto.Keys, dcidLen: Int): Pair<ByteArray, Int> {
        val streams = HashMap<Long, StreamBuffer>()
        var count = 0
        for (datagram in datagrams) {
            var off = 0
            while (off < datagram.size) {
                if (datagram[off].toInt() and LONG_HEADER != 0) {
                    off = skipLongHeaderPacket(datagram, off) ?: break
                    continue
                }
                val plaintext = decryptShort(datagram, off, keys, dcidLen)
                if (plaintext != null) {
                    count++
                    parseFrames(plaintext, streams)
                }
                break
            }
        }
        val out = ByteArrayOutputStream()
        for ((_, buffer) in streams.toSortedMap()) out.write(buffer.assemble())
        return out.toByteArray() to count
    }

    // --- packet decryption -------------------------------------------------------------

    private class LongHeader(val type: Int, val dcid: ByteArray, val scid: ByteArray, val headerEnd: Int, val lengthField: Int, val pnOffset: Int)

    private fun parseLongHeader(datagram: ByteArray, offset: Int): LongHeader? {
        if (offset + 6 > datagram.size || datagram[offset].toInt() and LONG_HEADER == 0) return null
        val type = (datagram[offset].toInt() ushr 4) and 0x03
        var p = offset + 5 // flags(1) + version(4)
        val dcidLen = datagram[p++].toInt() and 0xff
        if (p + dcidLen > datagram.size) return null
        val dcid = datagram.copyOfRange(p, p + dcidLen); p += dcidLen
        val scidLen = datagram[p++].toInt() and 0xff
        if (p + scidLen > datagram.size) return null
        val scid = datagram.copyOfRange(p, p + scidLen); p += scidLen
        if (type == TYPE_INITIAL) {
            val (tokenLen, after) = varint(datagram, p) ?: return null
            p = after + tokenLen.toInt()
        }
        val (length, afterLen) = varint(datagram, p) ?: return null
        return LongHeader(type, dcid, scid, offset, length.toInt(), afterLen)
    }

    private fun skipLongHeaderPacket(datagram: ByteArray, offset: Int): Int? {
        val header = parseLongHeader(datagram, offset) ?: return null
        val end = header.pnOffset + header.lengthField
        return if (end > offset && end <= datagram.size) end else null
    }

    /** Decrypts a short-header (1-RTT) packet at [offset]; null if it does not authenticate. */
    private fun decryptShort(datagram: ByteArray, offset: Int, keys: QuicCrypto.Keys, dcidLen: Int): ByteArray? {
        val pnOffset = offset + 1 + dcidLen
        if (pnOffset + 4 + 16 > datagram.size) return null
        return removeProtectionAndDecrypt(datagram, offset, pnOffset, datagram.size, keys, shortHeader = true)
    }

    private fun removeProtectionAndDecrypt(
        datagram: ByteArray, packetStart: Int, pnOffset: Int, packetEnd: Int, keys: QuicCrypto.Keys, shortHeader: Boolean,
    ): ByteArray? {
        val sample = datagram.copyOfRange(pnOffset + 4, pnOffset + 20)
        val mask = QuicCrypto.headerMask(keys, sample)
        val first = datagram[packetStart].toInt() and 0xff
        val unmaskedFirst = first xor (mask[0].toInt() and (if (shortHeader) 0x1f else 0x0f))
        val pnLen = (unmaskedFirst and 0x03) + 1

        var packetNumber = 0L
        val pnBytes = ByteArray(pnLen)
        for (i in 0 until pnLen) {
            pnBytes[i] = (datagram[pnOffset + i].toInt() xor mask[1 + i].toInt()).toByte()
            packetNumber = (packetNumber shl 8) or (pnBytes[i].toLong() and 0xff)
        }
        val header = datagram.copyOfRange(packetStart, pnOffset + pnLen)
        header[0] = unmaskedFirst.toByte()
        for (i in 0 until pnLen) header[pnOffset - packetStart + i] = pnBytes[i]

        val cipherStart = pnOffset + pnLen
        val cipherLen = packetEnd - cipherStart
        if (cipherLen < 16) return null
        return QuicCrypto.decrypt(keys, packetNumber, header, datagram, cipherStart, cipherLen)
    }

    // --- Initial / CRYPTO reassembly ---------------------------------------------------

    /** Reassembles the CRYPTO frames of the Initial packets into the handshake bytes (the ClientHello). */
    private fun reassembleCrypto(datagrams: List<ByteArray>, keys: QuicCrypto.Keys, type: Int): ByteArray? {
        val crypto = StreamBuffer()
        for (datagram in datagrams) {
            var off = 0
            while (off + 1 < datagram.size) {
                val header = parseLongHeader(datagram, off) ?: break
                if (header.type == type) {
                    val plaintext = removeProtectionAndDecrypt(datagram, off, header.pnOffset, header.pnOffset + header.lengthField, keys, shortHeader = false)
                    if (plaintext != null) parseFrames(plaintext, hashMapOf(), crypto)
                }
                off = skipLongHeaderPacket(datagram, off) ?: break
            }
        }
        val bytes = crypto.assemble()
        return bytes.takeIf { it.isNotEmpty() }
    }

    // --- frames ------------------------------------------------------------------------

    private fun parseFrames(payload: ByteArray, streams: HashMap<Long, StreamBuffer>, crypto: StreamBuffer? = null) {
        var p = 0
        while (p < payload.size) {
            val (frameType, afterType) = varint(payload, p) ?: break
            p = afterType
            when (frameType.toInt()) {
                0x00 -> {} // PADDING
                0x01 -> {} // PING
                0x02, 0x03 -> { // ACK: skip
                    p = skipAck(payload, p, frameType.toInt() == 0x03) ?: break
                }
                0x06 -> { // CRYPTO: offset, length, data
                    val (offset, a1) = varint(payload, p) ?: break
                    val (len, a2) = varint(payload, a1) ?: break
                    val end = a2 + len.toInt()
                    if (end > payload.size) break
                    crypto?.put(offset, payload.copyOfRange(a2, end))
                    p = end
                }
                in 0x08..0x0f -> { // STREAM: type bits = OFF(0x04), LEN(0x02), FIN(0x01)
                    val (streamId, a1) = varint(payload, p) ?: break
                    var q = a1
                    var offset = 0L
                    if (frameType.toInt() and 0x04 != 0) { val (o, a) = varint(payload, q) ?: break; offset = o; q = a }
                    val length: Int
                    if (frameType.toInt() and 0x02 != 0) { val (l, a) = varint(payload, q) ?: break; length = l.toInt(); q = a } else length = payload.size - q
                    val end = q + length
                    if (end > payload.size) break
                    streams.getOrPut(streamId) { StreamBuffer() }.put(offset, payload.copyOfRange(q, end))
                    p = end
                }
                else -> break // an unhandled frame type: stop parsing this packet
            }
        }
    }

    private fun skipAck(payload: ByteArray, start: Int, ecn: Boolean): Int? {
        var p = start
        varint(payload, p)?.let { p = it.second } ?: return null // Largest Acknowledged
        varint(payload, p)?.let { p = it.second } ?: return null // ACK Delay
        val (ranges, a1) = varint(payload, p) ?: return null; p = a1 // ACK Range Count
        varint(payload, p)?.let { p = it.second } ?: return null // First ACK Range
        repeat(ranges.toInt()) {
            varint(payload, p)?.let { p = it.second } ?: return null // Gap
            varint(payload, p)?.let { p = it.second } ?: return null // ACK Range Length
        }
        if (ecn) repeat(3) { varint(payload, p)?.let { p = it.second } ?: return null }
        return p
    }

    /** Reassembles a stream from its offset fragments. */
    private class StreamBuffer {
        private val fragments = sortedMapOf<Long, ByteArray>()
        fun put(offset: Long, data: ByteArray) { if (data.isNotEmpty()) fragments[offset] = data }
        fun assemble(): ByteArray {
            val out = ByteArrayOutputStream()
            var next = 0L
            for ((offset, data) in fragments) {
                if (offset >= next) { out.write(data); next = offset + data.size } // in-order, gap-tolerant
            }
            return out.toByteArray()
        }
    }

    /** A QUIC variable-length integer (RFC 9000 §16): returns (value, nextOffset). */
    private fun varint(buf: ByteArray, offset: Int): Pair<Long, Int>? {
        if (offset >= buf.size) return null
        val first = buf[offset].toInt() and 0xff
        val length = 1 shl (first ushr 6)
        if (offset + length > buf.size) return null
        var value = (first and 0x3f).toLong()
        for (i in 1 until length) value = (value shl 8) or (buf[offset + i].toLong() and 0xff)
        return value to (offset + length)
    }

    /** The client random (lowercase hex) from a QUIC ClientHello handshake message (no record layer). */
    private fun clientRandomOf(handshake: ByteArray): String? {
        if (handshake.size < 6 + 32 || handshake[0].toInt() and 0xff != 0x01) return null // ClientHello
        return handshake.copyOfRange(6, 6 + 32).joinToString("") { "%02x".format(it) }
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }

}
