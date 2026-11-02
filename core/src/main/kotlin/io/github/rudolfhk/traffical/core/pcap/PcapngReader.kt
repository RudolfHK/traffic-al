package io.github.rudolfhk.traffical.core.pcap

import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** One packet read back from a PCAPNG file (see [PcapngReader]). */
class RecordedPacket(
    val timestampMicros: Long,
    /** [Pcapng.DIR_OUTBOUND], [Pcapng.DIR_INBOUND] or [Pcapng.DIR_UNKNOWN] (from epb_flags). */
    val direction: Int,
    /** The raw IP packet (truncated to the snap length if the capture was). */
    val data: ByteArray,
    /** The packet comment, e.g. "uid=10123 app=com.example". */
    val comment: String?,
)

/**
 * Reads the enhanced packet blocks of a PCAPNG stream (one or several sections, as the
 * app's recordings store them), so a recording can be replayed in the app. The counterpart
 * of [PcapngWriter]; it ignores section/interface headers and decryption-secrets blocks,
 * and stops at the first truncated or malformed block (a segment cut off by a killed
 * capture), returning what it read up to there.
 */
object PcapngReader {
    private const val OPT_COMMENT = 1
    private const val EPB_FLAGS = 2
    private const val MAX_BLOCK_LENGTH = 1 shl 20

    fun read(input: InputStream): List<RecordedPacket> {
        val packets = ArrayList<RecordedPacket>()
        forEach(input) { packets += it }
        return packets
    }

    /** Calls [onPacket] for each packet, without holding them all; stops like [read]. */
    fun forEach(input: InputStream, onPacket: (RecordedPacket) -> Unit) {
        val header = ByteArray(8)
        var order = ByteOrder.LITTLE_ENDIAN
        while (true) {
            if (!readFully(input, header, 0, 8)) return
            // The block type of a section header reads the same in both byte orders.
            val typeLe = int(header, 0, ByteOrder.LITTLE_ENDIAN)
            if (typeLe == Pcapng.BLOCK_SECTION_HEADER) order = ByteOrder.LITTLE_ENDIAN
            val type = int(header, 0, order)
            val length = int(header, 4, order)
            if (length < 12 || length % 4 != 0 || length > MAX_BLOCK_LENGTH) return
            val block = header.copyOf(length)
            if (!readFully(input, block, 8, length - 8)) return
            if (int(block, length - 4, order) != length) return // trailing length must match
            if (type == Pcapng.BLOCK_ENHANCED_PACKET) parsePacket(block, length, order)?.let(onPacket)
        }
    }

    private fun parsePacket(block: ByteArray, length: Int, order: ByteOrder): RecordedPacket? {
        if (length < 8 + 20 + 4) return null
        val tsHigh = int(block, 12, order).toLong() and 0xffffffffL
        val tsLow = int(block, 16, order).toLong() and 0xffffffffL
        val captured = int(block, 20, order)
        // 8 block header + interface id(4) + ts high(4) + ts low(4) + captured(4) + original(4)
        val dataStart = 28
        val dataEnd = dataStart + captured
        if (captured < 0 || dataEnd > length - 4) return null

        var direction = Pcapng.DIR_UNKNOWN
        var comment: String? = null
        var pos = dataStart + ((captured + 3) and 3.inv()) // options follow the padded data
        val optionsEnd = length - 4
        while (pos + 4 <= optionsEnd) {
            val code = short(block, pos, order)
            val len = short(block, pos + 2, order)
            pos += 4
            if (code == 0 || pos + len > optionsEnd) break
            when (code) {
                OPT_COMMENT -> comment = String(block, pos, len, Charsets.UTF_8)
                EPB_FLAGS -> if (len >= 4) direction = int(block, pos, order) and 0x3
            }
            pos += (len + 3) and 3.inv()
        }
        return RecordedPacket((tsHigh shl 32) or tsLow, direction, block.copyOfRange(dataStart, dataEnd), comment)
    }

    private fun readFully(input: InputStream, buffer: ByteArray, offset: Int, length: Int): Boolean {
        var total = 0
        try {
            while (total < length) {
                val n = input.read(buffer, offset + total, length - total)
                if (n < 0) return false
                total += n
            }
        } catch (e: IOException) {
            return false // e.g. a segment that fails to decrypt: keep what was read before it
        }
        return true
    }

    private fun int(b: ByteArray, i: Int, order: ByteOrder) = ByteBuffer.wrap(b, i, 4).order(order).int
    private fun short(b: ByteArray, i: Int, order: ByteOrder) = ByteBuffer.wrap(b, i, 2).order(order).short.toInt() and 0xffff
}
