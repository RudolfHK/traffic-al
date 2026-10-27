package io.github.rudolfhk.traffical.core.pcap

import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal PCAPNG writer (one section, one interface) producing files that open in
 * Wireshark/tshark. Packets are raw IP packets ([LINKTYPE_RAW]) as read from a TUN device.
 * Timestamps are microseconds since the Unix epoch (the PCAPNG default resolution).
 */
class PcapngWriter(
    private val out: OutputStream,
    private val snapLength: Int = Pcapng.SNAP_LENGTH,
    application: String = Pcapng.APPLICATION,
    interfaceName: String = Pcapng.INTERFACE,
) : Closeable {

    init {
        out.write(Pcapng.header(application, interfaceName, snapLength))
    }

    /**
     * Writes a TLS key-log Decryption Secrets Block. Wireshark uses it to decrypt the TLS
     * sessions these keys belong to. Call it right after construction, before the packets:
     * a DSB applies to the packets that follow it. Does nothing for an empty key log.
     */
    fun writeTlsKeyLog(keyLog: String) {
        if (keyLog.isEmpty()) return
        out.write(Pcapng.tlsKeyLog(keyLog))
    }

    /** Writes one packet; [comment] shows up as the packet comment in Wireshark. */
    fun writePacket(
        timestampMicros: Long,
        data: ByteArray,
        offset: Int = 0,
        length: Int = data.size - offset,
        comment: String? = null,
    ) {
        out.write(Pcapng.packet(timestampMicros, data, offset, length, comment, snapLength))
    }

    fun flush() = out.flush()

    override fun close() = out.close()

    companion object {
        const val LINKTYPE_RAW = Pcapng.LINKTYPE_RAW
    }
}

/**
 * PCAPNG blocks as byte arrays: [header] (section header + interface description) starts
 * a section, [packet] is one enhanced packet block. A file may hold several sections, so
 * complete files can simply be concatenated.
 */
object Pcapng {
    const val LINKTYPE_RAW = 101
    const val SNAP_LENGTH = 65535
    const val APPLICATION = "traffic-al"
    const val INTERFACE = "tun"

    const val BLOCK_SECTION_HEADER = 0x0A0D0D0A
    const val BLOCK_INTERFACE_DESCRIPTION = 0x00000001
    const val BLOCK_ENHANCED_PACKET = 0x00000006
    const val BLOCK_DECRYPTION_SECRETS = 0x0000000A
    private const val BYTE_ORDER_MAGIC = 0x1A2B3C4D

    /** "TLSK": the secrets are an NSS key log (see [io.github.rudolfhk.traffical.core.tls.TlsKeyLog]). */
    const val SECRETS_TYPE_TLS_KEY_LOG = 0x544C534B

    private const val OPT_COMMENT = 1
    private const val SHB_USERAPPL = 4
    private const val IF_NAME = 2

    fun header(application: String = APPLICATION, interfaceName: String = INTERFACE, snapLength: Int = SNAP_LENGTH): ByteArray {
        val shbOptions = listOf(SHB_USERAPPL to application.toByteArray(Charsets.UTF_8))
        val shb = block(BLOCK_SECTION_HEADER, 16 + optionsLength(shbOptions))
        shb.putInt(BYTE_ORDER_MAGIC)
        shb.putShort(1) // major version
        shb.putShort(0) // minor version
        shb.putLong(-1) // section length unknown
        putOptions(shb, shbOptions)
        finish(shb)

        val idbOptions = listOf(IF_NAME to interfaceName.toByteArray(Charsets.UTF_8))
        val idb = block(BLOCK_INTERFACE_DESCRIPTION, 8 + optionsLength(idbOptions))
        idb.putShort(LINKTYPE_RAW.toShort())
        idb.putShort(0) // reserved
        idb.putInt(snapLength)
        putOptions(idb, idbOptions)
        finish(idb)

        return shb.array() + idb.array()
    }

    fun packet(
        timestampMicros: Long,
        data: ByteArray,
        offset: Int = 0,
        length: Int = data.size - offset,
        comment: String? = null,
        snapLength: Int = SNAP_LENGTH,
    ): ByteArray {
        val captured = minOf(length, snapLength)
        val options = comment?.let { listOf(OPT_COMMENT to it.toByteArray(Charsets.UTF_8)) }.orEmpty()
        val block = block(BLOCK_ENHANCED_PACKET, 20 + padded(captured) + optionsLength(options))
        block.putInt(0) // interface id
        block.putInt((timestampMicros ushr 32).toInt())
        block.putInt(timestampMicros.toInt())
        block.putInt(captured)
        block.putInt(length)
        block.put(data, offset, captured)
        pad(block, captured)
        putOptions(block, options)
        finish(block)
        return block.array()
    }

    /** A Decryption Secrets Block carrying an NSS TLS key log (UTF-8/ASCII text). */
    fun tlsKeyLog(keyLog: String): ByteArray = decryptionSecrets(SECRETS_TYPE_TLS_KEY_LOG, keyLog.toByteArray(Charsets.US_ASCII))

    private fun decryptionSecrets(secretsType: Int, data: ByteArray): ByteArray {
        val block = block(BLOCK_DECRYPTION_SECRETS, 8 + padded(data.size))
        block.putInt(secretsType)
        block.putInt(data.size)
        block.put(data)
        pad(block, data.size)
        finish(block)
        return block.array()
    }

    /** Result of [copyBlocks]. */
    data class BlockCopy(val bytes: Long, val packets: Long, val complete: Boolean)

    /**
     * Copies whole blocks from [input] to [out] up to the end of [input]. Stops at a block
     * that is cut off or malformed, or when reading fails (e.g. encrypted data that does not
     * authenticate); [BlockCopy.complete] is false then. Write errors are thrown.
     */
    fun copyBlocks(input: InputStream, out: OutputStream): BlockCopy {
        val reader = BlockReader(input)
        var bytes = 0L
        var packets = 0L
        val header = ByteArray(8)
        while (true) {
            val read = reader.read(header, 0, header.size)
            if (read < header.size) return BlockCopy(bytes, packets, complete = read == 0 && !reader.failed)
            val fields = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
            val type = fields.getInt(0)
            val length = fields.getInt(4)
            if (length < 12 || length % 4 != 0 || length > MAX_BLOCK_LENGTH) return BlockCopy(bytes, packets, complete = false)
            val block = header.copyOf(length)
            if (reader.read(block, header.size, length - header.size) < length - header.size) {
                return BlockCopy(bytes, packets, complete = false)
            }
            if (ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN).getInt(length - 4) != length) {
                return BlockCopy(bytes, packets, complete = false)
            }
            out.write(block)
            bytes += length
            if (type == BLOCK_ENHANCED_PACKET) packets++
        }
    }

    /** Reads fully; a read error ends the input like the end of the stream, but is remembered. */
    private class BlockReader(private val input: InputStream) {
        var failed = false
            private set

        fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            var total = 0
            try {
                while (total < length) {
                    val n = input.read(buffer, offset + total, length - total)
                    if (n < 0) break
                    total += n
                }
            } catch (e: IOException) {
                failed = true
            }
            return total
        }
    }

    private const val MAX_BLOCK_LENGTH = 1 shl 20

    private fun block(type: Int, bodyLength: Int): ByteBuffer {
        val total = 12 + bodyLength
        return ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(type)
            putInt(total)
        }
    }

    private fun finish(block: ByteBuffer) {
        block.putInt(block.capacity())
        check(!block.hasRemaining()) { "PCAPNG block size mismatch" }
    }

    private fun optionsLength(options: List<Pair<Int, ByteArray>>): Int =
        if (options.isEmpty()) 0 else options.sumOf { 4 + padded(it.second.size) } + 4

    private fun putOptions(block: ByteBuffer, options: List<Pair<Int, ByteArray>>) {
        if (options.isEmpty()) return
        for ((code, value) in options) {
            block.putShort(code.toShort())
            block.putShort(value.size.toShort())
            block.put(value)
            pad(block, value.size)
        }
        block.putInt(0) // opt_endofopt
    }

    private fun pad(block: ByteBuffer, length: Int) {
        repeat(padded(length) - length) { block.put(0.toByte()) }
    }

    private fun padded(length: Int) = (length + 3) and 3.inv()
}
