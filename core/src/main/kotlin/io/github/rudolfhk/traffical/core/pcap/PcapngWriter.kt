package io.github.rudolfhk.traffical.core.pcap

import java.io.Closeable
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
    private val snapLength: Int = 65535,
    application: String = "traffic-al",
    interfaceName: String = "tun",
) : Closeable {

    init {
        writeSectionHeader(application)
        writeInterfaceDescription(interfaceName)
    }

    /** Writes one packet; [comment] shows up as the packet comment in Wireshark. */
    fun writePacket(
        timestampMicros: Long,
        data: ByteArray,
        offset: Int = 0,
        length: Int = data.size - offset,
        comment: String? = null,
    ) {
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
    }

    fun flush() = out.flush()

    override fun close() = out.close()

    private fun writeSectionHeader(application: String) {
        val options = listOf(SHB_USERAPPL to application.toByteArray(Charsets.UTF_8))
        val block = block(BLOCK_SECTION_HEADER, 16 + optionsLength(options))
        block.putInt(BYTE_ORDER_MAGIC)
        block.putShort(1) // major version
        block.putShort(0) // minor version
        block.putLong(-1) // section length unknown
        putOptions(block, options)
        finish(block)
    }

    private fun writeInterfaceDescription(name: String) {
        val options = listOf(IF_NAME to name.toByteArray(Charsets.UTF_8))
        val block = block(BLOCK_INTERFACE_DESCRIPTION, 8 + optionsLength(options))
        block.putShort(LINKTYPE_RAW.toShort())
        block.putShort(0) // reserved
        block.putInt(snapLength)
        putOptions(block, options)
        finish(block)
    }

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
        out.write(block.array())
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

    companion object {
        const val LINKTYPE_RAW = 101

        private const val BLOCK_SECTION_HEADER = 0x0A0D0D0A
        private const val BLOCK_INTERFACE_DESCRIPTION = 0x00000001
        private const val BLOCK_ENHANCED_PACKET = 0x00000006
        private const val BYTE_ORDER_MAGIC = 0x1A2B3C4D

        private const val OPT_COMMENT = 1
        private const val SHB_USERAPPL = 4
        private const val IF_NAME = 2
    }
}
