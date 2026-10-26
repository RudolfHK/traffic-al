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
    private val snapLength: Int = Pcapng.SNAP_LENGTH,
    application: String = Pcapng.APPLICATION,
    interfaceName: String = Pcapng.INTERFACE,
) : Closeable {

    init {
        out.write(Pcapng.header(application, interfaceName, snapLength))
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
    private const val BYTE_ORDER_MAGIC = 0x1A2B3C4D

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

/**
 * Classic PCAP (libpcap 2.4, little endian, [Pcapng.LINKTYPE_RAW]) as byte arrays, the
 * format of PCAPdroid's UDP exporter: [header] once, then one [record] per packet.
 */
object Pcap {
    const val HEADER_SIZE = 24
    const val RECORD_HEADER_SIZE = 16
    private const val MAGIC = 0xA1B2C3D4.toInt()

    fun header(snapLength: Int = Pcapng.SNAP_LENGTH): ByteArray =
        ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(MAGIC)
            .putShort(2) // version 2.4
            .putShort(4)
            .putInt(0) // thiszone
            .putInt(0) // sigfigs
            .putInt(snapLength)
            .putInt(Pcapng.LINKTYPE_RAW)
            .array()

    fun record(
        timestampMicros: Long,
        data: ByteArray,
        offset: Int = 0,
        length: Int = data.size - offset,
        snapLength: Int = Pcapng.SNAP_LENGTH,
    ): ByteArray {
        val captured = minOf(length, snapLength)
        return ByteBuffer.allocate(RECORD_HEADER_SIZE + captured).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(Math.floorDiv(timestampMicros, 1_000_000L).toInt())
            .putInt(Math.floorMod(timestampMicros, 1_000_000L).toInt())
            .putInt(captured)
            .putInt(length)
            .put(data, offset, captured)
            .array()
    }
}
