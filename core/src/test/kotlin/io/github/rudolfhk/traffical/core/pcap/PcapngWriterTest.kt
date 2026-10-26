package io.github.rudolfhk.traffical.core.pcap

import io.github.rudolfhk.traffical.core.packet.PacketBuilder
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class PcapngWriterTest {

    @Test
    fun `writes well-formed blocks`() {
        val packet = PacketBuilder.udp(
            InetAddress.getByName("10.0.0.1"), 1234,
            InetAddress.getByName("10.0.0.2"), 53,
            ByteArray(5),
        )
        val out = ByteArrayOutputStream()
        PcapngWriter(out).use {
            it.writePacket(1_700_000_000_123_456L, packet, comment = "com.example.app")
            it.writePacket(1_700_000_001_000_000L, packet)
        }

        val blocks = blocks(out.toByteArray())
        assertEquals(listOf(0x0A0D0D0A, 1, 6, 6), blocks.map { it.first })

        val shb = blocks[0].second
        assertEquals(0x1A2B3C4D, shb.getInt(8))

        val idb = blocks[1].second
        assertEquals(PcapngWriter.LINKTYPE_RAW, idb.getShort(8).toInt())

        val epb = blocks[2].second
        val timestamp = (epb.getInt(12).toLong() shl 32) or (epb.getInt(16).toLong() and 0xffffffffL)
        assertEquals(1_700_000_000_123_456L, timestamp)
        assertEquals(packet.size, epb.getInt(20))
        assertEquals(packet.size, epb.getInt(24))
        val data = ByteArray(packet.size).also { epb.position(28); epb.get(it) }
        assertEquals(packet.toList(), data.toList())
        // Comment option follows the padded packet data.
        val optionStart = 28 + ((packet.size + 3) and 3.inv())
        assertEquals(1, epb.getShort(optionStart).toInt())
        assertEquals("com.example.app".length, epb.getShort(optionStart + 2).toInt())
    }

    @Test
    fun `writer output is header plus packet blocks`() {
        val packet = ByteArray(21) { 1 }
        val out = ByteArrayOutputStream()
        PcapngWriter(out).use { it.writePacket(5L, packet, comment = "x") }
        assertContentEquals(Pcapng.header() + Pcapng.packet(5L, packet, comment = "x"), out.toByteArray())
    }

    /** Splits a PCAPNG file into (type, block) pairs, checking the duplicated length fields. */
    private fun blocks(file: ByteArray): List<Pair<Int, ByteBuffer>> {
        val all = ByteBuffer.wrap(file).order(ByteOrder.LITTLE_ENDIAN)
        val result = mutableListOf<Pair<Int, ByteBuffer>>()
        var pos = 0
        while (pos < file.size) {
            val type = all.getInt(pos)
            val length = all.getInt(pos + 4)
            assertEquals(0, length % 4, "block length must be 32-bit aligned")
            assertEquals(length, all.getInt(pos + length - 4), "trailing block length")
            val block = ByteBuffer.wrap(file, pos, length).slice().order(ByteOrder.LITTLE_ENDIAN)
            result += type to block
            pos += length
        }
        assertEquals(file.size, pos)
        return result
    }
}
