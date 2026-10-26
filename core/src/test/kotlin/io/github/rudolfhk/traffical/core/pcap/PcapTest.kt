package io.github.rudolfhk.traffical.core.pcap

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class PcapTest {

    @Test
    fun `header is the one PCAPdroid's udp_receiver expects`() {
        // PCAP_HDR_BYTES_PREFIX + PCAP_HDR_BYTES_RAW_SUFFIX from PCAPdroid's tools/udp_receiver.py
        val expected = hex("d4c3b2a1020004000000000000000000" + "ffff000065000000")
        assertContentEquals(expected, Pcap.header())
    }

    @Test
    fun `record holds seconds, microseconds, lengths and the packet`() {
        val packet = ByteArray(40) { it.toByte() }
        val record = ByteBuffer.wrap(Pcap.record(1_700_000_000_123_456L, packet)).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(1_700_000_000, record.getInt(0))
        assertEquals(123_456, record.getInt(4))
        assertEquals(40, record.getInt(8))
        assertEquals(40, record.getInt(12))
        assertContentEquals(packet, record.array().copyOfRange(16, 56))
    }

    @Test
    fun `writer output is header plus packet blocks`() {
        val packet = ByteArray(21) { 1 }
        val out = ByteArrayOutputStream()
        PcapngWriter(out).use { it.writePacket(5L, packet, comment = "x") }
        assertContentEquals(Pcapng.header() + Pcapng.packet(5L, packet, comment = "x"), out.toByteArray())
    }

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
