package io.github.rudolfhk.traffical.core.pcap

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

class PcapngReaderTest {

    private fun write(block: PcapngWriter.() -> Unit): ByteArray {
        val out = ByteArrayOutputStream()
        PcapngWriter(out).use(block)
        return out.toByteArray()
    }

    @Test
    fun `reads back timestamp, direction, comment and data`() {
        val a = byteArrayOf(0x45, 1, 2, 3)
        val b = byteArrayOf(0x45, 9, 8, 7, 6)
        val bytes = write {
            writePacket(1_700_000_000_123_456L, a, comment = "uid=10123 app=com.example", direction = Pcapng.DIR_OUTBOUND)
            writePacket(1_700_000_001_000_000L, b, comment = "uid=0 app=android", direction = Pcapng.DIR_INBOUND)
        }
        val packets = PcapngReader.read(ByteArrayInputStream(bytes))

        assertEquals(2, packets.size)
        assertEquals(1_700_000_000_123_456L, packets[0].timestampMicros)
        assertEquals(Pcapng.DIR_OUTBOUND, packets[0].direction)
        assertEquals("uid=10123 app=com.example", packets[0].comment)
        assertContentEquals(a, packets[0].data)
        assertEquals(Pcapng.DIR_INBOUND, packets[1].direction)
        assertContentEquals(b, packets[1].data)
    }

    @Test
    fun `packet without epb_flags or comment reads as unknown direction`() {
        val packets = PcapngReader.read(ByteArrayInputStream(write { writePacket(5L, ByteArray(10)) }))
        assertEquals(Pcapng.DIR_UNKNOWN, packets.single().direction)
        assertNull(packets.single().comment)
    }

    @Test
    fun `reads packets across several concatenated sections`() {
        val first = write { writePacket(1L, byteArrayOf(0x45, 1), direction = Pcapng.DIR_OUTBOUND) }
        val second = write {
            writePacket(2L, byteArrayOf(0x45, 2), direction = Pcapng.DIR_INBOUND)
            writePacket(3L, byteArrayOf(0x45, 3), direction = Pcapng.DIR_INBOUND)
        }
        val packets = PcapngReader.read(ByteArrayInputStream(first + second))
        assertEquals(listOf(1L, 2L, 3L), packets.map { it.timestampMicros })
    }

    @Test
    fun `stops cleanly at a truncated block`() {
        val bytes = write {
            writePacket(1L, byteArrayOf(0x45, 1), direction = Pcapng.DIR_OUTBOUND)
            writePacket(2L, byteArrayOf(0x45, 2), direction = Pcapng.DIR_OUTBOUND)
        }
        // Cut the file in the middle of the second packet block (a killed capture).
        val packets = PcapngReader.read(ByteArrayInputStream(bytes.copyOf(bytes.size - 6)))
        assertEquals(listOf(1L), packets.map { it.timestampMicros })
    }
}
