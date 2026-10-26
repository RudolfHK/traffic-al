package io.github.rudolfhk.traffical.core.capture

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CaptureBatchTest {

    private fun record(buffer: ByteBuffer, timestamp: Long, uid: Int, direction: Int, flags: Int, packet: ByteArray) {
        buffer.putLong(timestamp).putInt(uid).putShort(packet.size.toShort())
            .put(direction.toByte()).put(flags.toByte()).put(packet)
    }

    @Test
    fun `decodes records in little-endian order`() {
        val buffer = ByteBuffer.allocate(2 * CaptureBatch.HEADER_SIZE + 3 + 2).order(ByteOrder.LITTLE_ENDIAN)
        record(buffer, 1_700_000_000_000_001L, 10123, 1, 0, byteArrayOf(1, 2, 3))
        record(buffer, 1_700_000_000_000_002L, -1, 0, 1, byteArrayOf(4, 5))

        val records = CaptureBatch.decode(buffer.array(), ByteOrder.LITTLE_ENDIAN).map { it as CaptureRecord }

        assertEquals(2, records.size)
        assertEquals(1_700_000_000_000_001L, records[0].timestampMicros)
        assertEquals(10123, records[0].uid)
        assertEquals(Direction.OUT, records[0].direction)
        assertFalse(records[0].blocked)
        assertContentEquals(byteArrayOf(1, 2, 3), records[0].packet)
        assertEquals(CaptureBatch.UID_UNKNOWN, records[1].uid)
        assertEquals(Direction.IN, records[1].direction)
        assertTrue(records[1].blocked)
    }

    @Test
    fun `decodes flow info records`() {
        val strings = listOf("QUIC.YouTube", "Media", "rr1.googlevideo.com").map { it.toByteArray() }
        val info = ByteBuffer.allocate(44 + strings.sumOf { it.size + 1 }).order(ByteOrder.LITTLE_ENDIAN)
        info.put(4).put(17).putShort(40000.toShort()).putShort(443)
        info.put(byteArrayOf(10, 0, 0, 1)).put(ByteArray(12))
        info.put(byteArrayOf(142.toByte(), 250.toByte(), 1, 1)).put(ByteArray(12))
        info.putShort(188).putShort(124).putShort(1)
        strings.forEach { info.put(it.size.toByte()).put(it) }

        val buffer = ByteBuffer.allocate(CaptureBatch.HEADER_SIZE + info.capacity()).order(ByteOrder.LITTLE_ENDIAN)
        record(buffer, 5, 10123, 2, 0, info.array())
        val detection = CaptureBatch.decode(buffer.array(), ByteOrder.LITTLE_ENDIAN).single() as FlowDetection

        assertEquals(10123, detection.uid)
        assertEquals(17, detection.protocol)
        assertEquals("10.0.0.1", detection.localAddress.hostAddress)
        assertEquals(40000, detection.localPort)
        assertEquals("142.250.1.1", detection.remoteAddress.hostAddress)
        assertEquals(443, detection.remotePort)
        assertEquals(188, detection.masterProtocolId)
        assertEquals("QUIC.YouTube", detection.protocolName)
        assertEquals("Media", detection.categoryName)
        assertEquals("rr1.googlevideo.com", detection.serverName)
    }

    @Test
    fun `rejects truncated batches`() {
        val buffer = ByteBuffer.allocate(CaptureBatch.HEADER_SIZE + 3).order(ByteOrder.LITTLE_ENDIAN)
        record(buffer, 1, 1, 1, 0, byteArrayOf(1, 2, 3))
        val batch = buffer.array()

        assertFailsWith<IllegalArgumentException> {
            CaptureBatch.decode(batch.copyOf(batch.size - 1), ByteOrder.LITTLE_ENDIAN)
        }
        assertFailsWith<IllegalArgumentException> {
            CaptureBatch.decode(batch.copyOf(batch.size + 5), ByteOrder.LITTLE_ENDIAN)
        }
    }
}
