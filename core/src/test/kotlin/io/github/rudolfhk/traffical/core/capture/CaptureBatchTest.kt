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

        val records = CaptureBatch.decode(buffer.array(), ByteOrder.LITTLE_ENDIAN)

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
