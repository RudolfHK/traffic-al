package io.github.rudolfhk.traffical.core.capture

import java.nio.ByteBuffer
import java.nio.ByteOrder

enum class Direction {
    /** App to network: read from the TUN interface. */
    OUT,

    /** Network to app: written to the TUN interface. */
    IN,
}

/** One packet that crossed the TUN interface, as reported by the native capture engine. */
class CaptureRecord(
    val timestampMicros: Long,
    /** Owning app uid, or [CaptureBatch.UID_UNKNOWN]. */
    val uid: Int,
    val direction: Direction,
    /** The engine refused to forward this connection. */
    val blocked: Boolean,
    /** Raw IP packet. */
    val packet: ByteArray,
)

/**
 * Decodes the packet batches produced by the native engine (capture_engine.h): a sequence
 * of 16-byte headers (u64 timestamp µs, i32 uid, u16 length, u8 direction, u8 flags) in
 * host byte order, each followed by the raw IP packet.
 */
object CaptureBatch {
    const val HEADER_SIZE = 16
    const val UID_UNKNOWN = -1

    private const val DIRECTION_OUT = 1
    private const val FLAG_BLOCKED = 0x01

    fun decode(batch: ByteArray, order: ByteOrder = ByteOrder.nativeOrder()): List<CaptureRecord> {
        val buffer = ByteBuffer.wrap(batch).order(order)
        val records = ArrayList<CaptureRecord>()
        while (buffer.remaining() >= HEADER_SIZE) {
            val timestamp = buffer.long
            val uid = buffer.int
            val length = buffer.short.toInt() and 0xffff
            val direction = buffer.get().toInt()
            val flags = buffer.get().toInt()
            require(length <= buffer.remaining()) { "Truncated capture record" }
            val packet = ByteArray(length)
            buffer.get(packet)
            records += CaptureRecord(
                timestampMicros = timestamp,
                uid = uid,
                direction = if (direction == DIRECTION_OUT) Direction.OUT else Direction.IN,
                blocked = flags and FLAG_BLOCKED != 0,
                packet = packet,
            )
        }
        require(!buffer.hasRemaining()) { "Trailing bytes after the last capture record" }
        return records
    }
}
