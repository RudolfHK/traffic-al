package io.github.rudolfhk.traffical.core.capture

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

enum class Direction {
    /** App to network: read from the TUN interface. */
    OUT,

    /** Network to app: written to the TUN interface. */
    IN,
}

/** An entry of a capture batch: a packet or a protocol detection result. */
sealed interface CaptureEntry {
    val timestampMicros: Long

    /** Owning app uid, or [CaptureBatch.UID_UNKNOWN]. */
    val uid: Int
}

/** One packet that crossed the TUN interface, as reported by the native capture engine. */
class CaptureRecord(
    override val timestampMicros: Long,
    override val uid: Int,
    val direction: Direction,
    /** The engine refused to forward this connection. */
    val blocked: Boolean,
    /** Raw IP packet. */
    val packet: ByteArray,
) : CaptureEntry

/**
 * nDPI's classification of a connection, sent once per connection. Local is the app's side.
 */
data class FlowDetection(
    override val timestampMicros: Long,
    override val uid: Int,
    val ipVersion: Int,
    val protocol: Int,
    val localAddress: InetAddress,
    val localPort: Int,
    val remoteAddress: InetAddress,
    val remotePort: Int,
    val masterProtocolId: Int,
    val appProtocolId: Int,
    val categoryId: Int,
    /** E.g. "TLS.YouTube", "DNS", "Unknown". */
    val protocolName: String,
    /** E.g. "Media", "Web". */
    val categoryName: String,
    /** TLS/QUIC SNI, HTTP Host or DNS query; empty if none. */
    val serverName: String,
    /** nDPI's rating of the protocol: "Safe", "Acceptable", "Tracker_Ads", "Dangerous", ... */
    val breed: String = "",
) : CaptureEntry

/**
 * Decodes the batches produced by the native engine (capture_engine.h): a sequence of
 * 16-byte headers (u64 timestamp µs, i32 uid, u16 length, u8 kind, u8 flags) in host byte
 * order, each followed by a raw IP packet or, for kind 2, a capture_flow_info_t.
 */
object CaptureBatch {
    const val HEADER_SIZE = 16
    const val UID_UNKNOWN = -1

    private const val KIND_IN = 0
    private const val KIND_OUT = 1
    private const val KIND_INFO = 2
    private const val FLAG_BLOCKED = 0x01
    private const val FLOW_INFO_SIZE = 44

    fun decode(batch: ByteArray, order: ByteOrder = ByteOrder.nativeOrder()): List<CaptureEntry> {
        val buffer = ByteBuffer.wrap(batch).order(order)
        val entries = ArrayList<CaptureEntry>()
        while (buffer.remaining() >= HEADER_SIZE) {
            val timestamp = buffer.long
            val uid = buffer.int
            val length = buffer.short.toInt() and 0xffff
            val kind = buffer.get().toInt()
            val flags = buffer.get().toInt()
            require(length <= buffer.remaining()) { "Truncated capture record" }
            val payload = ByteArray(length)
            buffer.get(payload)
            entries += when (kind) {
                KIND_IN, KIND_OUT -> CaptureRecord(
                    timestampMicros = timestamp,
                    uid = uid,
                    direction = if (kind == KIND_OUT) Direction.OUT else Direction.IN,
                    blocked = flags and FLAG_BLOCKED != 0,
                    packet = payload,
                )
                KIND_INFO -> decodeFlowInfo(timestamp, uid, ByteBuffer.wrap(payload).order(order))
                else -> throw IllegalArgumentException("Unknown capture record kind $kind")
            }
        }
        require(!buffer.hasRemaining()) { "Trailing bytes after the last capture record" }
        return entries
    }

    private fun decodeFlowInfo(timestamp: Long, uid: Int, info: ByteBuffer): FlowDetection {
        require(info.remaining() >= FLOW_INFO_SIZE) { "Truncated flow info" }
        val ipVersion = info.get().toInt()
        val protocol = info.get().toInt() and 0xff
        val localPort = info.short.toInt() and 0xffff
        val remotePort = info.short.toInt() and 0xffff
        val addressLength = if (ipVersion == 4) 4 else 16
        val local = ByteArray(16).also { info.get(it) }
        val remote = ByteArray(16).also { info.get(it) }
        return FlowDetection(
            timestampMicros = timestamp,
            uid = uid,
            ipVersion = ipVersion,
            protocol = protocol,
            localAddress = InetAddress.getByAddress(local.copyOf(addressLength)),
            localPort = localPort,
            remoteAddress = InetAddress.getByAddress(remote.copyOf(addressLength)),
            remotePort = remotePort,
            masterProtocolId = info.short.toInt() and 0xffff,
            appProtocolId = info.short.toInt() and 0xffff,
            categoryId = info.short.toInt() and 0xffff,
            protocolName = info.string(),
            categoryName = info.string(),
            serverName = info.string(),
            breed = if (info.hasRemaining()) info.string() else "",
        )
    }

    private fun ByteBuffer.string(): String {
        require(hasRemaining()) { "Truncated flow info string" }
        val bytes = ByteArray(get().toInt() and 0xff)
        require(bytes.size <= remaining()) { "Truncated flow info string" }
        get(bytes)
        return String(bytes, Charsets.UTF_8)
    }
}
