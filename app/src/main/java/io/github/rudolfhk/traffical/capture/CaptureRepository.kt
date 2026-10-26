package io.github.rudolfhk.traffical.capture

import androidx.annotation.StringRes
import io.github.rudolfhk.traffical.core.pcap.PcapngWriter
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicLong

data class CaptureStatus(
    val running: Boolean = false,
    val startedAtMillis: Long = 0L,
    @StringRes val errorRes: Int? = null,
)

data class DnsEvent(
    val id: Long,
    val timestampMillis: Long,
    val app: AppInfo,
    val domain: String,
    val queryType: String,
    val answers: List<String>,
    /** DNS response code, or null if no upstream server answered. */
    val rcode: Int?,
    val latencyMillis: Long,
)

private class CapturedPacket(val timestampMicros: Long, val data: ByteArray, val comment: String?)

/**
 * In-memory capture state shared by the VPN service (writer) and the UI (reader).
 * Phase 2a keeps everything in memory; persistent, encrypted storage follows in a later phase.
 */
object CaptureRepository {
    private const val MAX_EVENTS = 5_000
    private const val MAX_PACKETS = 20_000

    private val _status = MutableStateFlow(CaptureStatus())
    val status: StateFlow<CaptureStatus> = _status.asStateFlow()

    private val _events = MutableStateFlow<List<DnsEvent>>(emptyList())

    /** Newest first. */
    val events: StateFlow<List<DnsEvent>> = _events.asStateFlow()

    private val _packetCount = MutableStateFlow(0)
    val packetCount: StateFlow<Int> = _packetCount.asStateFlow()

    private val packets = ArrayDeque<CapturedPacket>()
    private val eventIds = AtomicLong()

    fun onStarted() {
        _status.value = CaptureStatus(running = true, startedAtMillis = System.currentTimeMillis())
    }

    fun onStopped(@StringRes errorRes: Int? = null) {
        _status.update { it.copy(running = false, errorRes = errorRes ?: it.errorRes) }
    }

    fun nextEventId(): Long = eventIds.incrementAndGet()

    fun addEvent(event: DnsEvent) {
        _events.update { current -> listOf(event) + current.take(MAX_EVENTS - 1) }
    }

    fun recordPacket(data: ByteArray, timestampMicros: Long, comment: String?) {
        synchronized(packets) {
            packets.addLast(CapturedPacket(timestampMicros, data, comment))
            if (packets.size > MAX_PACKETS) packets.removeFirst()
            _packetCount.value = packets.size
        }
    }

    /** Writes all buffered packets as PCAPNG and closes [out]. Returns the packet count. */
    fun exportPcapng(out: OutputStream): Int {
        val snapshot = synchronized(packets) { packets.toList() }.sortedBy { it.timestampMicros }
        PcapngWriter(out.buffered()).use { writer ->
            for (packet in snapshot) writer.writePacket(packet.timestampMicros, packet.data, comment = packet.comment)
        }
        return snapshot.size
    }

    fun clear() {
        synchronized(packets) {
            packets.clear()
            _packetCount.value = 0
        }
        _events.value = emptyList()
    }
}
