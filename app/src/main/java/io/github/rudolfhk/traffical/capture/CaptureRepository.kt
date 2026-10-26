package io.github.rudolfhk.traffical.capture

import android.content.Context
import androidx.annotation.StringRes
import io.github.rudolfhk.traffical.core.analysis.DashboardData
import io.github.rudolfhk.traffical.core.analysis.FlowPacket
import io.github.rudolfhk.traffical.core.analysis.TimeRange
import io.github.rudolfhk.traffical.core.analysis.TrafficTimeline
import io.github.rudolfhk.traffical.core.analysis.dashboard as buildDashboard
import io.github.rudolfhk.traffical.core.analysis.packetsOf as flowPackets
import io.github.rudolfhk.traffical.core.capture.CaptureBatch
import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.capture.Direction
import io.github.rudolfhk.traffical.core.capture.DnsLookup
import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.capture.FlowTracker
import io.github.rudolfhk.traffical.core.dns.DnsType
import io.github.rudolfhk.traffical.core.pcap.PcapngWriter
import io.github.rudolfhk.traffical.model.AppInfo
import io.github.rudolfhk.traffical.model.Connection
import io.github.rudolfhk.traffical.model.DnsEvent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicLong

data class CaptureStatus(
    val running: Boolean = false,
    val startedAtMillis: Long = 0L,
    /** When the last capture stopped; 0 while running or before the first one. */
    val stoppedAtMillis: Long = 0L,
    @StringRes val errorRes: Int? = null,
    /** Hostname of a strict Private DNS provider: lookups are encrypted. */
    val privateDnsStrictHost: String? = null,
    /** Strict Private DNS was switched to automatic by this app and is restored on stop. */
    val privateDnsOverridden: Boolean = false,
)

/**
 * Capture state shared by the VPN service (writer, on the capture thread) and the UI.
 * Everything is kept in memory; encrypted persistent storage is a later phase.
 */
object CaptureRepository {
    private const val MAX_DNS_EVENTS = 5_000
    private const val MAX_CONNECTIONS_SHOWN = 2_000
    private const val MAX_BUFFERED_BYTES = 64L * 1024 * 1024

    private val _status = MutableStateFlow(CaptureStatus())
    val status: StateFlow<CaptureStatus> = _status.asStateFlow()

    private val _connections = MutableStateFlow<List<Connection>>(emptyList())

    /** Most recently active first. */
    val connections: StateFlow<List<Connection>> = _connections.asStateFlow()

    private val _dnsEvents = MutableStateFlow<List<DnsEvent>>(emptyList())

    /** Newest first. */
    val dnsEvents: StateFlow<List<DnsEvent>> = _dnsEvents.asStateFlow()

    private val _packetCount = MutableStateFlow(0)
    val packetCount: StateFlow<Int> = _packetCount.asStateFlow()

    private lateinit var apps: AppResolver
    private val lock = Any()
    private val tracker = FlowTracker()
    private val timeline = TrafficTimeline()
    private val packets = ArrayDeque<CaptureRecord>()
    private var bufferedBytes = 0L
    private val eventIds = AtomicLong()

    fun init(context: Context) = synchronized(this) {
        if (!::apps.isInitialized) apps = AppResolver(context)
    }

    fun onStarted() {
        _status.update { CaptureStatus(running = true, startedAtMillis = System.currentTimeMillis()) }
    }

    fun onStopped(@StringRes errorRes: Int? = null) {
        _status.update {
            it.copy(
                running = false,
                stoppedAtMillis = System.currentTimeMillis(),
                errorRes = errorRes ?: it.errorRes,
                privateDnsOverridden = false,
            )
        }
    }

    fun setError(@StringRes errorRes: Int?) {
        _status.update { it.copy(errorRes = errorRes) }
    }

    fun setPrivateDns(strictHost: String?, overridden: Boolean) {
        _status.update { it.copy(privateDnsStrictHost = strictHost, privateDnsOverridden = overridden) }
    }

    /** Handles one batch of packets and detections of the native engine. Runs on the capture thread. */
    fun onBatch(batch: ByteArray) {
        val entries = CaptureBatch.decode(batch)
        val lookups = ArrayList<DnsEvent>()
        synchronized(lock) {
            for (entry in entries) {
                tracker.process(entry)?.let { lookups += it.toEvent() }
                if (entry !is CaptureRecord) continue
                timeline.add(entry.timestampMicros, entry.uid, entry.direction == Direction.OUT, entry.packet.size)
                packets.addLast(entry)
                bufferedBytes += entry.packet.size
                while (bufferedBytes > MAX_BUFFERED_BYTES) bufferedBytes -= packets.removeFirst().packet.size
            }
            _connections.value = tracker.snapshot(MAX_CONNECTIONS_SHOWN).map { Connection(it, apps.appInfo(it.uid)) }
            _packetCount.value = packets.size
        }
        if (lookups.isNotEmpty()) {
            _dnsEvents.update { current -> (lookups.asReversed() + current).take(MAX_DNS_EVENTS) }
        }
    }

    /**
     * The moment the analysis looks at: now while capturing, otherwise when the capture
     * stopped, so the dashboard of a finished capture does not scroll away.
     */
    fun referenceMicros(): Long {
        val status = _status.value
        val millis = if (status.running || status.stoppedAtMillis == 0L) System.currentTimeMillis() else status.stoppedAtMillis
        return millis * 1000
    }

    /** Totals, throughput and per-app ranking over [range]. Cheap enough to call every second. */
    fun dashboard(range: TimeRange): DashboardData {
        val flows = _connections.value.map { it.flow }
        val now = referenceMicros()
        return synchronized(lock) { buildDashboard(flows, timeline, range, now) }
    }

    fun appInfo(uid: Int): AppInfo = apps.appInfo(uid)

    /** The packets of [connection] still in the capture buffer, oldest first. */
    fun packetsOf(connection: Connection): List<FlowPacket> =
        synchronized(lock) { flowPackets(connection.flow, packets) }

    /** Writes the buffered packets as PCAPNG with the app per packet, and closes [out]. */
    fun exportPcapng(out: OutputStream): Int {
        val snapshot = synchronized(lock) { packets.toList() }
        PcapngWriter(out.buffered()).use { writer ->
            for (record in snapshot) {
                val app = if (record.uid == CaptureBatch.UID_UNKNOWN) null else apps.appInfo(record.uid).describe()
                val comment = if (record.blocked) listOfNotNull(app, "blocked").joinToString(" ") else app
                writer.writePacket(record.timestampMicros, record.packet, comment = comment)
            }
        }
        return snapshot.size
    }

    fun clear() {
        synchronized(lock) {
            tracker.clear()
            timeline.clear()
            packets.clear()
            bufferedBytes = 0
            _connections.value = emptyList()
            _packetCount.value = 0
        }
        _dnsEvents.value = emptyList()
    }

    private fun DnsLookup.toEvent() = DnsEvent(
        id = eventIds.incrementAndGet(),
        timestampMillis = timestampMicros / 1000,
        app = apps.appInfo(uid),
        domain = domain,
        queryType = DnsType.name(type),
        answers = answers,
        rcode = rcode,
        latencyMillis = latencyMicros?.let { it / 1000 },
    )
}
