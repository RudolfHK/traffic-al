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
import io.github.rudolfhk.traffical.core.recording.ExportResult
import io.github.rudolfhk.traffical.history.History
import io.github.rudolfhk.traffical.history.HistoryStore
import io.github.rudolfhk.traffical.history.StoredLookup
import io.github.rudolfhk.traffical.model.AppInfo
import io.github.rudolfhk.traffical.model.Connection
import io.github.rudolfhk.traffical.model.DnsEvent
import io.github.rudolfhk.traffical.model.RecorderStatus
import io.github.rudolfhk.traffical.model.RecordingItem
import io.github.rudolfhk.traffical.security.Keys
import io.github.rudolfhk.traffical.settings.SettingsStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.File
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
    /** Android runs the capture as always-on VPN. */
    val alwaysOn: Boolean = false,
)

/**
 * Capture state shared by the VPN service (writer, on the capture thread) and the UI.
 * Connections and DNS lookups are kept in memory and saved to the encrypted history
 * database every few seconds; the packets go to the recorder (encrypted recordings).
 */
object CaptureRepository {
    private const val MAX_DNS_EVENTS = 5_000
    private const val MAX_CONNECTIONS_SHOWN = 2_000
    private const val MAX_BUFFERED_BYTES = 64L * 1024 * 1024
    private const val SETTINGS_DEBOUNCE_MILLIS = 800L
    private const val SAVE_INTERVAL_MILLIS = 10_000L

    /** Flows seen this long before the last save are saved again (late nDPI results). */
    private const val SAVE_OVERLAP_MICROS = 60_000_000L

    private val _status = MutableStateFlow(CaptureStatus())
    val status: StateFlow<CaptureStatus> = _status.asStateFlow()

    private val _connections = MutableStateFlow<List<Connection>>(emptyList())

    /** Most recently active first. Only kept up to date while someone collects it. */
    val connections: StateFlow<List<Connection>> = _connections.asStateFlow()

    private val _dnsEvents = MutableStateFlow<List<DnsEvent>>(emptyList())

    /** Newest first. */
    val dnsEvents: StateFlow<List<DnsEvent>> = _dnsEvents.asStateFlow()

    private val _packetCount = MutableStateFlow(0)
    val packetCount: StateFlow<Int> = _packetCount.asStateFlow()

    private lateinit var apps: AppResolver
    private lateinit var recorder: CaptureRecorder
    private lateinit var history: HistoryStore
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val lock = Any()

    // Ids start at the current time in microseconds, so they never repeat those of
    // connections and lookups stored by earlier runs.
    private val tracker = FlowTracker(firstFlowId = System.currentTimeMillis() * 1000)
    private val eventIds = AtomicLong(System.currentTimeMillis() * 1000)

    private val timeline = TrafficTimeline()
    private val packets = ArrayDeque<CaptureRecord>()
    private var bufferedBytes = 0L

    /** Connections of earlier runs, from the history database. */
    private var storedConnections = emptyList<FlowInfo>()
    private val unsavedLookups = ArrayList<StoredLookup>()
    private var savedAtMillis = 0L
    private var savedUpToMicros = 0L

    /** The connection list is stale because nobody watched it during the last batches. */
    @Volatile
    private var connectionsStale = false

    val recorderStatus: StateFlow<RecorderStatus> get() = recorder.status

    fun init(context: Context) {
        synchronized(this) {
            if (::apps.isInitialized) return
            apps = AppResolver(context)
            recorder = CaptureRecorder(File(context.filesDir, "recordings"), { Keys.recordingCodec }, ::packetComment)
            history = HistoryStore(context)
        }
        scope.launch(Dispatchers.IO) { onHistoryLoaded(history.load(MAX_CONNECTIONS_SHOWN).get()) }
        // While the capture runs in the background nobody looks at the connection list, so
        // it is only built when a screen starts collecting it.
        scope.launch {
            _connections.subscriptionCount.collect { subscribers ->
                if (subscribers > 0 && connectionsStale) synchronized(lock) { publishConnections() }
            }
        }
        scope.launch {
            SettingsStore.settings.collectLatest {
                delay(SETTINGS_DEBOUNCE_MILLIS) // e.g. while the UDP host is being typed
                recorder.configure(it)
            }
        }
    }

    fun onStarted(alwaysOn: Boolean) {
        _status.update { CaptureStatus(running = true, startedAtMillis = System.currentTimeMillis(), alwaysOn = alwaysOn) }
        recorder.start(SettingsStore.settings.value)
    }

    fun onStopped(@StringRes errorRes: Int? = null) {
        recorder.stop()
        synchronized(lock) { saveHistory(System.currentTimeMillis()) }
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
        val records = ArrayList<CaptureRecord>(entries.size)
        synchronized(lock) {
            for (entry in entries) {
                tracker.process(entry)?.let { lookups += it.toEvent() }
                if (entry !is CaptureRecord) continue
                records += entry
                timeline.add(entry.timestampMicros, entry.uid, entry.direction == Direction.OUT, entry.packet.size)
                packets.addLast(entry)
                bufferedBytes += entry.packet.size
                while (bufferedBytes > MAX_BUFFERED_BYTES) bufferedBytes -= packets.removeFirst().packet.size
            }
            if (_connections.subscriptionCount.value > 0) publishConnections() else connectionsStale = true
            _packetCount.value = packets.size
            lookups.mapTo(unsavedLookups) { it.toStored() }
            val now = System.currentTimeMillis()
            if (now - savedAtMillis >= SAVE_INTERVAL_MILLIS) saveHistory(now)
        }
        recorder.submit(records)
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
        val now = referenceMicros()
        return synchronized(lock) { buildDashboard(tracker.snapshot(MAX_CONNECTIONS_SHOWN), timeline, range, now) }
    }

    fun appInfo(uid: Int): AppInfo = apps.appInfo(uid)

    /** The packets of [connection] still in the capture buffer, oldest first. */
    fun packetsOf(connection: Connection): List<FlowPacket> =
        synchronized(lock) { flowPackets(connection.flow, packets) }

    /** Writes the packets in memory as PCAPNG with the app per packet, and closes [out]. */
    fun exportPcapng(out: OutputStream): Int {
        val snapshot = synchronized(lock) { packets.toList() }
        PcapngWriter(out.buffered()).use { writer ->
            for (record in snapshot) writer.writePacket(record.timestampMicros, record.packet, comment = packetComment(record))
        }
        return snapshot.size
    }

    /** Saved recordings, newest first. Reads the storage. */
    fun recordings(): List<RecordingItem> {
        val active = recorder.status.value.recording
        return recorder.list().get().map {
            RecordingItem(
                name = it.name,
                startMillis = it.startMillis,
                endMillis = it.endMillis,
                bytes = it.bytes,
                segments = it.segments.size,
                truncated = it.truncated,
                active = it.name == active,
            )
        }
    }

    /** Writes a recording, decrypted, as one PCAPNG file and closes [out]; null if it no longer exists. */
    fun exportRecording(name: String, out: OutputStream): ExportResult? {
        out.buffered().use { buffered ->
            val (store, recording) = recorder.finishedRecording(name).get() ?: return null
            return store.export(recording, buffered)
        }
    }

    fun deleteRecording(name: String): Boolean = recorder.delete(name).get()

    /** Forgets the connections, lookups and packets, in memory and in the history; recordings stay. */
    fun clear() {
        synchronized(lock) {
            tracker.clear()
            timeline.clear()
            packets.clear()
            bufferedBytes = 0
            storedConnections = emptyList()
            unsavedLookups.clear()
            _connections.value = emptyList()
            connectionsStale = false
            _packetCount.value = 0
        }
        _dnsEvents.value = emptyList()
        history.clear()
    }

    /** [clear] and delete every recording (a running capture starts a new one). */
    fun eraseAll() {
        clear()
        recorder.deleteAll().get()
    }

    private fun onHistoryLoaded(loaded: History) {
        synchronized(lock) {
            storedConnections = loaded.connections
            if (_connections.subscriptionCount.value > 0) publishConnections() else connectionsStale = true
        }
        val events = loaded.lookups.map { it.toEvent() }
        _dnsEvents.update { current -> (current + events).distinctBy { it.id }.take(MAX_DNS_EVENTS) }
    }

    /** Hands the connections changed since the last save and the new lookups to the history. Must hold [lock]. */
    private fun saveHistory(nowMillis: Long) {
        val since = savedUpToMicros - SAVE_OVERLAP_MICROS
        history.save(tracker.snapshot().filter { it.lastSeenMicros >= since }, unsavedLookups.toList())
        unsavedLookups.clear()
        savedAtMillis = nowMillis
        savedUpToMicros = nowMillis * 1000
    }

    /** The live connections and those of earlier runs, most recent first. Must hold [lock]. */
    private fun publishConnections() {
        val live = tracker.snapshot(MAX_CONNECTIONS_SHOWN)
        val flows = if (storedConnections.isEmpty()) {
            live
        } else {
            val liveIds = live.mapTo(HashSet()) { it.id }
            (live + storedConnections.filter { it.id !in liveIds })
                .sortedByDescending { it.lastSeenMicros }
                .take(MAX_CONNECTIONS_SHOWN)
        }
        _connections.value = flows.map { Connection(it, apps.appInfo(it.uid)) }
        connectionsStale = false
    }

    /** The packet comment in exported files: which app sent or received it. */
    private fun packetComment(record: CaptureRecord): String? {
        val app = if (record.uid == CaptureBatch.UID_UNKNOWN) null else apps.appInfo(record.uid).describe()
        return if (record.blocked) listOfNotNull(app, "blocked").joinToString(" ") else app
    }

    private fun DnsEvent.toStored() = StoredLookup(
        id = id,
        timestampMillis = timestampMillis,
        uid = app.uid,
        domain = domain,
        queryType = queryType,
        answers = answers,
        rcode = rcode,
        latencyMillis = latencyMillis,
    )

    private fun StoredLookup.toEvent() = DnsEvent(
        id = id,
        timestampMillis = timestampMillis,
        app = apps.appInfo(uid),
        domain = domain,
        queryType = queryType,
        answers = answers,
        rcode = rcode,
        latencyMillis = latencyMillis,
    )

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
