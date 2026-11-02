package io.github.rudolfhk.traffical.core.recording

import io.github.rudolfhk.traffical.core.analysis.DashboardData
import io.github.rudolfhk.traffical.core.analysis.FlowPacket
import io.github.rudolfhk.traffical.core.analysis.TimeRange
import io.github.rudolfhk.traffical.core.analysis.dashboard
import io.github.rudolfhk.traffical.core.analysis.packetsOf
import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.capture.Direction
import io.github.rudolfhk.traffical.core.capture.DnsLookup
import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.capture.FlowTracker
import io.github.rudolfhk.traffical.core.enrichment.Destination
import io.github.rudolfhk.traffical.core.analysis.TrafficTimeline

/**
 * Replays a recording's packets into the same connections, DNS lookups, timeline and
 * dashboard the live capture builds, so a saved recording can be browsed like the live
 * view. Feed every packet (oldest first) with [add]; the flows and the timeline keep the
 * whole recording, while only the newest [bufferLimit] packets are kept for the per-packet
 * detail view, so a huge recording stays within memory.
 *
 * nDPI's classification is not in a recording (it came from the native engine live), so
 * flows here carry the transport protocol and the SNI/DNS name, not the nDPI protocol.
 * Not thread-safe; load on one thread, then read.
 */
class RecordingReplay(private val bufferLimit: Int = 2_000, private val maxConnections: Int = 2_000) {
    private val tracker = FlowTracker(firstFlowId = 1L)
    private val timeline = TrafficTimeline()
    private val buffer = ArrayDeque<CaptureRecord>()
    private val lookups = ArrayList<DnsLookup>()

    var packetCount = 0L
        private set
    var firstMicros = 0L
        private set
    var lastMicros = 0L
        private set

    fun add(record: CaptureRecord) {
        tracker.process(record)?.let { lookups += it }
        timeline.add(record.timestampMicros, record.uid, record.direction == Direction.OUT, record.packet.size)
        if (packetCount == 0L) firstMicros = record.timestampMicros
        lastMicros = record.timestampMicros
        packetCount++
        buffer.addLast(record)
        while (buffer.size > bufferLimit) buffer.removeFirst()
    }

    val bufferedPackets: Int get() = buffer.size

    /** The moment the analysis looks at: the end of the recording. */
    fun referenceMicros(): Long = lastMicros

    /** Connections, most recently active first. */
    fun flows(): List<FlowInfo> = tracker.snapshot(maxConnections)

    /** DNS lookups, newest first. */
    fun dnsLookups(): List<DnsLookup> = lookups.asReversed()

    fun dashboard(range: TimeRange, destination: (FlowInfo) -> Destination? = { null }): DashboardData =
        dashboard(tracker.snapshot(maxConnections), timeline, range, lastMicros, destination)

    /** The packets of [flow] still in the buffer (the newest of the recording), oldest first. */
    fun packetsOf(flow: FlowInfo): List<FlowPacket> = packetsOf(flow, buffer.toList())
}
