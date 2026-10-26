package io.github.rudolfhk.traffical.core.analysis

import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.capture.Direction
import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.packet.PacketParser

/** One packet of a connection, for the detail view. */
class FlowPacket(
    val timestampMicros: Long,
    val direction: Direction,
    /** Length of the whole IP packet. */
    val length: Int,
    /** 0 unless TCP. */
    val tcpFlags: Int,
    /** Transport payload (application data), copied. */
    val payload: ByteArray,
)

/**
 * The captured packets of [flow] among [records], oldest first, at most [limit]. Packets
 * of an earlier connection on the same ports are excluded by the flow's time span.
 */
fun packetsOf(flow: FlowInfo, records: Iterable<CaptureRecord>, limit: Int = 1000): List<FlowPacket> {
    val result = ArrayList<FlowPacket>()
    for (record in records) {
        if (record.timestampMicros < flow.firstSeenMicros || record.timestampMicros > flow.lastSeenMicros) continue
        val packet = PacketParser.parse(record.packet) ?: continue
        if (packet.protocol != flow.protocol) continue
        val matches = if (record.direction == Direction.OUT) {
            packet.source == flow.localAddress && packet.sourcePort == flow.localPort &&
                packet.destination == flow.remoteAddress && packet.destinationPort == flow.remotePort
        } else {
            packet.source == flow.remoteAddress && packet.sourcePort == flow.remotePort &&
                packet.destination == flow.localAddress && packet.destinationPort == flow.localPort
        }
        if (!matches) continue
        result += FlowPacket(
            timestampMicros = record.timestampMicros,
            direction = record.direction,
            length = packet.length,
            tcpFlags = packet.tcpFlags,
            payload = record.packet.copyOfRange(packet.payloadOffset, packet.payloadOffset + packet.payloadLength),
        )
        if (result.size >= limit) break
    }
    return result
}
