package io.github.rudolfhk.traffical.capture

import io.github.rudolfhk.traffical.core.analysis.DashboardData
import io.github.rudolfhk.traffical.core.analysis.FlowPacket
import io.github.rudolfhk.traffical.core.analysis.TimeRange
import io.github.rudolfhk.traffical.core.capture.CaptureBatch
import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.capture.Direction
import io.github.rudolfhk.traffical.core.dns.DnsType
import io.github.rudolfhk.traffical.core.enrichment.Enrichment
import io.github.rudolfhk.traffical.core.packet.PacketParser
import io.github.rudolfhk.traffical.core.pcap.Pcapng
import io.github.rudolfhk.traffical.core.pcap.RecordedPacket
import io.github.rudolfhk.traffical.core.recording.RecordingReplay
import io.github.rudolfhk.traffical.model.Connection
import io.github.rudolfhk.traffical.model.DnsEvent
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * A saved recording loaded for browsing, like the live capture: its packets are replayed
 * into connections, DNS lookups, a dashboard and per-connection packets. Built once (see
 * [CaptureRepository.loadRecording]) and then read from the UI thread.
 */
class RecordingView internal constructor(
    val name: String,
    val startMillis: Long,
    val endMillis: Long,
    val packetCount: Long,
    val bufferedPackets: Int,
    private val replay: RecordingReplay,
    private val apps: AppResolver,
    private val enrichment: Enrichment?,
) {
    /** The analysis looks at the end of the recording. */
    fun referenceMicros(): Long = replay.referenceMicros()

    fun appInfo(uid: Int) = apps.appInfo(uid)

    val connections: List<Connection> by lazy {
        replay.flows().map { Connection(it, apps.appInfo(it.uid), enrichment?.destination(it)) }
    }

    val dnsEvents: List<DnsEvent> by lazy {
        replay.dnsLookups().mapIndexed { index, lookup ->
            DnsEvent(
                id = index.toLong(),
                timestampMillis = lookup.timestampMicros / 1000,
                app = apps.appInfo(lookup.uid),
                domain = lookup.domain,
                queryType = DnsType.name(lookup.type),
                answers = lookup.answers,
                rcode = lookup.rcode,
                latencyMillis = lookup.latencyMicros?.let { it / 1000 },
            )
        }
    }

    fun dashboard(range: TimeRange): DashboardData = replay.dashboard(range) { enrichment?.destination(it) }

    fun packetsOf(connection: Connection): List<FlowPacket> = replay.packetsOf(connection.flow)
}

/**
 * A recorded packet as a [CaptureRecord] for replay: the uid (and whether it was blocked)
 * come from the comment the recorder wrote, the direction from the stored epb_flags, or,
 * for older recordings without it, from whether the source is the app side (the VPN's TUN
 * address, see CaptureVpnService).
 */
internal fun RecordedPacket.toCaptureRecord(): CaptureRecord {
    val uid = UID_IN_COMMENT.find(comment.orEmpty())?.groupValues?.get(1)?.toIntOrNull() ?: CaptureBatch.UID_UNKNOWN
    val blocked = comment?.contains("blocked") == true
    val dir = when (direction) {
        Pcapng.DIR_OUTBOUND -> Direction.OUT
        Pcapng.DIR_INBOUND -> Direction.IN
        else -> if (fromAppSide(data)) Direction.OUT else Direction.IN
    }
    return CaptureRecord(timestampMicros, uid, dir, blocked, data)
}

private val UID_IN_COMMENT = Regex("""uid=(-?\d+)""")

private fun fromAppSide(packet: ByteArray): Boolean {
    val source = PacketParser.parse(packet)?.source ?: return true
    return isVpnLocalAddress(source)
}

/** The TUN addresses CaptureVpnService assigns (10.215.173.1/30 and fd00:7a1:c0de::/64). */
private fun isVpnLocalAddress(address: InetAddress): Boolean {
    val bytes = address.address
    return when (address) {
        is Inet4Address -> bytes.size == 4 &&
            bytes[0].toInt() and 0xff == 10 && bytes[1].toInt() and 0xff == 215 && bytes[2].toInt() and 0xff == 173
        is Inet6Address -> bytes.size == 16 &&
            bytes[0].toInt() and 0xff == 0xfd && bytes[1].toInt() == 0 && bytes[2].toInt() and 0xff == 0x07 &&
            bytes[3].toInt() and 0xff == 0xa1 && bytes[4].toInt() and 0xff == 0xc0 && bytes[5].toInt() and 0xff == 0xde
        else -> false
    }
}
