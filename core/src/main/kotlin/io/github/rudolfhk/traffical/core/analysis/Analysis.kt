package io.github.rudolfhk.traffical.core.analysis

import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.enrichment.Destination
import io.github.rudolfhk.traffical.core.enrichment.Tracker
import io.github.rudolfhk.traffical.core.packet.IpProtocol

enum class TimeRange(val seconds: Long?) {
    MINUTE(60),
    FIVE_MINUTES(300),
    FIFTEEN_MINUTES(900),
    HOUR(3600),
    ALL(null),
}

/** Why a connection deserves a closer look. */
enum class FlowFlag {
    /**
     * The server name is on the bundled tracker list with an advertising, analytics or
     * telemetry category, or nDPI rates the service as tracker/advertising.
     */
    TRACKER,

    /** nDPI rates the protocol as unsafe or dangerous, or the category as malware/mining. */
    RISKY,

    /** Neither a TLS/QUIC server name, an HTTP host nor a DNS name is known: only an IP. */
    UNNAMED,

    /** DNS-over-TLS/QUIC or a DNS-over-HTTPS server: the lookups inside are hidden. */
    ENCRYPTED_DNS,

    /** The engine did not forward the connection. */
    BLOCKED,
}

private val RISKY_BREEDS = setOf("Unsafe", "Potentially_Dangerous", "Dangerous")
private val RISKY_CATEGORIES = setOf("Malware", "Mining")

/** The flags of this connection; [tracker] is its match on the bundled tracker list. */
fun FlowInfo.flags(tracker: Tracker? = null): Set<FlowFlag> {
    val flags = mutableSetOf<FlowFlag>()
    if (breed == "Tracker_Ads" || category == "Advertisement" || tracker?.tracking == true) flags += FlowFlag.TRACKER
    if (breed in RISKY_BREEDS || category in RISKY_CATEGORIES) flags += FlowFlag.RISKY
    val isTransport = protocol == IpProtocol.TCP || protocol == IpProtocol.UDP
    if (domain == null && isTransport && remotePort != DNS_PORT && !blocked) flags += FlowFlag.UNNAMED
    if (encryptedDns) flags += FlowFlag.ENCRYPTED_DNS
    if (blocked) flags += FlowFlag.BLOCKED
    return flags
}

/** Flags that mark a connection as worth checking (highlighted in the UI). */
val ATTENTION_FLAGS = setOf(FlowFlag.TRACKER, FlowFlag.RISKY, FlowFlag.UNNAMED)

private const val DNS_PORT = 53

/** "TCP"/"UDP"/... or the nDPI master protocol: "TLS" for "TLS.YouTube". */
val FlowInfo.protocolLabel: String
    get() = appProtocol?.substringBefore('.')?.takeUnless { it == "Unknown" } ?: IpProtocol.name(protocol)

/**
 * Filter of the connection list. All set criteria must match; [text] is split into words
 * that must each occur in the app, package, domain, IP, protocol, category, port, or
 * the destination's country, network or tracker.
 */
data class ConnectionFilter(
    val text: String = "",
    val timeRange: TimeRange = TimeRange.ALL,
    /** Matches [protocolLabel] or the IP protocol name, e.g. "TLS", "QUIC", "UDP". */
    val protocol: String? = null,
    val port: Int? = null,
    val uid: Int? = null,
    /** Only connections with one of [ATTENTION_FLAGS]. */
    val attentionOnly: Boolean = false,
) {
    /** True if nothing but the time range is set. */
    val isEmpty: Boolean get() = copy(timeRange = TimeRange.ALL) == ConnectionFilter()

    fun matches(
        flow: FlowInfo,
        appLabel: String,
        packageName: String?,
        nowMicros: Long,
        destination: Destination? = null,
    ): Boolean {
        timeRange.seconds?.let { if (flow.lastSeenMicros < nowMicros - it * 1_000_000) return false }
        if (uid != null && flow.uid != uid) return false
        if (port != null && flow.remotePort != port && flow.localPort != port) return false
        if (protocol != null && !protocol.equals(flow.protocolLabel, ignoreCase = true) &&
            !protocol.equals(IpProtocol.name(flow.protocol), ignoreCase = true)
        ) {
            return false
        }
        if (attentionOnly && flow.flags(destination?.tracker).none { it in ATTENTION_FLAGS }) return false

        val words = text.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (words.isEmpty()) return true
        val haystack = listOfNotNull(
            appLabel, packageName, flow.domain, flow.sni, flow.serverName, flow.dnsName,
            flow.remoteAddress.hostAddress, flow.appProtocol, flow.category, flow.remotePort.toString(),
        ) + destination?.searchTerms.orEmpty()
        return words.all { word -> haystack.any { it.contains(word, ignoreCase = true) } }
    }
}

/** Traffic of one app (uid) in a time range. */
data class AppTraffic(
    val uid: Int,
    val bytesOut: Long,
    val bytesIn: Long,
    val connections: Int,
    val domains: Int,
    /** Connections with one of [ATTENTION_FLAGS]. */
    val attention: Int,
    /** Bytes per second over the last few seconds, both directions. */
    val rate: Long,
) {
    val bytes: Long get() = bytesOut + bytesIn
}

/** Connections to the trackers of one company in a time range. */
data class TrackerTraffic(
    val company: String,
    /** Category labels of its trackers, e.g. "Advertising". */
    val categories: List<String>,
    val connections: Int,
    /** Number of apps that connected. */
    val apps: Int,
    val bytes: Long,
)

data class DashboardData(
    val range: TimeRange,
    val totals: TrafficTotals,
    /** Bytes per second over the last few seconds. */
    val rate: TrafficTotals,
    val series: List<TrafficPoint>,
    /** Sorted by bytes, most first. */
    val apps: List<AppTraffic>,
    val connections: Int,
    val attention: Int,
    /** Tracking companies, most connections first. */
    val trackers: List<TrackerTraffic> = emptyList(),
) {
    companion object {
        val EMPTY = DashboardData(TimeRange.FIVE_MINUTES, TrafficTotals(), TrafficTotals(), emptyList(), emptyList(), 0, 0)
    }
}

/** Builds the dashboard of the [range] ending at [nowMicros]; [destination] adds tracker knowledge. */
fun dashboard(
    flows: List<FlowInfo>,
    timeline: TrafficTimeline,
    range: TimeRange,
    nowMicros: Long,
    destination: (FlowInfo) -> Destination? = { null },
): DashboardData {
    val nowSecond = Math.floorDiv(nowMicros, 1_000_000L)
    val inRange = range.seconds?.let { seconds ->
        flows.filter { it.lastSeenMicros >= nowMicros - seconds * 1_000_000 }
    } ?: flows
    val bytesByUid = timeline.totalsByUid(nowSecond, range.seconds)
    val flowsByUid = inRange.groupBy { it.uid }
    val trackerOf = inRange.associate { it.id to destination(it)?.tracker }

    val apps = (bytesByUid.keys + flowsByUid.keys).map { uid ->
        val appFlows = flowsByUid[uid].orEmpty()
        val bytes = bytesByUid[uid] ?: TrafficTotals()
        val rate = timeline.rate(nowSecond, uid)
        AppTraffic(
            uid = uid,
            bytesOut = bytes.bytesOut,
            bytesIn = bytes.bytesIn,
            connections = appFlows.size,
            domains = appFlows.mapNotNull { it.domain }.distinct().size,
            attention = appFlows.count { flow -> flow.flags(trackerOf[flow.id]).any { it in ATTENTION_FLAGS } },
            rate = rate.total,
        )
    }.filter { it.bytes > 0 || it.connections > 0 }
        .sortedWith(compareByDescending<AppTraffic> { it.bytes }.thenByDescending { it.connections })

    return DashboardData(
        range = range,
        totals = timeline.totals(nowSecond, range.seconds),
        rate = timeline.rate(nowSecond),
        series = timeline.series(nowSecond, range.seconds ?: (nowSecond - firstSecond(flows, nowSecond) + 1)),
        apps = apps,
        connections = inRange.size,
        attention = apps.sumOf { it.attention },
        trackers = inRange.filter { trackerOf[it.id]?.tracking == true }
            .groupBy { trackerOf.getValue(it.id)!!.company }
            .map { (company, companyFlows) ->
                TrackerTraffic(
                    company = company,
                    categories = companyFlows.map { trackerOf.getValue(it.id)!!.categoryLabel }.distinct().sorted(),
                    connections = companyFlows.size,
                    apps = companyFlows.map { it.uid }.distinct().size,
                    bytes = companyFlows.sumOf { it.bytesOut + it.bytesIn },
                )
            }
            .sortedWith(compareByDescending<TrackerTraffic> { it.connections }.thenBy { it.company }),
    )
}

private fun firstSecond(flows: List<FlowInfo>, nowSecond: Long): Long =
    flows.minOfOrNull { Math.floorDiv(it.firstSeenMicros, 1_000_000L) } ?: (nowSecond - 59)
