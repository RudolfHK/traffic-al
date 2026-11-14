package io.github.rudolfhk.traffical.core.analysis

import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.enrichment.Destination
import io.github.rudolfhk.traffical.core.packet.IpProtocol

/** Whether a connection's application data could be turned into readable content. */
enum class ReadState {
    /** Decrypted (or plaintext) and parsed into HTTP messages. */
    READABLE,

    /** Encrypted (TLS/QUIC) and not decryptable: no keys, unsupported cipher, or pinned. */
    ENCRYPTED,

    /** Not HTTP-bearing (DNS, non-HTTP), so it is neither "read" nor "couldn't read". */
    NOT_APPLICABLE,
}

/** What reading one connection produced; the app builds this from decryption + [PlaintextDissector]. */
data class FlowReadResult(
    val state: ReadState,
    val requests: List<HttpMessage> = emptyList(),
    val responses: List<HttpMessage> = emptyList(),
) {
    companion object {
        val NOT_APPLICABLE = FlowReadResult(ReadState.NOT_APPLICABLE)
        val ENCRYPTED = FlowReadResult(ReadState.ENCRYPTED)
    }
}

/** One destination an app sent HTTP-bearing traffic to, with what was readable about it. */
data class AuditDestination(
    val host: String?,
    val address: String,
    val port: Int,
    val tracker: Boolean,
    val company: String?,
    val country: String?,
    val connections: Int,
    val requests: Int,
    /** At least one connection to this destination was readable. */
    val readable: Boolean,
    /** Connections that were encrypted and could not be read. */
    val encrypted: Int,
    val methods: List<String>,
    val paths: List<String>,
    val exposures: List<Exposure>,
) {
    val label: String get() = host ?: "$address:$port"
}

/** The audit of one app (uid): where it sends data and what of yours goes with it. */
data class AppAudit(
    val uid: Int,
    val destinations: List<AuditDestination>,
    val exposureCount: Int,
    val exposureTypes: Set<ExposureType>,
    val readableConnections: Int,
    val encryptedConnections: Int,
) {
    val destinationCount: Int get() = destinations.size
}

/** A per-app "what data goes where" audit over decrypted + plaintext traffic (phase 12). */
data class DataFlowAudit(
    val apps: List<AppAudit>,
    val totalExposures: Int,
    val readableConnections: Int,
    val encryptedConnections: Int,
) {
    val appsWithExposures: Int get() = apps.count { it.exposureCount > 0 }

    companion object {
        val EMPTY = DataFlowAudit(emptyList(), 0, 0, 0)
    }
}

private const val MAX_PATHS = 20
private const val MAX_PATH_LENGTH = 160

/**
 * Builds a per-app data-flow audit. [read] turns each connection into readable content (the
 * app runs decryption with the owner's keys plus [PlaintextDissector]; pure callers can pass
 * a stub), and [destination] adds offline knowledge (tracker, company, country). Pure and
 * deterministic — all the decryption happens behind [read]; this only organizes the result.
 */
fun dataFlowAudit(
    flows: List<FlowInfo>,
    read: (FlowInfo) -> FlowReadResult = { FlowReadResult.NOT_APPLICABLE },
    destination: (FlowInfo) -> Destination? = { null },
): DataFlowAudit {
    val apps = ArrayList<AppAudit>()
    var totalExposures = 0
    var totalReadable = 0
    var totalEncrypted = 0

    for ((uid, appFlows) in flows.groupBy { it.uid }) {
        val byDestination = LinkedHashMap<Pair<String, Int>, DestinationBuilder>()
        var readable = 0
        var encrypted = 0

        for (flow in appFlows) {
            val result = read(flow)
            when (result.state) {
                ReadState.NOT_APPLICABLE -> continue
                ReadState.READABLE -> readable++
                ReadState.ENCRYPTED -> encrypted++
            }
            val dest = destination(flow)
            val host = flow.domain ?: result.requests.firstNotNullOfOrNull { it.authority }
            val address = flow.remoteAddress.hostAddress?.substringBefore('%') ?: "?"
            val key = (host ?: address) to flow.remotePort
            val builder = byDestination.getOrPut(key) {
                DestinationBuilder(host, address, flow.remotePort, dest)
            }
            builder.add(flow, result)
        }

        if (byDestination.isEmpty()) continue
        val destinations = byDestination.values.map { it.build() }
            .sortedWith(compareByDescending<AuditDestination> { it.exposures.size }
                .thenByDescending { it.requests }
                .thenByDescending { it.connections })
        val exposures = destinations.sumOf { it.exposures.size }
        val types = destinations.flatMap { d -> d.exposures.map { it.type } }.toSet()
        totalExposures += exposures
        totalReadable += readable
        totalEncrypted += encrypted
        apps += AppAudit(uid, destinations, exposures, types, readable, encrypted)
    }

    apps.sortWith(
        compareByDescending<AppAudit> { it.exposureCount }
            .thenByDescending { it.destinationCount }
            .thenByDescending { it.readableConnections },
    )
    return DataFlowAudit(apps, totalExposures, totalReadable, totalEncrypted)
}

private class DestinationBuilder(
    private val host: String?,
    private val address: String,
    private val port: Int,
    private val destination: Destination?,
) {
    private var connections = 0
    private var requests = 0
    private var readable = false
    private var encrypted = 0
    private val methods = linkedSetOf<String>()
    private val paths = linkedSetOf<String>()
    private val exposures = ArrayList<Exposure>()

    fun add(flow: FlowInfo, result: FlowReadResult) {
        connections++
        if (flow.blocked) return
        if (result.state == ReadState.ENCRYPTED) { encrypted++; return }
        if (result.state != ReadState.READABLE) return
        readable = true
        for (req in result.requests) {
            requests++
            req.method?.let { methods += it }
            req.path?.let { if (paths.size < MAX_PATHS) paths += it.take(MAX_PATH_LENGTH) }
            exposures += SensitiveData.scan(req)
        }
    }

    fun build(): AuditDestination {
        val tracker = destination?.tracker
        return AuditDestination(
            host = host,
            address = address,
            port = port,
            tracker = tracker?.tracking == true,
            company = tracker?.company,
            country = destination?.country,
            connections = connections,
            requests = requests,
            readable = readable,
            encrypted = encrypted,
            methods = methods.sorted(),
            paths = paths.toList(),
            exposures = dedupExposures(exposures),
        )
    }

    private fun dedupExposures(list: List<Exposure>): List<Exposure> {
        val seen = LinkedHashMap<Pair<ExposureType, String>, Exposure>()
        for (e in list) seen.putIfAbsent(e.type to e.where, e)
        return seen.values.toList()
    }
}

/** True for connections that could carry HTTP (so the audit should try to read them). */
fun FlowInfo.carriesHttp(): Boolean = protocol == IpProtocol.TCP || protocol == IpProtocol.UDP
