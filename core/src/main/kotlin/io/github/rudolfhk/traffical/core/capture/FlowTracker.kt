package io.github.rudolfhk.traffical.core.capture

import io.github.rudolfhk.traffical.core.dns.DnsMessage
import io.github.rudolfhk.traffical.core.dns.DnsType
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import io.github.rudolfhk.traffical.core.packet.Packet
import io.github.rudolfhk.traffical.core.packet.PacketParser
import io.github.rudolfhk.traffical.core.packet.TcpFlags
import io.github.rudolfhk.traffical.core.tls.SniResult
import io.github.rudolfhk.traffical.core.tls.TlsSni
import java.net.InetAddress

/** A connection as seen from the app: local = the app's side, remote = the server. */
data class FlowInfo(
    val id: Long,
    val uid: Int,
    val ipVersion: Int,
    val protocol: Int,
    val localAddress: InetAddress,
    val localPort: Int,
    val remoteAddress: InetAddress,
    val remotePort: Int,
    /** Server name from the TLS ClientHello. */
    val sni: String?,
    /** Name the app looked up before connecting to [remoteAddress]. */
    val dnsName: String?,
    val bytesOut: Long,
    val bytesIn: Long,
    val packetsOut: Long,
    val packetsIn: Long,
    val firstSeenMicros: Long,
    val lastSeenMicros: Long,
    val blocked: Boolean,
    val closed: Boolean,
    /** DNS-over-TLS/QUIC (port 853) or a known DNS-over-HTTPS server: lookups inside are hidden. */
    val encryptedDns: Boolean,
    /** nDPI protocol, e.g. "TLS.YouTube", "QUIC.Google", "HTTP"; null until classified. */
    val appProtocol: String? = null,
    /** nDPI category, e.g. "Media", "Advertisement"; null until classified. */
    val category: String? = null,
    /** Server name found by nDPI: QUIC SNI or HTTP Host (null for IP literals and DNS). */
    val serverName: String? = null,
    /** nDPI's rating of the protocol, e.g. "Safe", "Tracker_Ads", "Dangerous"; null until classified. */
    val breed: String? = null,
) {
    val domain: String? get() = sni ?: serverName ?: dnsName
}

/** A completed DNS query/response pair. */
data class DnsLookup(
    val uid: Int,
    val timestampMicros: Long,
    val domain: String,
    val type: Int,
    /** IPs for A/AAAA records, target names for CNAME records. */
    val answers: List<String>,
    val rcode: Int,
    /** Null if the query itself was not captured. */
    val latencyMicros: Long?,
)

/**
 * Turns the packet stream of the capture engine into connections ("flows") with byte
 * counters, the server name (TLS SNI or the DNS name the app resolved) and DNS lookups.
 * Not thread-safe.
 */
class FlowTracker(
    private val maxFlows: Int = 10_000,
    private val maxDomainMappings: Int = 50_000,
) {
    private data class FlowKey(
        val ipVersion: Int,
        val protocol: Int,
        val localAddress: InetAddress,
        val localPort: Int,
        val remoteAddress: InetAddress,
        val remotePort: Int,
    )

    private class FlowState(val id: Long, val key: FlowKey, var uid: Int, val firstSeenMicros: Long) {
        var lastSeenMicros = firstSeenMicros
        var bytesOut = 0L
        var bytesIn = 0L
        var packetsOut = 0L
        var packetsIn = 0L
        var sni: String? = null
        var dnsName: String? = null
        var blocked = false
        var closed = false
        var encryptedDns = false
        var appProtocol: String? = null
        var category: String? = null
        var serverName: String? = null
        var breed: String? = null

        /** First client bytes of a TCP flow, kept until the SNI is known. Null once done. */
        var helloBuffer: ByteArray? = ByteArray(0)
    }

    private data class PendingKey(val localPort: Int, val transactionId: Int)

    private class PendingQuery(val uid: Int, val timestampMicros: Long)

    /** The current flow per 5-tuple; a closed flow is replaced when its ports are reused. */
    private val activeFlows = HashMap<FlowKey, FlowState>()

    // All retained flows by id, in access order: iteration starts with the least recently updated.
    private val flows = object : LinkedHashMap<Long, FlowState>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, FlowState>): Boolean {
            if (size <= maxFlows) return false
            val flow = eldest.value
            if (activeFlows[flow.key] === flow) activeFlows.remove(flow.key)
            return true
        }
    }
    private val domainByAddress = object : LinkedHashMap<InetAddress, String>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<InetAddress, String>) =
            size > maxDomainMappings
    }
    private val pendingQueries = LinkedHashMap<PendingKey, PendingQuery>()
    private var nextFlowId = 1L

    /** Processes one capture entry. Returns the DNS lookup a packet completed, if any. */
    fun process(entry: CaptureEntry): DnsLookup? = when (entry) {
        is CaptureRecord -> processPacket(entry)
        is FlowDetection -> {
            attachDetection(entry)
            null
        }
    }

    private fun attachDetection(detection: FlowDetection) {
        val key = FlowKey(
            detection.ipVersion, detection.protocol,
            detection.localAddress, detection.localPort,
            detection.remoteAddress, detection.remotePort,
        )
        val flow = activeFlows[key] ?: return
        flow.appProtocol = detection.protocolName
        flow.category = detection.categoryName
        flow.breed = detection.breed.ifEmpty { null }
        val name = detection.serverName.lowercase()
        if (name.isNotEmpty() && key.remotePort != DNS_PORT && !isIpLiteral(name)) {
            flow.serverName = name
            if (isDohHost(name)) flow.encryptedDns = true
        }
    }

    private fun processPacket(record: CaptureRecord): DnsLookup? {
        val packet = PacketParser.parse(record.packet) ?: return null
        val outgoing = record.direction == Direction.OUT
        val key = if (outgoing) {
            FlowKey(packet.ipVersion, packet.protocol, packet.source, packet.sourcePort, packet.destination, packet.destinationPort)
        } else {
            FlowKey(packet.ipVersion, packet.protocol, packet.destination, packet.destinationPort, packet.source, packet.sourcePort)
        }

        val isTcp = packet.protocol == IpProtocol.TCP
        val isSyn = isTcp && packet.tcpFlags and TcpFlags.SYN != 0 && packet.tcpFlags and TcpFlags.ACK == 0
        var flow = activeFlows[key]
        if (flow == null || (flow.closed && isSyn && outgoing)) {
            flow = FlowState(nextFlowId++, key, record.uid, record.timestampMicros)
            flow.dnsName = domainByAddress[key.remoteAddress]
            flow.encryptedDns = key.remotePort == PRIVATE_DNS_PORT
            if (!isTcp) flow.helloBuffer = null
            activeFlows[key] = flow
            flows[flow.id] = flow
        } else {
            flows[flow.id] // marks it as most recently active
        }

        if (flow.uid == CaptureBatch.UID_UNKNOWN) flow.uid = record.uid
        flow.lastSeenMicros = record.timestampMicros
        if (record.blocked) flow.blocked = true
        if (outgoing) {
            flow.bytesOut += packet.length
            flow.packetsOut++
        } else {
            flow.bytesIn += packet.length
            flow.packetsIn++
        }
        if (isTcp && packet.tcpFlags and (TcpFlags.FIN or TcpFlags.RST) != 0) flow.closed = true
        if (outgoing && packet.payloadLength > 0) inspectClientPayload(flow, record.packet, packet)

        return dnsMessage(packet, record.packet)?.let { (offset, length) ->
            if (outgoing) {
                rememberQuery(record, packet, offset, length)
                null
            } else {
                completeLookup(record, packet, offset, length)
            }
        }
    }

    /** Most recently active flows first. */
    fun snapshot(limit: Int = Int.MAX_VALUE): List<FlowInfo> =
        // toList().asReversed() rather than reversed(): on JDK 21 the latter binds to
        // SequencedCollection.reversed(), which Android only has since API 35.
        flows.values.toList().asReversed().asSequence().take(limit).map { it.toInfo() }.toList()

    fun clear() {
        activeFlows.clear()
        flows.clear()
        domainByAddress.clear()
        pendingQueries.clear()
    }

    private fun inspectClientPayload(flow: FlowState, buf: ByteArray, packet: Packet) {
        val previous = flow.helloBuffer ?: return
        val hello = previous + buf.copyOfRange(packet.payloadOffset, packet.payloadOffset + packet.payloadLength)
        when (val result = TlsSni.parse(hello)) {
            is SniResult.Found -> {
                flow.sni = result.hostname
                if (isDohHost(result.hostname)) flow.encryptedDns = true
                flow.helloBuffer = null
            }
            SniResult.Absent -> flow.helloBuffer = null
            SniResult.Incomplete -> flow.helloBuffer = if (hello.size < MAX_HELLO_SIZE) hello else null
        }
    }

    /** Offset and length of a DNS message carried by this packet (UDP or single-segment TCP). */
    private fun dnsMessage(packet: Packet, buf: ByteArray): Pair<Int, Int>? {
        if (packet.sourcePort != DNS_PORT && packet.destinationPort != DNS_PORT) return null
        return when (packet.protocol) {
            IpProtocol.UDP -> packet.payloadOffset to packet.payloadLength
            IpProtocol.TCP -> {
                if (packet.payloadLength < 2) return null
                val length = ((buf[packet.payloadOffset].toInt() and 0xff) shl 8) or
                    (buf[packet.payloadOffset + 1].toInt() and 0xff)
                if (length == packet.payloadLength - 2) packet.payloadOffset + 2 to length else null
            }
            else -> null
        }
    }

    private fun rememberQuery(record: CaptureRecord, packet: Packet, offset: Int, length: Int) {
        val query = DnsMessage.parse(record.packet, offset, length) ?: return
        if (query.isResponse) return
        if (pendingQueries.size >= MAX_PENDING_QUERIES) {
            pendingQueries.remove(pendingQueries.keys.first())
        }
        pendingQueries[PendingKey(packet.sourcePort, query.id)] = PendingQuery(record.uid, record.timestampMicros)
    }

    private fun completeLookup(record: CaptureRecord, packet: Packet, offset: Int, length: Int): DnsLookup? {
        val response = DnsMessage.parse(record.packet, offset, length) ?: return null
        if (!response.isResponse) return null
        val question = response.questions.firstOrNull() ?: return null
        val pending = pendingQueries.remove(PendingKey(packet.destinationPort, response.id))

        for (answer in response.answers) {
            if (answer.type == DnsType.A || answer.type == DnsType.AAAA) {
                domainByAddress[InetAddress.getByName(answer.data)] = question.name
            }
        }

        return DnsLookup(
            uid = if (record.uid != CaptureBatch.UID_UNKNOWN) record.uid else pending?.uid ?: CaptureBatch.UID_UNKNOWN,
            timestampMicros = pending?.timestampMicros ?: record.timestampMicros,
            domain = question.name,
            type = question.type,
            answers = response.answers
                .filter { it.type == DnsType.A || it.type == DnsType.AAAA || it.type == DnsType.CNAME }
                .map { it.data },
            rcode = response.rcode,
            latencyMicros = pending?.let { record.timestampMicros - it.timestampMicros },
        )
    }

    private fun FlowState.toInfo() = FlowInfo(
        id = id,
        uid = uid,
        ipVersion = key.ipVersion,
        protocol = key.protocol,
        localAddress = key.localAddress,
        localPort = key.localPort,
        remoteAddress = key.remoteAddress,
        remotePort = key.remotePort,
        sni = sni,
        dnsName = dnsName,
        bytesOut = bytesOut,
        bytesIn = bytesIn,
        packetsOut = packetsOut,
        packetsIn = packetsIn,
        firstSeenMicros = firstSeenMicros,
        lastSeenMicros = lastSeenMicros,
        blocked = blocked,
        closed = closed,
        encryptedDns = encryptedDns,
        appProtocol = appProtocol,
        category = category,
        serverName = serverName,
        breed = breed,
    )

    companion object {
        private const val DNS_PORT = 53
        private const val PRIVATE_DNS_PORT = 853
        private const val MAX_HELLO_SIZE = 16 * 1024
        private const val MAX_PENDING_QUERIES = 1_000

        /** Well-known DNS-over-HTTPS endpoints (matched as domain suffixes). */
        val DOH_HOSTS = listOf(
            "dns.google",
            "cloudflare-dns.com",
            "dns.quad9.net",
            "doh.opendns.com",
            "dns.nextdns.io",
            "dns.adguard-dns.com",
            "doh.dns.sb",
            "doh.mullvad.net",
            "dns.controld.com",
        )

        fun isDohHost(hostname: String): Boolean =
            DOH_HOSTS.any { hostname == it || hostname.endsWith(".$it") }

        /** "10.0.0.1", "10.0.0.1:8080", "[2001:db8::1]:443", "2001:db8::1" */
        private fun isIpLiteral(name: String): Boolean =
            name.startsWith("[") || name.count { it == ':' } >= 2 ||
                name.substringBefore(':').all { it.isDigit() || it == '.' }
    }
}
