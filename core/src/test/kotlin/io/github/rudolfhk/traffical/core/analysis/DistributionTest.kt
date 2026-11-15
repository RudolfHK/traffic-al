package io.github.rudolfhk.traffical.core.analysis

import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DistributionTest {
    private val local = InetAddress.getByName("10.215.173.1")

    private fun flow(
        id: Long,
        protocol: Int,
        appProtocol: String?,
        bytesOut: Long,
        bytesIn: Long,
        category: String? = null,
    ) = FlowInfo(
        id = id, uid = 10100, ipVersion = 4, protocol = protocol,
        localAddress = local, localPort = 40000 + id.toInt(),
        remoteAddress = InetAddress.getByName("93.184.216.34"), remotePort = 443,
        sni = null, dnsName = null, bytesOut = bytesOut, bytesIn = bytesIn, packetsOut = 1, packetsIn = 1,
        firstSeenMicros = 0, lastSeenMicros = 1_000_000, blocked = false, closed = true, encryptedDns = false,
        appProtocol = appProtocol, category = category,
    )

    @Test
    fun `groups by protocol label, largest by bytes first`() {
        val flows = listOf(
            flow(1, IpProtocol.TCP, "TLS.YouTube", bytesOut = 1_000, bytesIn = 9_000),
            flow(2, IpProtocol.TCP, "TLS", bytesOut = 500, bytesIn = 500),
            flow(3, IpProtocol.UDP, "QUIC.Google", bytesOut = 2_000, bytesIn = 2_000),
            flow(4, IpProtocol.UDP, "DNS", bytesOut = 40, bytesIn = 80),
        )
        val mix = protocolMix(flows)

        assertEquals(listOf("TLS", "QUIC", "DNS"), mix.map { it.label })
        val tls = mix.first { it.label == "TLS" }
        assertEquals(11_000L, tls.bytes) // both TLS flows merged
        assertEquals(2, tls.connections)
        // Totals are preserved across the whole distribution.
        assertEquals(flows.sumOf { it.bytesOut + it.bytesIn }, mix.sumOf { it.bytes })
        assertEquals(flows.size, mix.sumOf { it.connections })
    }

    @Test
    fun `folds the tail past the slot cap into Other, which sorts last`() {
        // Six distinct protocols; with maxSlots = 5 the two smallest fold into "Other".
        val flows = listOf(
            flow(1, IpProtocol.TCP, "TLS", bytesOut = 0, bytesIn = 6_000),
            flow(2, IpProtocol.UDP, "QUIC", bytesOut = 0, bytesIn = 5_000),
            flow(3, IpProtocol.TCP, "HTTP", bytesOut = 0, bytesIn = 4_000),
            flow(4, IpProtocol.TCP, "TLS1", bytesOut = 0, bytesIn = 3_000),
            flow(5, IpProtocol.UDP, "DNS", bytesOut = 0, bytesIn = 200),
            flow(6, IpProtocol.TCP, "RTMP", bytesOut = 0, bytesIn = 100),
        )
        val mix = protocolMix(flows, maxSlots = 5)

        assertEquals(5, mix.size)
        assertEquals("Other", mix.last().label)
        assertEquals(OTHER_SHARE_LABEL, mix.last().label)
        // Other aggregates exactly the two smallest slices (DNS + RTMP).
        assertEquals(300L, mix.last().bytes)
        assertEquals(2, mix.last().connections)
        // Nothing is lost by folding.
        assertEquals(flows.sumOf { it.bytesIn }, mix.sumOf { it.bytes })
        assertEquals(flows.size, mix.sumOf { it.connections })
        // "Other" is last even though an earlier named slice may be smaller than it in another run.
        assertTrue(mix.dropLast(1).none { it.label == "Other" })
    }

    @Test
    fun `empty input yields no slices`() {
        assertTrue(protocolMix(emptyList()).isEmpty())
    }
}
