package io.github.rudolfhk.traffical.core.analysis

import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DataFlowAuditTest {
    private val app = InetAddress.getByName("10.215.173.1")

    private fun flow(id: Long, uid: Int, remote: String, sni: String?, blocked: Boolean = false) = FlowInfo(
        id = id, uid = uid, ipVersion = 4, protocol = IpProtocol.TCP,
        localAddress = app, localPort = 40000 + id.toInt(),
        remoteAddress = InetAddress.getByName(remote), remotePort = 443,
        sni = sni, dnsName = sni, bytesOut = 100, bytesIn = 1000, packetsOut = 1, packetsIn = 1,
        firstSeenMicros = 0, lastSeenMicros = 1_000_000,
        blocked = blocked, closed = true, encryptedDns = false,
    )

    private fun request(host: String, path: String) = FlowReadResult(
        ReadState.READABLE,
        requests = listOf(HttpMessage(HttpKind.REQUEST, method = "POST", authority = host, path = path)),
    )

    @Test
    fun `builds a per-app audit with exposures and an unreadable tally`() {
        val leaky = flow(1, uid = 10100, remote = "93.184.216.34", sni = "collect.example.test")
        val opaque = flow(2, uid = 10100, remote = "93.184.216.35", sni = "pinned.example.test")
        val other = flow(3, uid = 10200, remote = "93.184.216.36", sni = "cdn.example.test")

        val audit = dataFlowAudit(
            flows = listOf(leaky, opaque, other),
            read = { flow ->
                when (flow.id) {
                    1L -> request("collect.example.test", "/t?email=user@example.test")
                    2L -> FlowReadResult.ENCRYPTED // pinned / no keys
                    else -> request("cdn.example.test", "/asset.js")
                }
            },
        )

        assertEquals(2, audit.apps.size)
        // The app with the exposure sorts first.
        val first = audit.apps.first()
        assertEquals(10100, first.uid)
        assertEquals(1, first.readableConnections)
        assertEquals(1, first.encryptedConnections)
        assertTrue(ExposureType.EMAIL in first.exposureTypes)

        val collect = first.destinations.first { it.host == "collect.example.test" }
        assertTrue(collect.readable)
        assertTrue(collect.exposures.any { it.type == ExposureType.EMAIL })

        val pinned = first.destinations.first { it.host == "pinned.example.test" }
        assertFalse(pinned.readable)
        assertEquals(1, pinned.encrypted)

        assertEquals(1, audit.totalExposures)
        assertEquals(2, audit.readableConnections)
        assertEquals(1, audit.encryptedConnections)
    }

    @Test
    fun `apps with only non-http traffic are omitted`() {
        val dns = flow(1, uid = 10300, remote = "1.1.1.1", sni = null)
        val audit = dataFlowAudit(flows = listOf(dns), read = { FlowReadResult.NOT_APPLICABLE })
        assertTrue(audit.apps.isEmpty())
    }
}
