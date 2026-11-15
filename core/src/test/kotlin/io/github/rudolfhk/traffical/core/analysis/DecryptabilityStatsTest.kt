package io.github.rudolfhk.traffical.core.analysis

import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DecryptabilityStatsTest {
    private val app = InetAddress.getByName("10.215.173.1")

    private fun flow(id: Long, uid: Int, bytes: Long) = FlowInfo(
        id = id, uid = uid, ipVersion = 4, protocol = IpProtocol.TCP,
        localAddress = app, localPort = 40000 + id.toInt(),
        remoteAddress = InetAddress.getByName("93.184.216.34"), remotePort = 443,
        sni = "host.example.test", dnsName = "host.example.test",
        bytesOut = bytes / 2, bytesIn = bytes - bytes / 2, packetsOut = 1, packetsIn = 1,
        firstSeenMicros = 0, lastSeenMicros = 1_000_000, blocked = false, closed = true, encryptedDns = false,
    )

    @Test
    fun `splits readable from undecryptable, overall and per app`() {
        val flows = listOf(
            flow(1, uid = 10100, bytes = 1000),
            flow(2, uid = 10100, bytes = 1000),
            flow(3, uid = 10100, bytes = 5000),
            flow(4, uid = 10200, bytes = 2000),
            flow(5, uid = 10300, bytes = 400), // DNS / not HTTP -> excluded
        )
        val stats = decryptabilityStats(flows) { flow ->
            when (flow.id) {
                1L, 2L -> FlowReadResult(ReadState.READABLE)
                3L, 4L -> FlowReadResult.ENCRYPTED
                else -> FlowReadResult.NOT_APPLICABLE
            }
        }

        assertEquals(2, stats.readableConnections)
        assertEquals(2, stats.encryptedConnections)
        assertEquals(2000, stats.readableBytes)
        assertEquals(7000, stats.encryptedBytes)
        assertEquals(2000.0 / 9000.0, stats.readableFraction, 1e-9)

        // uid 10300 (only non-HTTP) is excluded; the most-opaque app sorts first.
        assertEquals(2, stats.apps.size)
        assertEquals(10100, stats.apps.first().uid) // 5000 encrypted bytes > 2000
        assertEquals(1, stats.fullyEncryptedApps) // uid 10200 is entirely opaque
        assertEquals(0, stats.fullyReadableApps) // uid 10100 has both readable and encrypted

        val leaky = stats.apps.first { it.uid == 10100 }
        assertEquals(2, leaky.readableConnections)
        assertEquals(1, leaky.encryptedConnections)
        assertTrue(leaky.readableFraction < 0.3) // 2000 / 7000
    }

    @Test
    fun `empty when nothing is http-bearing`() {
        val stats = decryptabilityStats(listOf(flow(1, uid = 1, bytes = 100))) { FlowReadResult.NOT_APPLICABLE }
        assertEquals(DecryptabilityStats.EMPTY, stats)
    }
}
