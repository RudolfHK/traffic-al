package io.github.rudolfhk.traffical.core.capture

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SyntheticTrafficTest {

    @Test
    fun `batches decode into the connections they describe`() {
        val traffic = SyntheticTraffic(flows = 24, dataPacketsPerFlow = 5, concurrentFlows = 7, maxBatchBytes = 16 * 1024)
        val tracker = FlowTracker()
        var packets = 0
        var detections = 0
        val lookups = ArrayList<DnsLookup>()
        val batches = traffic.batches().toList()
        for (batch in batches) {
            for (entry in CaptureBatch.decode(batch)) {
                if (entry is CaptureRecord) packets++ else detections++
                tracker.process(entry)?.let { lookups += it }
            }
        }

        assertTrue(batches.size > 1, "split into batches")
        assertEquals(traffic.packets, packets)
        assertEquals(24, detections)
        assertEquals(24, lookups.size)
        val connections = tracker.snapshot().filter { it.remotePort == 443 }
        assertEquals(24, connections.size)
        for (flow in connections) {
            assertEquals(SyntheticTraffic.HOSTS[(flow.localPort - 30_000) % SyntheticTraffic.HOSTS.size], flow.sni)
            assertEquals(flow.sni, flow.dnsName, "the address was looked up first")
            assertEquals("TLS.Google", flow.appProtocol)
            assertEquals(5L, flow.packetsIn - 2, "SYN+ACK, data, FIN")
            assertTrue(flow.closed)
        }
        assertEquals(6, connections.count { it.ipVersion == 6 })
    }
}
