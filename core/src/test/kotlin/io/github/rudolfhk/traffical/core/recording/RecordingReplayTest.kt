package io.github.rudolfhk.traffical.core.recording

import io.github.rudolfhk.traffical.core.analysis.TimeRange
import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.capture.Direction
import io.github.rudolfhk.traffical.core.packet.PacketBuilder
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RecordingReplayTest {

    private val app = InetAddress.getByName("10.215.173.1")
    private val server = InetAddress.getByName("93.184.216.34")

    private fun record(micros: Long, direction: Direction, packet: ByteArray, uid: Int = 10200) =
        CaptureRecord(micros, uid, direction, blocked = false, packet = packet)

    @Test
    fun `rebuilds a connection with its byte counters and packets`() {
        val replay = RecordingReplay()
        // A tiny TCP exchange: SYN out, data out, data in.
        replay.add(record(1_000, Direction.OUT, PacketBuilder.tcp(app, 44000, server, 443, 1, 0, flags = 0x02)))
        replay.add(record(2_000, Direction.OUT, PacketBuilder.tcp(app, 44000, server, 443, 2, 1, flags = 0x18, payload = ByteArray(100))))
        replay.add(record(3_000, Direction.IN, PacketBuilder.tcp(server, 443, app, 44000, 1, 102, flags = 0x18, payload = ByteArray(500))))

        val flows = replay.flows()
        assertEquals(1, flows.size)
        val flow = flows.single()
        assertEquals(443, flow.remotePort)
        assertEquals(2, flow.packetsOut)
        assertEquals(1, flow.packetsIn)
        assertEquals(500 + 40, flow.bytesIn) // IP+TCP header is 40 bytes
        assertEquals(3L, replay.packetCount)
        assertEquals(3_000, replay.referenceMicros())

        val packets = replay.packetsOf(flow)
        assertEquals(3, packets.size)
        assertEquals(100, packets[1].payload.size)
    }

    @Test
    fun `reports DNS lookups and a dashboard`() {
        val replay = RecordingReplay()
        val dns = InetAddress.getByName("10.215.173.2")
        // DNS query then response for example.com -> the server address.
        replay.add(record(1_000, Direction.OUT, PacketBuilder.udp(app, 55000, dns, 53, query("example.com"))))
        replay.add(record(2_000, Direction.IN, PacketBuilder.udp(dns, 53, app, 55000, response("example.com", server))))
        replay.add(record(3_000, Direction.OUT, PacketBuilder.tcp(app, 44001, server, 443, 1, 0, flags = 0x02)))

        assertTrue(replay.dnsLookups().any { it.domain == "example.com" })
        val dashboard = replay.dashboard(TimeRange.ALL)
        assertTrue(dashboard.totals.bytesOut > 0)
        assertTrue(dashboard.apps.any { it.uid == 10200 })
    }

    /** A minimal DNS query for [name] (type A). */
    private fun query(name: String): ByteArray = dns(name, isResponse = false, address = null)

    private fun response(name: String, address: InetAddress): ByteArray = dns(name, isResponse = true, address = address)

    private fun dns(name: String, isResponse: Boolean, address: InetAddress?): ByteArray {
        val out = ArrayList<Byte>()
        fun u16(v: Int) { out.add((v ushr 8).toByte()); out.add(v.toByte()) }
        u16(0x1234) // id
        u16(if (isResponse) 0x8180 else 0x0100) // flags
        u16(1) // qdcount
        u16(if (address != null) 1 else 0) // ancount
        u16(0); u16(0)
        for (label in name.split(".")) {
            out.add(label.length.toByte())
            out.addAll(label.toByteArray(Charsets.US_ASCII).toList())
        }
        out.add(0)
        u16(1); u16(1) // type A, class IN
        if (address != null) {
            u16(0xc00c) // name pointer to the question
            u16(1); u16(1) // type A, class IN
            u16(0); u16(60) // ttl
            u16(4)
            out.addAll(address.address.toList())
        }
        return out.toByteArray()
    }
}
