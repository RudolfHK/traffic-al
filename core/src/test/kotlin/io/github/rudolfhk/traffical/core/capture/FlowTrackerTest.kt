package io.github.rudolfhk.traffical.core.capture

import io.github.rudolfhk.traffical.core.dns.DnsType
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import io.github.rudolfhk.traffical.core.packet.PacketBuilder
import io.github.rudolfhk.traffical.core.packet.TcpFlags
import io.github.rudolfhk.traffical.core.tls.TlsSniTest
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FlowTrackerTest {

    private val app = InetAddress.getByName("10.215.173.1")
    private val virtualDns = InetAddress.getByName("10.215.173.2")
    private val server = InetAddress.getByName("93.184.216.34")
    private val uid = 10123
    private var clock = 1_000_000L

    private fun out(packet: ByteArray, uid: Int = this.uid, blocked: Boolean = false) =
        CaptureRecord(clock++, uid, Direction.OUT, blocked, packet)

    private fun inbound(packet: ByteArray, uid: Int = this.uid) = CaptureRecord(clock++, uid, Direction.IN, false, packet)

    private fun dnsQuery(id: Int, name: String) = TlsSniTest.hex(
        "%04x 0100 0001 0000 0000 0000".format(id) + labels(name) + "0001 0001",
    )

    private fun dnsResponse(id: Int, name: String, address: String) = TlsSniTest.hex(
        "%04x 8180 0001 0001 0000 0000".format(id) + labels(name) + "0001 0001" +
            "c00c 0001 0001 0000 003c 0004" + InetAddress.getByName(address).address.joinToString("") { "%02x".format(it) },
    )

    private fun labels(name: String) =
        name.split(".").joinToString("") { "%02x".format(it.length) + it.toByteArray().joinToString("") { b -> "%02x".format(b) } } + "00"

    private fun tcp(from: InetAddress, fromPort: Int, to: InetAddress, toPort: Int, flags: Int, payload: ByteArray = ByteArray(0)) =
        PacketBuilder.tcp(from, fromPort, to, toPort, 1, 1, flags, payload)

    @Test
    fun `pairs DNS queries and responses and names later connections`() {
        val tracker = FlowTracker()
        assertNull(tracker.process(out(PacketBuilder.udp(app, 40000, virtualDns, 53, dnsQuery(7, "tracker.example")))))
        clock += 25_000
        val lookup = assertNotNull(
            tracker.process(inbound(PacketBuilder.udp(virtualDns, 53, app, 40000, dnsResponse(7, "tracker.example", "93.184.216.34")))),
        )

        assertEquals(uid, lookup.uid)
        assertEquals("tracker.example", lookup.domain)
        assertEquals(DnsType.A, lookup.type)
        assertEquals(listOf("93.184.216.34"), lookup.answers)
        assertEquals(25_001L, lookup.latencyMicros)

        tracker.process(out(tcp(app, 50000, server, 443, TcpFlags.SYN)))
        val flow = tracker.snapshot().first()
        assertEquals(IpProtocol.TCP, flow.protocol)
        assertEquals("tracker.example", flow.dnsName)
        assertEquals("tracker.example", flow.domain)
    }

    @Test
    fun `tracks bytes, SNI and close of a TLS connection`() {
        val tracker = FlowTracker()
        val syn = tcp(app, 50001, server, 443, TcpFlags.SYN)
        val synAck = tcp(server, 443, app, 50001, TcpFlags.SYN or TcpFlags.ACK)
        // The ClientHello arrives split over two segments.
        val hello = TlsSniTest.CLIENT_HELLO
        val part1 = tcp(app, 50001, server, 443, TcpFlags.ACK or TcpFlags.PSH, hello.copyOfRange(0, 60))
        val part2 = tcp(app, 50001, server, 443, TcpFlags.ACK or TcpFlags.PSH, hello.copyOfRange(60, hello.size))
        val data = tcp(server, 443, app, 50001, TcpFlags.ACK, ByteArray(1000))
        val fin = tcp(app, 50001, server, 443, TcpFlags.FIN or TcpFlags.ACK)

        for (record in listOf(out(syn), inbound(synAck), out(part1), out(part2), inbound(data), out(fin))) {
            tracker.process(record)
        }

        val flow = tracker.snapshot().single()
        assertEquals("www.example.com", flow.sni)
        assertEquals(uid, flow.uid)
        assertEquals((syn.size + part1.size + part2.size + fin.size).toLong(), flow.bytesOut)
        assertEquals((synAck.size + data.size).toLong(), flow.bytesIn)
        assertEquals(4, flow.packetsOut)
        assertEquals(2, flow.packetsIn)
        assertTrue(flow.closed)
        assertFalse(flow.encryptedDns)

        // Port reuse after close starts a new flow.
        tracker.process(out(syn))
        val flows = tracker.snapshot()
        assertEquals(2, flows.size)
        assertNotEquals(flows[0].id, flows[1].id)
        assertFalse(flows[0].closed)
    }

    @Test
    fun `flags blocked and encrypted DNS flows`() {
        val tracker = FlowTracker()
        tracker.process(out(tcp(app, 50002, InetAddress.getByName("8.8.8.8"), 853, TcpFlags.SYN), blocked = true))
        val dot = tracker.snapshot().single()
        assertTrue(dot.blocked)
        assertTrue(dot.encryptedDns)

        assertTrue(FlowTracker.isDohHost("dns.google"))
        assertTrue(FlowTracker.isDohHost("mozilla.cloudflare-dns.com"))
        assertFalse(FlowTracker.isDohHost("notdns.google.com"))
    }

    @Test
    fun `fills in the uid when the first packet had none`() {
        val tracker = FlowTracker()
        tracker.process(out(tcp(app, 50003, server, 80, TcpFlags.SYN), uid = CaptureBatch.UID_UNKNOWN))
        tracker.process(inbound(tcp(server, 80, app, 50003, TcpFlags.SYN or TcpFlags.ACK)))
        assertEquals(uid, tracker.snapshot().single().uid)
    }

    @Test
    fun `evicts the least recently active flows`() {
        val tracker = FlowTracker(maxFlows = 2)
        tracker.process(out(tcp(app, 1, server, 80, TcpFlags.SYN)))
        tracker.process(out(tcp(app, 2, server, 80, TcpFlags.SYN)))
        tracker.process(out(tcp(app, 1, server, 80, TcpFlags.ACK)))
        tracker.process(out(tcp(app, 3, server, 80, TcpFlags.SYN)))
        assertEquals(listOf(3, 1), tracker.snapshot().map { it.localPort })
    }
}
