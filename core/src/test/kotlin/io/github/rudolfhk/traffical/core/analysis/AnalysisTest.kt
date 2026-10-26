package io.github.rudolfhk.traffical.core.analysis

import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.capture.Direction
import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import io.github.rudolfhk.traffical.core.packet.PacketBuilder
import io.github.rudolfhk.traffical.core.packet.TcpFlags
import java.net.InetAddress
import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AnalysisTest {

    private val app = InetAddress.getByName("10.215.173.1")
    private val server = InetAddress.getByName("93.184.216.34")
    private val now = 1_800_000_000_000_000L // µs
    private val nowSecond = now / 1_000_000

    private fun flow(
        id: Long = 1,
        uid: Int = 10100,
        remotePort: Int = 443,
        protocol: Int = IpProtocol.TCP,
        sni: String? = null,
        dnsName: String? = null,
        lastSeen: Long = now,
        appProtocol: String? = null,
        category: String? = null,
        breed: String? = null,
        blocked: Boolean = false,
        encryptedDns: Boolean = false,
    ) = FlowInfo(
        id = id, uid = uid, ipVersion = 4, protocol = protocol,
        localAddress = app, localPort = 40000 + id.toInt(), remoteAddress = server, remotePort = remotePort,
        sni = sni, dnsName = dnsName, bytesOut = 100, bytesIn = 1000, packetsOut = 1, packetsIn = 1,
        firstSeenMicros = lastSeen - 1_000_000, lastSeenMicros = lastSeen,
        blocked = blocked, closed = false, encryptedDns = encryptedDns,
        appProtocol = appProtocol, category = category, breed = breed,
    )

    @Test
    fun `timeline sums windows, rates and series`() {
        val timeline = TrafficTimeline()
        for (s in 0 until 120) {
            timeline.add((nowSecond - s) * 1_000_000 + 500, uid = 1, outgoing = true, bytes = 100)
            timeline.add((nowSecond - s) * 1_000_000 + 600, uid = 2, outgoing = false, bytes = 1000)
        }

        assertEquals(TrafficTotals(6000, 60000), timeline.totals(nowSecond, 60))
        assertEquals(TrafficTotals(12000, 120000), timeline.totals(nowSecond, null))
        assertEquals(TrafficTotals(100, 1000), timeline.rate(nowSecond))
        assertEquals(TrafficTotals(100, 0), timeline.rate(nowSecond, uid = 1))
        assertEquals(TrafficTotals(), timeline.rate(nowSecond, uid = 3))

        val byUid = timeline.totalsByUid(nowSecond, 60)
        // 10-second buckets: the window start rounds down to a bucket boundary
        assertTrue(byUid.getValue(1).bytesOut in 6000L..7000L)
        assertEquals(TrafficTotals(12000, 0), timeline.totalsByUid(nowSecond, null).getValue(1))

        val series = timeline.series(nowSecond, 60, points = 30)
        assertEquals(30, series.size)
        assertEquals(TrafficPoint((nowSecond - 1) * 1000, 200, 2000), series.last())
    }

    @Test
    fun `timeline forgets data older than its buckets`() {
        val timeline = TrafficTimeline()
        timeline.add((nowSecond - 4000) * 1_000_000, uid = 1, outgoing = true, bytes = 50)
        timeline.add(now, uid = 1, outgoing = true, bytes = 7)
        assertEquals(TrafficTotals(7, 0), timeline.totals(nowSecond, 3600))
        assertEquals(TrafficTotals(57, 0), timeline.totals(nowSecond, null))
    }

    @Test
    fun `flags trackers, risky and unnamed destinations`() {
        assertEquals(setOf(FlowFlag.TRACKER), flow(sni = "ads.example", breed = "Tracker_Ads").flags())
        assertEquals(setOf(FlowFlag.TRACKER), flow(sni = "ads.example", category = "Advertisement").flags())
        assertEquals(setOf(FlowFlag.RISKY), flow(sni = "x.example", breed = "Dangerous").flags())
        assertEquals(setOf(FlowFlag.UNNAMED), flow().flags())
        assertEquals(emptySet(), flow(dnsName = "named.example", breed = "Safe").flags())
        assertEquals(emptySet(), flow(remotePort = 53, protocol = IpProtocol.UDP).flags())
        assertEquals(setOf(FlowFlag.BLOCKED, FlowFlag.ENCRYPTED_DNS), flow(blocked = true, encryptedDns = true).flags())
    }

    @Test
    fun `filters by text, protocol, port, time and attention`() {
        val tls = flow(id = 1, sni = "api.example.com", appProtocol = "TLS.Google", category = "Web")
        val quic = flow(id = 2, protocol = IpProtocol.UDP, appProtocol = "QUIC.YouTube", dnsName = "rr1.googlevideo.com")
        val old = flow(id = 3, sni = "old.example", lastSeen = now - 600_000_000)

        fun ConnectionFilter.ids(appLabel: String = "Chrome") =
            listOf(tls, quic, old).filter { matches(it, appLabel, "com.android.chrome", now) }.map { it.id }

        assertEquals(listOf(1L, 2L, 3L), ConnectionFilter().ids())
        assertEquals(listOf(1L), ConnectionFilter(text = "api google").ids())
        assertEquals(listOf(2L), ConnectionFilter(text = "googlevideo").ids())
        assertEquals(listOf(1L, 2L, 3L), ConnectionFilter(text = "chrome").ids())
        assertEquals(emptyList(), ConnectionFilter(text = "firefox").ids())
        assertEquals(listOf(2L), ConnectionFilter(protocol = "QUIC").ids())
        assertEquals(listOf(2L), ConnectionFilter(protocol = "udp").ids())
        assertEquals(listOf(1L, 3L), ConnectionFilter(protocol = "TCP").ids())
        assertEquals(listOf(1L, 2L, 3L), ConnectionFilter(port = 443).ids())
        assertEquals(listOf(1L, 2L), ConnectionFilter(timeRange = TimeRange.FIVE_MINUTES).ids())
        assertEquals(emptyList(), ConnectionFilter(uid = 1).ids())
        assertEquals(listOf(4L), listOf(flow(id = 4), tls).filter {
            ConnectionFilter(attentionOnly = true).matches(it, "x", null, now)
        }.map { it.id })
        assertTrue(ConnectionFilter(timeRange = TimeRange.HOUR).isEmpty)
        assertFalse(ConnectionFilter(port = 1).isEmpty)
    }

    @Test
    fun `dashboard ranks apps by bytes in the range`() {
        val timeline = TrafficTimeline()
        timeline.add(now - 2_000_000, uid = 1, outgoing = false, bytes = 5000)
        timeline.add(now - 2_000_000, uid = 2, outgoing = true, bytes = 300)
        timeline.add(now - 3_000_000_000, uid = 3, outgoing = true, bytes = 9999) // 50 min ago
        val flows = listOf(
            flow(id = 1, uid = 1, sni = "a.example"),
            flow(id = 2, uid = 1, sni = "a.example"),
            flow(id = 3, uid = 2), // unnamed
            flow(id = 4, uid = 3, sni = "c.example", lastSeen = now - 3_000_000_000),
        )

        val minute = dashboard(flows, timeline, TimeRange.MINUTE, now)
        assertEquals(listOf(1, 2), minute.apps.map { it.uid })
        assertEquals(AppTraffic(1, 0, 5000, connections = 2, domains = 1, attention = 0, rate = 1000), minute.apps[0])
        assertEquals(1, minute.apps[1].attention)
        assertEquals(TrafficTotals(300, 5000), minute.totals)
        assertEquals(3, minute.connections)
        assertEquals(1, minute.attention)

        val all = dashboard(flows, timeline, TimeRange.ALL, now)
        assertEquals(listOf(3, 1, 2), all.apps.map { it.uid })
        assertEquals(4, all.connections)
    }

    @Test
    fun `formats sizes, rates and durations`() {
        val us = Locale.US
        assertEquals("999 B", Format.bytes(999, us))
        assertEquals("1.2 kB", Format.bytes(1234, us))
        assertEquals("53 MB", Format.bytes(52_639_815, us))
        assertEquals("1.0 MB", Format.bytes(999_999, us))
        assertEquals("1,5 MB", Format.bytes(1_500_000, Locale.GERMANY))
        assertEquals("12 kB/s", Format.rate(12_345, us))
        assertEquals("850 ms", Format.duration(850_000, us))
        assertEquals("12.3 s", Format.duration(12_300_000, us))
        assertEquals("3 min 05 s", Format.duration(185_000_000, us))
        assertEquals("1 h 02 min", Format.duration(3_720_000_000, us))
    }

    @Test
    fun `hex dump shows offsets, hex and ASCII`() {
        val lines = HexDump.lines("GET / HTTP/1.1\r\nHost: x\r\n".toByteArray())
        assertEquals(
            listOf(
                "0000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1..",
                "0010  48 6f 73 74 3a 20 78 0d  0a                       Host: x..",
            ),
            lines,
        )
    }

    @Test
    fun `finds the packets of a connection`() {
        val flow = flow(id = 7).copy(firstSeenMicros = now, lastSeenMicros = now + 10)
        val request = PacketBuilder.tcp(app, flow.localPort, server, 443, 1, 1, TcpFlags.ACK or TcpFlags.PSH, "hi".toByteArray())
        val reply = PacketBuilder.tcp(server, 443, app, flow.localPort, 1, 3, TcpFlags.ACK, "ok!".toByteArray())
        val other = PacketBuilder.tcp(app, flow.localPort + 1, server, 443, 1, 1, TcpFlags.SYN)
        val records = listOf(
            CaptureRecord(now, 1, Direction.OUT, false, request),
            CaptureRecord(now + 1, 1, Direction.OUT, false, other),
            CaptureRecord(now + 2, 1, Direction.IN, false, reply),
            CaptureRecord(now + 20, 1, Direction.OUT, false, request), // after the flow: port reused
        )

        val packets = packetsOf(flow, records)
        assertEquals(listOf(Direction.OUT, Direction.IN), packets.map { it.direction })
        assertEquals("hi", String(packets[0].payload))
        assertEquals("ok!", String(packets[1].payload))
        assertEquals(TcpFlags.ACK, packets[1].tcpFlags)
    }
}
