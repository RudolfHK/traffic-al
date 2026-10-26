package io.github.rudolfhk.traffical.core.export

import io.github.rudolfhk.traffical.core.pcap.Pcap
import io.github.rudolfhk.traffical.core.pcap.Pcapng
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class UdpExporterTest {
    private val packet = ByteArray(60) { (it * 3).toByte() }

    @Test
    fun `PCAP stream is header then one record per datagram`() {
        val received = exchange(StreamFormat.PCAP, count = 3)
        assertContentEquals(Pcap.header(), received[0])
        for (i in 1..3) assertContentEquals(Pcap.record(i * 1_000_000L, packet), received[i])
    }

    @Test
    fun `PCAPNG stream carries the comment`() {
        val received = exchange(StreamFormat.PCAPNG, count = 2)
        assertContentEquals(Pcapng.header(), received[0])
        assertContentEquals(Pcapng.packet(1_000_000L, packet, comment = "uid=1 app=a"), received[1])
    }

    private fun exchange(format: StreamFormat, count: Int): List<ByteArray> =
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { receiver ->
            receiver.soTimeout = 5_000
            val target = InetSocketAddress(InetAddress.getLoopbackAddress(), receiver.localPort)
            UdpExporter(target, format).use { exporter ->
                for (i in 1..count) exporter.send(i * 1_000_000L, packet, "uid=1 app=a")
                assertEquals(count.toLong(), exporter.packets)
                assertEquals(0, exporter.errors)
            }
            List(count + 1) {
                val buffer = ByteArray(65_535)
                val datagram = DatagramPacket(buffer, buffer.size)
                receiver.receive(datagram)
                buffer.copyOf(datagram.length)
            }
        }
}
