package io.github.rudolfhk.traffical.core.packet

import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class PacketTest {

    private val client4 = InetAddress.getByName("10.215.173.1")
    private val dns4 = InetAddress.getByName("10.215.173.2")
    private val client6 = InetAddress.getByName("fd00::1")
    private val dns6 = InetAddress.getByName("fd00::2")

    @Test
    fun `builds and parses an IPv4 UDP packet`() {
        val payload = "hello".toByteArray()
        val raw = PacketBuilder.udp(client4, 40000, dns4, 53, payload)

        val packet = assertNotNull(PacketParser.parse(raw))
        assertEquals(4, packet.ipVersion)
        assertEquals(IpProtocol.UDP, packet.protocol)
        assertEquals(client4, packet.source)
        assertEquals(dns4, packet.destination)
        assertEquals(40000, packet.sourcePort)
        assertEquals(53, packet.destinationPort)
        assertEquals(raw.size, packet.length)
        assertEquals("hello", String(raw, packet.payloadOffset, packet.payloadLength))
    }

    @Test
    fun `IPv4 header and UDP checksums verify`() {
        val raw = PacketBuilder.udp(client4, 40000, dns4, 53, "odd-length".toByteArray())
        assertEquals(0, Checksum.finish(Checksum.add(0, raw, 0, 20)))

        var sum = Checksum.add(0, raw, 12, 8) // pseudo header: addresses
        sum += IpProtocol.UDP + (raw.size - 20)
        sum = Checksum.add(sum, raw, 20, raw.size - 20)
        assertEquals(0, Checksum.finish(sum))
    }

    @Test
    fun `builds and parses an IPv6 UDP packet with a valid checksum`() {
        val raw = PacketBuilder.udp(dns6, 53, client6, 51515, ByteArray(33) { it.toByte() })

        val packet = assertNotNull(PacketParser.parse(raw))
        assertEquals(6, packet.ipVersion)
        assertEquals(dns6, packet.source)
        assertEquals(client6, packet.destination)
        assertEquals(51515, packet.destinationPort)
        assertEquals(33, packet.payloadLength)

        var sum = Checksum.add(0, raw, 8, 32)
        sum += IpProtocol.UDP + (raw.size - 40)
        sum = Checksum.add(sum, raw, 40, raw.size - 40)
        assertEquals(0, Checksum.finish(sum))
    }

    @Test
    fun `parses a TCP SYN with options`() {
        // 192.168.1.10:51000 -> 93.184.216.34:443, SYN, 12 bytes of TCP options
        val raw = hex(
            "4500 0034 1234 4000 4006 0000 c0a8 010a 5db8 d822" +
                "c738 01bb 0000 0001 0000 0000 8002 ffff 0000 0000" +
                "0204 05b4 0103 0308 0101 0402",
        )
        val packet = assertNotNull(PacketParser.parse(raw))
        assertEquals(IpProtocol.TCP, packet.protocol)
        assertEquals("93.184.216.34", packet.destination.hostAddress)
        assertEquals(51000, packet.sourcePort)
        assertEquals(443, packet.destinationPort)
        assertEquals(TcpFlags.SYN, packet.tcpFlags)
        assertEquals(0, packet.payloadLength)
    }

    @Test
    fun `skips IPv6 extension headers`() {
        val udp = PacketBuilder.udp(client6, 1000, dns6, 53, byteArrayOf(1, 2, 3))
        // Insert an 8-byte hop-by-hop header between the IPv6 header and UDP.
        val raw = udp.copyOfRange(0, 40) + byteArrayOf(17, 0, 0, 0, 0, 0, 0, 0) + udp.copyOfRange(40, udp.size)
        raw[6] = 0 // next header: hop-by-hop
        raw.put16(4, udp.size - 40 + 8)

        val packet = assertNotNull(PacketParser.parse(raw))
        assertEquals(IpProtocol.UDP, packet.protocol)
        assertEquals(53, packet.destinationPort)
        assertEquals(3, packet.payloadLength)
    }

    @Test
    fun `non-first IPv4 fragments carry no ports`() {
        val raw = PacketBuilder.udp(client4, 40000, dns4, 53, ByteArray(16))
        raw.put16(6, 0x0010) // fragment offset 16 * 8 bytes
        val packet = assertNotNull(PacketParser.parse(raw))
        assertEquals(0, packet.destinationPort)
        assertEquals(raw.size - 20, packet.payloadLength)
    }

    @Test
    fun `rejects truncated and non-IP data`() {
        val raw = PacketBuilder.udp(client4, 40000, dns4, 53, ByteArray(16))
        assertNull(PacketParser.parse(raw, 0, raw.size - 1))
        assertNull(PacketParser.parse(ByteArray(0)))
        assertNull(PacketParser.parse(byteArrayOf(0x20, 0, 0, 0)))
        assertNull(PacketParser.parse(raw, 0, 10))
    }

    @Test
    fun `parses at a buffer offset`() {
        val raw = PacketBuilder.udp(client4, 1, dns4, 53, ByteArray(4))
        val buffer = ByteArray(7) + raw + ByteArray(5)
        val packet = assertNotNull(PacketParser.parse(buffer, 7, raw.size))
        assertEquals(7 + 28, packet.payloadOffset)
        assertEquals(4, packet.payloadLength)
    }
}

internal fun hex(s: String): ByteArray {
    val clean = s.filterNot { it.isWhitespace() }
    return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
