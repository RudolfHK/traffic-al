package io.github.rudolfhk.traffical.core.analysis

import io.github.rudolfhk.traffical.core.capture.SyntheticTraffic
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PacketDecoderTest {

    @Test
    fun `decodes a DNS query`() {
        val query = dnsQuery("example.com")
        val decoded = PacketDecoder.decode(query, IpProtocol.UDP, remotePort = 53)
        assertEquals("DNS query A example.com", decoded.summary)
        assertTrue(decoded.lines.any { it.contains("example.com") })
    }

    @Test
    fun `decodes an HTTP request with headers`() {
        val request = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n".toByteArray()
        val decoded = PacketDecoder.decode(request, IpProtocol.TCP, remotePort = 80)
        assertEquals("HTTP GET /index.html HTTP/1.1", decoded.summary)
        assertTrue(decoded.lines.contains("Host: example.com"))
        assertTrue(decoded.lines.contains("Accept: */*"))
    }

    @Test
    fun `decodes a TLS ClientHello and shows the server name`() {
        val hello = SyntheticTraffic.clientHello("secure.example.com")
        val decoded = PacketDecoder.decode(hello, IpProtocol.TCP, remotePort = 443)
        assertTrue(decoded.summary.contains("ClientHello"), decoded.summary)
        assertTrue(decoded.summary.contains("secure.example.com"), decoded.summary)
    }

    @Test
    fun `marks TLS application data as encrypted`() {
        val appData = byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5)
        val decoded = PacketDecoder.decode(appData, IpProtocol.TCP, remotePort = 443)
        assertTrue(decoded.summary.contains("application data"), decoded.summary)
        assertTrue(decoded.summary.contains("encrypted"), decoded.summary)
    }

    @Test
    fun `falls back for binary data and never throws on garbage`() {
        val binary = ByteArray(64) { (it * 37 + 128).toByte() }
        assertTrue(PacketDecoder.decode(binary, IpProtocol.TCP, remotePort = 1234).summary.contains("bytes"))
        assertEquals("no payload", PacketDecoder.decode(ByteArray(0), IpProtocol.TCP, remotePort = 443).summary)
        // A truncated TLS record must not throw.
        PacketDecoder.decode(byteArrayOf(0x16, 0x03, 0x01, 0x05, 0x00), IpProtocol.TCP, remotePort = 443)
    }

    private fun dnsQuery(name: String): ByteArray {
        val out = ArrayList<Byte>()
        fun u16(v: Int) { out.add((v ushr 8).toByte()); out.add(v.toByte()) }
        u16(0x1234); u16(0x0100); u16(1); u16(0); u16(0); u16(0)
        for (label in name.split(".")) {
            out.add(label.length.toByte())
            out.addAll(label.toByteArray(Charsets.US_ASCII).toList())
        }
        out.add(0)
        u16(1); u16(1)
        return out.toByteArray()
    }
}
