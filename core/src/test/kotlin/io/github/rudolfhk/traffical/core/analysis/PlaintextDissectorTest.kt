package io.github.rudolfhk.traffical.core.analysis

import io.github.rudolfhk.traffical.core.packet.IpProtocol
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PlaintextDissectorTest {
    private fun hex(s: String): ByteArray {
        val clean = s.filterNot { it.isWhitespace() }
        return ByteArray(clean.length / 2) { ((clean[it * 2].digitToInt(16) shl 4) or clean[it * 2 + 1].digitToInt(16)).toByte() }
    }

    private fun bytes(s: String) = s.toByteArray(Charsets.ISO_8859_1)

    @Test
    fun `http 1_1 request and response`() {
        val body = "{\"password\":\"hunter2secret\"}"
        val request = bytes(
            "POST /api/login?email=user@example.test HTTP/1.1\r\n" +
                "Host: api.example.test\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: ${body.length}\r\n\r\n$body",
        )
        val response = bytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok")

        val d = PlaintextDissector.dissect(request, response, IpProtocol.TCP)
        assertEquals(HttpProtocol.HTTP_1, d.protocol)
        val req = d.requests.single()
        assertEquals("POST", req.method)
        assertEquals("api.example.test", req.authority)
        assertEquals("/api/login?email=user@example.test", req.path)
        assertEquals("application/json", req.contentType)
        assertTrue(req.bodyPreview.contains("hunter2secret"))
        assertEquals(200, d.responses.single().status)
    }

    @Test
    fun `http 2 request with hpack headers and data`() {
        // Preface + HEADERS(stream 1): :method POST, :scheme https, :path /submit,
        // :authority h2.test (all via indexed/literal HPACK) + DATA "hello".
        val preface = bytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        val headerBlock = "83 87 44 07 2f7375626d6974 41 07 68322e74657374"
        val headersFrame = hex("000014 01 04 00000001") + hex(headerBlock)
        val dataFrame = hex("000005 00 01 00000001") + bytes("hello")
        val toServer = preface + headersFrame + dataFrame
        // Server: HEADERS(stream 1) :status 200 (indexed 8).
        val toClient = hex("000001 01 04 00000001 88")

        val d = PlaintextDissector.dissect(toServer, toClient, IpProtocol.TCP)
        assertEquals(HttpProtocol.HTTP_2, d.protocol)
        val req = d.requests.single()
        assertEquals("POST", req.method)
        assertEquals("h2.test", req.authority)
        assertEquals("/submit", req.path)
        assertEquals("hello", req.bodyPreview)
        assertEquals(200, d.responses.single().status)
    }

    @Test
    fun `http 3 stream data over quic`() {
        // HTTP/3 HEADERS frame (type 1, opaque QPACK) + DATA frame (type 0) "h3body".
        val toServer = hex("01 03 aabbcc 00 06") + bytes("h3body")
        val d = PlaintextDissector.dissect(toServer, ByteArray(0), IpProtocol.UDP)
        assertEquals(HttpProtocol.HTTP_3, d.protocol)
        val req = d.requests.single()
        assertEquals("h3body", req.bodyPreview)
        assertTrue(req.headers.any { it.value.contains("QPACK", ignoreCase = true) })
    }

    @Test
    fun `non-http bytes give an empty dissection`() {
        val d = PlaintextDissector.dissect(hex("16030100a0"), hex("1603030040"), IpProtocol.TCP)
        assertTrue(d.isEmpty)
    }
}
