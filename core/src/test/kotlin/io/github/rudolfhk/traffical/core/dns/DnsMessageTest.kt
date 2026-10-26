package io.github.rudolfhk.traffical.core.dns

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsMessageTest {

    // Query: id 0x1a2b, RD, www.example.com A
    private val query = hex(
        "1a2b 0100 0001 0000 0000 0000" +
            "03 777777 07 6578616d706c65 03 636f6d 00 0001 0001",
    )

    // Response with compressed names: CNAME www.example.com -> example.com, then A 93.184.216.34
    private val response = hex(
        "1a2b 8180 0001 0002 0000 0000" +
            "03 777777 07 6578616d706c65 03 636f6d 00 0001 0001" +
            "c00c 0005 0001 0000 012c 0002 c010" +
            "c010 0001 0001 0000 0e10 0004 5db8d822",
    )

    @Test
    fun `parses a query`() {
        val message = assertNotNull(DnsMessage.parse(query))
        assertEquals(0x1a2b, message.id)
        assertFalse(message.isResponse)
        assertEquals(listOf(DnsQuestion("www.example.com", DnsType.A)), message.questions)
        assertTrue(message.answers.isEmpty())
    }

    @Test
    fun `parses a response with compressed names`() {
        val message = assertNotNull(DnsMessage.parse(response))
        assertTrue(message.isResponse)
        assertEquals(0, message.rcode)
        assertEquals(
            listOf(
                DnsRecord("www.example.com", DnsType.CNAME, 300, "example.com"),
                DnsRecord("example.com", DnsType.A, 3600, "93.184.216.34"),
            ),
            message.answers,
        )
    }

    @Test
    fun `parses AAAA answers and NXDOMAIN`() {
        val aaaa = hex(
            "0001 8180 0001 0001 0000 0000" +
                "01 61 00 001c 0001" +
                "c00c 001c 0001 0000 003c 0010 2606 2800 0220 0001 0248 1893 25c8 1946",
        )
        assertEquals("2606:2800:220:1:248:1893:25c8:1946", DnsMessage.parse(aaaa)?.answers?.single()?.data)

        val nxdomain = hex("0002 8183 0001 0000 0000 0000 01 62 00 0001 0001")
        assertEquals(3, DnsMessage.parse(nxdomain)?.rcode)
    }

    @Test
    fun `parses at an offset`() {
        val buffer = ByteArray(9) + response
        assertEquals("www.example.com", DnsMessage.parse(buffer, 9, response.size)?.questions?.single()?.name)
    }

    @Test
    fun `rejects malformed messages`() {
        assertNull(DnsMessage.parse(query, 0, query.size - 1))
        assertNull(DnsMessage.parse(ByteArray(5)))
        // A compression pointer that points at itself.
        assertNull(DnsMessage.parse(hex("0000 0100 0001 0000 0000 0000 c00c 0001 0001")))
        // Answer data length beyond the end of the message.
        assertNull(DnsMessage.parse(hex("0000 8180 0000 0001 0000 0000 00 0001 0001 0000 0000 00ff 01")))
    }
}

private fun hex(s: String): ByteArray {
    val clean = s.filterNot { it.isWhitespace() }
    return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
