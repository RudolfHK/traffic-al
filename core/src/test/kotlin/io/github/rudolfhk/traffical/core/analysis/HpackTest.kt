package io.github.rudolfhk.traffical.core.analysis

import kotlin.test.Test
import kotlin.test.assertEquals

/** HPACK decoder against the RFC 7541 examples (Appendix C). */
class HpackTest {
    private fun hex(s: String): ByteArray {
        val clean = s.filterNot { it.isWhitespace() }
        return ByteArray(clean.length / 2) { ((clean[it * 2].digitToInt(16) shl 4) or clean[it * 2 + 1].digitToInt(16)).toByte() }
    }

    private fun List<HttpHeader>.pairs() = map { it.name to it.value }

    @Test
    fun `huffman decodes a known string`() {
        // RFC 7541 C.4.1: the Huffman coding of "www.example.com".
        assertEquals("www.example.com", Hpack.huffman(hex("f1e3c2e5f23a6ba0ab90f4ff")))
    }

    @Test
    fun `C_3 request sequence without huffman`() {
        val d = HpackDecoder()
        assertEquals(
            listOf(":method" to "GET", ":scheme" to "http", ":path" to "/", ":authority" to "www.example.com"),
            d.decode(hex("828684410f7777772e6578616d706c652e636f6d")).pairs(),
        )
        assertEquals(
            listOf(":method" to "GET", ":scheme" to "http", ":path" to "/", ":authority" to "www.example.com",
                "cache-control" to "no-cache"),
            d.decode(hex("828684be58086e6f2d6361636865")).pairs(),
        )
        assertEquals(
            listOf(":method" to "GET", ":scheme" to "https", ":path" to "/index.html", ":authority" to "www.example.com",
                "custom-key" to "custom-value"),
            d.decode(hex("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565")).pairs(),
        )
    }

    @Test
    fun `C_4 request sequence with huffman`() {
        val d = HpackDecoder()
        assertEquals(
            listOf(":method" to "GET", ":scheme" to "http", ":path" to "/", ":authority" to "www.example.com"),
            d.decode(hex("828684418cf1e3c2e5f23a6ba0ab90f4ff")).pairs(),
        )
        assertEquals(
            listOf(":method" to "GET", ":scheme" to "http", ":path" to "/", ":authority" to "www.example.com",
                "cache-control" to "no-cache"),
            d.decode(hex("828684be5886a8eb10649cbf")).pairs(),
        )
        assertEquals(
            listOf(":method" to "GET", ":scheme" to "https", ":path" to "/index.html", ":authority" to "www.example.com",
                "custom-key" to "custom-value"),
            d.decode(hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf")).pairs(),
        )
    }

    @Test
    fun `C_6_1 response with huffman and a small dynamic table`() {
        // SETTINGS_HEADER_TABLE_SIZE = 256.
        val d = HpackDecoder(256)
        val block = hex(
            "488264025885aec3771a4b6196d07abe941054d444a8" +
                "20059504 0b8166e0 82a62d1b ff6e919d 29ad1718 63c78f0b 97c8e9ae 82ae43d3",
        )
        assertEquals(
            listOf(
                ":status" to "302",
                "cache-control" to "private",
                "date" to "Mon, 21 Oct 2013 20:13:21 GMT",
                "location" to "https://www.example.com",
            ),
            d.decode(block).pairs(),
        )
    }
}
