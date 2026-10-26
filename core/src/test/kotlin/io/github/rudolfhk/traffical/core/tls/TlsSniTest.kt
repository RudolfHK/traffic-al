package io.github.rudolfhk.traffical.core.tls

import kotlin.test.Test
import kotlin.test.assertEquals

class TlsSniTest {

    @Test
    fun `extracts the server name from a real ClientHello`() {
        assertEquals(SniResult.Found("www.example.com"), TlsSni.parse(CLIENT_HELLO))
    }

    @Test
    fun `asks for more data while the ClientHello is incomplete`() {
        assertEquals(SniResult.Incomplete, TlsSni.parse(CLIENT_HELLO, 0, 4))
        assertEquals(SniResult.Incomplete, TlsSni.parse(CLIENT_HELLO, 0, 100))
        assertEquals(SniResult.Found("www.example.com"), TlsSni.parse(CLIENT_HELLO, 0, 200))
    }

    @Test
    fun `parses at an offset`() {
        val buffer = ByteArray(11) + CLIENT_HELLO
        assertEquals(SniResult.Found("www.example.com"), TlsSni.parse(buffer, 11, CLIENT_HELLO.size))
    }

    @Test
    fun `reports absent SNI for other protocols and hellos without the extension`() {
        assertEquals(SniResult.Absent, TlsSni.parse("GET / HTTP/1.1\r\n".toByteArray()))

        // Minimal ClientHello: no session id, one cipher suite, null compression, no extensions.
        val noExtensions = hex(
            "16 0301 002d 01 000029 0303" + "00".repeat(32) + "00 0002 1301 01 00",
        )
        assertEquals(SniResult.Absent, TlsSni.parse(noExtensions))
    }

    companion object {
        // Generated with Python's ssl module for server_hostname="www.example.com".
        val CLIENT_HELLO = hex(
            "1603010200010001fc030353e5db486d28e6425203ba14307d7c927d74ba41011e9121b727856351b16e" +
                "1720384c51a4782ce87972451f5c2c8df3827275db1ef7bf07fe39f12eb9c408d7950024130213031301" +
                "c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f00000014001200" +
                "000f7777772e6578616d706c652e636f6d000b000403000102000a00160014001d0017001e0019001801" +
                "000101010201030104002300000016000000170000000d002a0028040305030603080708080809080a08" +
                "0b080408050806040105010601030303010302040205020602002b00050403040303002d00020101" +
                "003300260024001d0020c171ae7b50e3a17a42b2e34c7fbad4c8a717422b10b6157a3e24b8c5e6280d" +
                "7f001500de" + "00".repeat(0xde),
        )

        fun hex(s: String): ByteArray {
            val clean = s.filterNot { it.isWhitespace() }
            return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        }
    }
}
