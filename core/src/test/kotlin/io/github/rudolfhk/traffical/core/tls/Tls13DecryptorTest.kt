package io.github.rudolfhk.traffical.core.tls

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class Tls13DecryptorTest {

    private fun hex(s: String) = ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

    @Test
    fun `derives the write key and IV (RFC 8448 vectors)`() {
        // RFC 8448, server handshake traffic secret -> write key and IV (TLS_AES_128_GCM_SHA256).
        val secret = hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        val (key, iv) = Tls13Decryptor.keyAndIv(secret, 0x1301)!!
        assertEquals("3fce516009c21727d0f2e4e86ee403bc", key.hex())
        assertEquals("5d313eb2671276ee13000b30", iv.hex())
    }

    @Test
    fun `derives the 256-bit key for AES_256_GCM_SHA384`() {
        val secret = hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        val (key, iv) = Tls13Decryptor.keyAndIv(secret, 0x1302)!!
        assertEquals(32, key.size)
        assertEquals(12, iv.size)
    }

    @Test
    fun `returns null for an unsupported cipher suite`() {
        assertNull(Tls13Decryptor.keyAndIv(ByteArray(32), 0x00ff))
    }

    @Test
    fun `decrypt returns null without a ClientHello`() {
        assertNull(Tls13Decryptor.decrypt(ByteArray(0), ByteArray(0), TlsKeyLog.parse("")))
    }
}
