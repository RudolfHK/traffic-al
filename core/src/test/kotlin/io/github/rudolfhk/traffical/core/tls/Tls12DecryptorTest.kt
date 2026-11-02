package io.github.rudolfhk.traffical.core.tls

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class Tls12DecryptorTest {

    private fun hex(s: String) = ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

    @Test
    fun `PRF matches the known SHA-256 test vector`() {
        // From the IETF TLS WG test vectors for the TLS 1.2 PRF (HMAC-SHA256).
        val secret = hex("9bbe436ba940f017b17652849a71db35")
        val seed = hex("a0ba9f936cda311827a6f796ffd5198c")
        val expected = "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791" +
            "e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f7967" +
            "89baa48082d122ee42c5a72e5a5110fff70187347b66"
        assertEquals(expected, Tls12Decryptor.prf(secret, "test label", seed, 100, "HmacSHA256").hex())
    }

    @Test
    fun `decrypt returns null without a ClientHello`() {
        assertNull(Tls12Decryptor.decrypt(ByteArray(0), ByteArray(0), TlsKeyLog.parse("")))
    }
}
