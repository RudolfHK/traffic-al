package io.github.rudolfhk.traffical.core.quic

import kotlin.test.Test
import kotlin.test.assertEquals

class QuicCryptoTest {

    private fun hex(s: String) = ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

    @Test
    fun `derives the Initial keys (RFC 9001 Appendix A vectors)`() {
        // The client's original destination connection ID from RFC 9001 Appendix A.
        val (client, server) = QuicCrypto.initialKeys(hex("8394c8f03e515708"))

        assertEquals("1f369613dd76d5467730efcbe3b1a22d", client.key.hex())
        assertEquals("fa044b2f42a3fd3b46fb255c", client.iv.hex())
        assertEquals("9f50449e04a0e810283a1e9933adedd2", client.hp.hex())

        assertEquals("cf3a5331653c364c88f0f379b6067e37", server.key.hex())
        assertEquals("0ac1493ca1905853b0bba03e", server.iv.hex())
        assertEquals("c206b8d9b9f0f37644430b490eeaa314", server.hp.hex())
    }
}
