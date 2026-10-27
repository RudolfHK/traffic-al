package io.github.rudolfhk.traffical.core.tls

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TlsKeyLogTest {

    private val randomA = "a".repeat(64)
    private val randomB = "b".repeat(64)

    private val sample = """
        # a comment, and a blank line follow

        CLIENT_RANDOM $randomA ${"1".repeat(96)}
        CLIENT_HANDSHAKE_TRAFFIC_SECRET $randomB ${"2".repeat(64)}
        SERVER_HANDSHAKE_TRAFFIC_SECRET $randomB ${"3".repeat(64)}
        CLIENT_TRAFFIC_SECRET_0 $randomB ${"4".repeat(64)}
        SERVER_TRAFFIC_SECRET_0 $randomB ${"5".repeat(64)}
    """.trimIndent()

    @Test
    fun parsesLabelsAndSessions() {
        val log = TlsKeyLog.parse(sample)
        assertEquals(5, log.entries.size)
        assertEquals(setOf(randomA, randomB), log.sessions)
    }

    @Test
    fun ignoresCommentsBlankAndMalformedLines() {
        val log = TlsKeyLog.parse(
            """
            # comment
            CLIENT_RANDOM tooshort ${"1".repeat(96)}
            NOT_A_LABEL $randomA ${"1".repeat(96)}
            CLIENT_RANDOM $randomA nothex_zz${"1".repeat(87)}
            CLIENT_RANDOM $randomA
            CLIENT_RANDOM $randomA ${"1".repeat(96)}
            """.trimIndent(),
        )
        assertEquals(1, log.entries.size)
        assertEquals(randomA, log.entries.single().clientRandom)
    }

    @Test
    fun deduplicatesIdenticalLines() {
        val line = "CLIENT_RANDOM $randomA ${"1".repeat(96)}"
        assertEquals(1, TlsKeyLog.parse("$line\n$line\n").entries.size)
    }

    @Test
    fun textForEmbedsOnlyWantedSessions() {
        val log = TlsKeyLog.parse(sample)
        val text = log.textFor(setOf(randomB))
        assertEquals(4, text.trimEnd('\n').count { it == '\n' } + 1)
        assertTrue(text.endsWith("\n"))
        assertTrue(text.lineSequence().filter { it.isNotEmpty() }.all { randomB in it })
        assertEquals("", log.textFor(setOf("c".repeat(64))))
    }

    @Test
    fun readsClientRandomFromAClientHello() {
        val random = ByteArray(32) { it.toByte() }
        val hello = byteArrayOf(
            0x16, 0x03, 0x01, 0x00, 0x2b, // TLS record: handshake, version, length
            0x01, 0x00, 0x00, 0x27,       // handshake: client_hello, length
            0x03, 0x03,                   // client_version
        ) + random + ByteArray(8)         // session_id length byte and some trailing bytes
        assertEquals("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            TlsClientHello.clientRandom(hello))
    }

    @Test
    fun rejectsNonClientHello() {
        assertNull(TlsClientHello.clientRandom(ByteArray(64))) // not a handshake record
        assertNull(TlsClientHello.clientRandom(byteArrayOf(0x16, 0x03, 0x01))) // too short
        val appData = byteArrayOf(0x17, 0x03, 0x03) + ByteArray(60)
        assertNull(TlsClientHello.clientRandom(appData))
    }
}
