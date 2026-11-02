package io.github.rudolfhk.traffical.core.tls

import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Decrypts the application data of a TLS 1.3 connection from keys the device owner supplies
 * (the phase-8 key log). Traffic AL never derives these keys; with them (obtainable with
 * root) it can show the owner what their own encrypted traffic contains. This is the "with
 * root" half of the human-readable packets feature (docs/DECRYPTION.md, docs/PROMPT.md).
 *
 * Only TLS 1.3 with an AES-GCM or ChaCha20-Poly1305 cipher is handled; TLS 1.2 and QUIC are
 * not. It reassembles each direction's record stream from the captured payloads (in capture
 * order) and, for every application record, tries the application traffic secret at the next
 * sequence number: a record that authenticates is application data (the plaintext is kept),
 * one that does not is an encrypted handshake record (skipped). Nothing leaves the device.
 */
object Tls13Decryptor {

    /** The decrypted application bytes of each direction. */
    class Transcript(val clientToServer: ByteArray, val serverToClient: ByteArray, val records: Int) {
        val isEmpty: Boolean get() = clientToServer.isEmpty() && serverToClient.isEmpty()
    }

    private class Suite(val keyLength: Int, val hash: String, val aead: Aead)
    private enum class Aead { AES_GCM, CHACHA20_POLY1305 }

    private val SUITES = mapOf(
        0x1301 to Suite(16, "HmacSHA256", Aead.AES_GCM),          // TLS_AES_128_GCM_SHA256
        0x1302 to Suite(32, "HmacSHA384", Aead.AES_GCM),          // TLS_AES_256_GCM_SHA384
        0x1303 to Suite(32, "HmacSHA256", Aead.CHACHA20_POLY1305), // TLS_CHACHA20_POLY1305_SHA256
    )

    /**
     * Decrypts the connection whose client stream starts with the ClientHello and whose
     * server stream starts with the ServerHello. Returns null if the keys aren't in [keyLog],
     * the cipher isn't supported, or it is not TLS 1.3.
     */
    fun decrypt(clientStream: ByteArray, serverStream: ByteArray, keyLog: TlsKeyLog): Transcript? {
        val clientRandom = TlsClientHello.clientRandom(clientStream) ?: return null
        val cipher = serverHelloCipherSuite(serverStream) ?: return null
        val suite = SUITES[cipher] ?: return null

        val secrets = keyLog.entries.filter { it.clientRandom == clientRandom }.associate { it.label to it.secret }
        val clientSecret = secrets["CLIENT_TRAFFIC_SECRET_0"]?.let(::hex) ?: return null
        val serverSecret = secrets["SERVER_TRAFFIC_SECRET_0"]?.let(::hex) ?: return null

        return try {
            val toServer = decryptStream(clientStream, clientSecret, suite)
            val toClient = decryptStream(serverStream, serverSecret, suite)
            Transcript(toServer.first, toClient.first, toServer.second + toClient.second)
        } catch (e: Exception) {
            null // unsupported JCE algorithm (e.g. ChaCha20 before API 28), or malformed input
        }
    }

    /** The decrypted application bytes of one direction, and how many records were decrypted. */
    private fun decryptStream(stream: ByteArray, secret: ByteArray, suite: Suite): Pair<ByteArray, Int> {
        val key = hkdfExpandLabel(secret, "key", suite.keyLength, suite.hash)
        val iv = hkdfExpandLabel(secret, "iv", 12, suite.hash)
        val output = java.io.ByteArrayOutputStream()
        var seq = 0L
        var decrypted = 0
        var pos = 0
        while (pos + 5 <= stream.size) {
            val type = stream[pos].toInt() and 0xff
            val length = ((stream[pos + 3].toInt() and 0xff) shl 8) or (stream[pos + 4].toInt() and 0xff)
            val bodyStart = pos + 5
            if (bodyStart + length > stream.size) break // truncated record
            // 0x14 ChangeCipherSpec and plaintext 0x16 handshake records are skipped; only
            // application_data records (which wrap the encrypted handshake and the app data).
            if (type == 0x17 && length >= 16) {
                val header = stream.copyOfRange(pos, bodyStart)
                val plaintext = tryDecrypt(stream, bodyStart, length, key, iv, seq, header, suite)
                if (plaintext != null) {
                    seq++
                    decrypted++
                    val inner = innerContent(plaintext)
                    if (inner != null && inner.second == 0x17) output.write(inner.first)
                }
            }
            pos = bodyStart + length
        }
        return output.toByteArray() to decrypted
    }

    private fun tryDecrypt(
        stream: ByteArray, bodyStart: Int, length: Int, key: ByteArray, iv: ByteArray, seq: Long, header: ByteArray, suite: Suite,
    ): ByteArray? {
        val nonce = iv.copyOf()
        val seqBytes = ByteBuffer.allocate(8).putLong(seq).array()
        for (i in 0 until 8) nonce[4 + i] = (nonce[4 + i].toInt() xor seqBytes[i].toInt()).toByte()
        return try {
            when (suite.aead) {
                Aead.AES_GCM -> Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                    updateAAD(header)
                    doFinal(stream, bodyStart, length)
                }
                Aead.CHACHA20_POLY1305 -> Cipher.getInstance("ChaCha20-Poly1305").run {
                    init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
                    updateAAD(header)
                    doFinal(stream, bodyStart, length)
                }
            }
        } catch (e: javax.crypto.AEADBadTagException) {
            null // wrong key/seq: an encrypted handshake record, not application data
        }
    }

    /** Strips the TLS 1.3 inner plaintext padding; returns (content, real content type). */
    private fun innerContent(plaintext: ByteArray): Pair<ByteArray, Int>? {
        var end = plaintext.size - 1
        while (end >= 0 && plaintext[end].toInt() == 0) end-- // zero padding
        if (end < 0) return null
        return plaintext.copyOfRange(0, end) to (plaintext[end].toInt() and 0xff)
    }

    /** The cipher suite from the ServerHello at the start of [serverStream], or null. */
    private fun serverHelloCipherSuite(serverStream: ByteArray): Int? {
        // Record: type(1)=0x16, version(2), length(2); handshake: type(1)=2, length(3);
        // ServerHello: version(2), random(32), session_id(1+len), cipher_suite(2).
        if (serverStream.size < 44 || serverStream[0].toInt() and 0xff != 0x16) return null
        if (serverStream[5].toInt() and 0xff != 2) return null
        val sidLen = serverStream[5 + 4 + 2 + 32].toInt() and 0xff
        val cipherAt = 5 + 4 + 2 + 32 + 1 + sidLen
        if (cipherAt + 2 > serverStream.size) return null
        return ((serverStream[cipherAt].toInt() and 0xff) shl 8) or (serverStream[cipherAt + 1].toInt() and 0xff)
    }

    /** The write key and IV for a traffic secret and cipher suite (for tests). */
    internal fun keyAndIv(secret: ByteArray, cipherSuite: Int): Pair<ByteArray, ByteArray>? {
        val suite = SUITES[cipherSuite] ?: return null
        return hkdfExpandLabel(secret, "key", suite.keyLength, suite.hash) to hkdfExpandLabel(secret, "iv", 12, suite.hash)
    }

    /** HKDF-Expand-Label (RFC 8446 7.1) with an empty context. */
    private fun hkdfExpandLabel(secret: ByteArray, label: String, length: Int, hash: String): ByteArray {
        val fullLabel = "tls13 $label".toByteArray(Charsets.US_ASCII)
        val info = ByteBuffer.allocate(2 + 1 + fullLabel.size + 1)
            .putShort(length.toShort())
            .put(fullLabel.size.toByte()).put(fullLabel)
            .put(0) // empty context
            .array()
        return hkdfExpand(secret, info, length, hash)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int, hash: String): ByteArray {
        val mac = Mac.getInstance(hash)
        val output = ByteArray(length)
        var previous = ByteArray(0)
        var filled = 0
        var counter = 1
        while (filled < length) {
            mac.init(SecretKeySpec(prk, hash))
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            previous = mac.doFinal()
            val take = minOf(previous.size, length - filled)
            previous.copyInto(output, filled, 0, take)
            filled += take
            counter++
        }
        return output
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }
}
