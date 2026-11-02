package io.github.rudolfhk.traffical.core.tls

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Decrypts the application data of a TLS 1.2 connection from the master secret the device
 * owner supplies (a `CLIENT_RANDOM` key-log line, see [Tls13Decryptor] and phase 11). Only
 * the AEAD cipher suites (AES-GCM and ChaCha20-Poly1305) are handled — the ones a current
 * TLS 1.2 handshake negotiates. Legacy CBC suites are not. Nothing leaves the device.
 *
 * Unlike TLS 1.3 the record type is in the clear, so the decryptor finds each direction's
 * ChangeCipherSpec and decrypts the application records after it with a sequence number that
 * counts every record from there.
 */
object Tls12Decryptor {

    class Transcript(val clientToServer: ByteArray, val serverToClient: ByteArray, val records: Int) {
        val isEmpty: Boolean get() = clientToServer.isEmpty() && serverToClient.isEmpty()
    }

    private enum class Aead { AES_GCM, CHACHA20_POLY1305 }

    /** [fixedIvLength] is the implicit IV: 4 (GCM salt) or 12 (ChaCha); GCM adds an 8-byte explicit nonce per record. */
    private class Suite(val keyLength: Int, val fixedIvLength: Int, val hash: String, val aead: Aead)

    private val SUITES = mapOf(
        0xc02f to Suite(16, 4, "HmacSHA256", Aead.AES_GCM),           // ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xc030 to Suite(32, 4, "HmacSHA384", Aead.AES_GCM),           // ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xc02b to Suite(16, 4, "HmacSHA256", Aead.AES_GCM),           // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc02c to Suite(32, 4, "HmacSHA384", Aead.AES_GCM),           // ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0x009c to Suite(16, 4, "HmacSHA256", Aead.AES_GCM),           // RSA_WITH_AES_128_GCM_SHA256
        0x009d to Suite(32, 4, "HmacSHA384", Aead.AES_GCM),           // RSA_WITH_AES_256_GCM_SHA384
        0xcca8 to Suite(32, 12, "HmacSHA256", Aead.CHACHA20_POLY1305), // ECDHE_RSA_WITH_CHACHA20_POLY1305
        0xcca9 to Suite(32, 12, "HmacSHA256", Aead.CHACHA20_POLY1305), // ECDHE_ECDSA_WITH_CHACHA20_POLY1305
    )

    fun decrypt(clientStream: ByteArray, serverStream: ByteArray, keyLog: TlsKeyLog): Transcript? {
        val clientRandomHex = TlsClientHello.clientRandom(clientStream) ?: return null
        val (serverRandom, cipher) = serverHelloRandomAndCipher(serverStream) ?: return null
        val suite = SUITES[cipher] ?: return null
        val master = keyLog.entries.firstOrNull { it.clientRandom == clientRandomHex && it.label == "CLIENT_RANDOM" }
            ?.let { hex(it.secret) } ?: return null
        val clientRandom = hex(clientRandomHex)

        return try {
            // key_block = PRF(master, "key expansion", server_random + client_random)
            val block = prf(master, "key expansion", serverRandom + clientRandom, 2 * (suite.keyLength + suite.fixedIvLength), suite.hash)
            var o = 0
            val clientKey = block.copyOfRange(o, suite.keyLength.also { o += it })
            val serverKey = block.copyOfRange(o, o + suite.keyLength); o += suite.keyLength
            val clientIv = block.copyOfRange(o, o + suite.fixedIvLength); o += suite.fixedIvLength
            val serverIv = block.copyOfRange(o, o + suite.fixedIvLength)

            val toServer = decryptStream(clientStream, clientKey, clientIv, suite)
            val toClient = decryptStream(serverStream, serverKey, serverIv, suite)
            Transcript(toServer.first, toClient.first, toServer.second + toClient.second)
        } catch (e: Exception) {
            null // unsupported JCE algorithm, or malformed input
        }
    }

    private fun decryptStream(stream: ByteArray, key: ByteArray, fixedIv: ByteArray, suite: Suite): Pair<ByteArray, Int> {
        val output = ByteArrayOutputStream()
        var seq = 0L
        var afterCcs = false
        var decrypted = 0
        var pos = 0
        while (pos + 5 <= stream.size) {
            val type = stream[pos].toInt() and 0xff
            val length = ((stream[pos + 3].toInt() and 0xff) shl 8) or (stream[pos + 4].toInt() and 0xff)
            val bodyStart = pos + 5
            if (bodyStart + length > stream.size) break
            if (type == 0x14) {
                afterCcs = true // ChangeCipherSpec: the records that follow are encrypted
            } else if (afterCcs) {
                val plaintext = decryptRecord(stream, bodyStart, length, key, fixedIv, suite, seq, type)
                if (plaintext != null) {
                    decrypted++
                    if (type == 0x17) output.write(plaintext) // application_data
                }
                seq++ // every record after the CCS consumes a sequence number (incl. the Finished)
            }
            pos = bodyStart + length
        }
        return output.toByteArray() to decrypted
    }

    private fun decryptRecord(
        stream: ByteArray, bodyStart: Int, length: Int, key: ByteArray, fixedIv: ByteArray, suite: Suite, seq: Long, type: Int,
    ): ByteArray? {
        val seqBytes = ByteBuffer.allocate(8).putLong(seq).array()
        return try {
            when (suite.aead) {
                Aead.AES_GCM -> {
                    if (length < 8 + 16) return null
                    val nonce = fixedIv + stream.copyOfRange(bodyStart, bodyStart + 8) // 4-byte salt + 8-byte explicit
                    val cipherStart = bodyStart + 8
                    val cipherLen = length - 8
                    val aad = aad(seqBytes, type, cipherLen - 16)
                    Cipher.getInstance("AES/GCM/NoPadding").run {
                        init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                        updateAAD(aad)
                        doFinal(stream, cipherStart, cipherLen)
                    }
                }
                Aead.CHACHA20_POLY1305 -> {
                    if (length < 16) return null
                    val nonce = fixedIv.copyOf()
                    for (i in 0 until 8) nonce[4 + i] = (nonce[4 + i].toInt() xor seqBytes[i].toInt()).toByte()
                    val aad = aad(seqBytes, type, length - 16)
                    Cipher.getInstance("ChaCha20-Poly1305").run {
                        init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
                        updateAAD(aad)
                        doFinal(stream, bodyStart, length)
                    }
                }
            }
        } catch (e: javax.crypto.AEADBadTagException) {
            null
        }
    }

    /** TLS 1.2 AEAD additional data: seq(8) || type(1) || version(2)=0x0303 || plaintext length(2). */
    private fun aad(seqBytes: ByteArray, type: Int, plaintextLen: Int): ByteArray =
        seqBytes + byteArrayOf(type.toByte(), 0x03, 0x03, (plaintextLen ushr 8).toByte(), plaintextLen.toByte())

    private fun serverHelloRandomAndCipher(serverStream: ByteArray): Pair<ByteArray, Int>? {
        if (serverStream.size < 44 || serverStream[0].toInt() and 0xff != 0x16) return null
        if (serverStream[5].toInt() and 0xff != 2) return null // ServerHello
        val random = serverStream.copyOfRange(11, 43) // record(5)+handshake(4)+version(2) = 11, random 32 bytes
        val sidLen = serverStream[43].toInt() and 0xff
        val cipherAt = 44 + sidLen
        if (cipherAt + 2 > serverStream.size) return null
        val cipher = ((serverStream[cipherAt].toInt() and 0xff) shl 8) or (serverStream[cipherAt + 1].toInt() and 0xff)
        return random to cipher
    }

    /** The TLS 1.2 PRF (RFC 5246 §5): P_hash(secret, label || seed). */
    internal fun prf(secret: ByteArray, label: String, seed: ByteArray, length: Int, hash: String): ByteArray {
        val labelSeed = label.toByteArray(Charsets.US_ASCII) + seed
        val mac = Mac.getInstance(hash)
        fun hmac(data: ByteArray): ByteArray {
            mac.init(SecretKeySpec(secret, hash))
            return mac.doFinal(data)
        }
        val output = ByteArray(length)
        var a = labelSeed // A(0)
        var filled = 0
        while (filled < length) {
            a = hmac(a) // A(i)
            val chunk = hmac(a + labelSeed)
            val take = minOf(chunk.size, length - filled)
            chunk.copyInto(output, filled, 0, take)
            filled += take
        }
        return output
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }
}
