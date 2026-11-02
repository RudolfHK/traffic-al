package io.github.rudolfhk.traffical.core.quic

import io.github.rudolfhk.traffical.core.tls.Hkdf
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.ChaCha20ParameterSpec
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * QUIC v1 packet protection (RFC 9001): the Initial key schedule, the per-direction keys
 * from a TLS traffic secret, header-protection masks and AEAD decryption. Used by
 * [QuicDecryptor]; verified against the RFC 9001 Appendix A key-derivation vectors.
 */
object QuicCrypto {
    /** QUIC v1 Initial salt (RFC 9001 §5.2). */
    val INITIAL_SALT_V1 = bytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

    enum class Aead { AES_GCM, CHACHA20 }

    class Suite(val keyLength: Int, val hash: String, val aead: Aead)

    /** The three TLS 1.3 / QUIC v1 cipher suites, by their TLS code point. */
    val SUITES = mapOf(
        0x1301 to Suite(16, "HmacSHA256", Aead.AES_GCM),
        0x1302 to Suite(32, "HmacSHA384", Aead.AES_GCM),
        0x1303 to Suite(32, "HmacSHA256", Aead.CHACHA20),
    )

    class Keys(val key: ByteArray, val iv: ByteArray, val hp: ByteArray, val aead: Aead)

    /** Client and server Initial keys from the client's original destination connection ID. */
    fun initialKeys(dcid: ByteArray): Pair<Keys, Keys> {
        val initial = Hkdf.extract(INITIAL_SALT_V1, dcid, "HmacSHA256")
        val suite = SUITES.getValue(0x1301) // Initial packets always use AES-128-GCM-SHA256
        val client = keysFromSecret(Hkdf.expandLabel(initial, "client in", 32, "HmacSHA256"), suite)
        val server = keysFromSecret(Hkdf.expandLabel(initial, "server in", 32, "HmacSHA256"), suite)
        return client to server
    }

    fun keysFromSecret(secret: ByteArray, suite: Suite) = Keys(
        key = Hkdf.expandLabel(secret, "quic key", suite.keyLength, suite.hash),
        iv = Hkdf.expandLabel(secret, "quic iv", 12, suite.hash),
        hp = Hkdf.expandLabel(secret, "quic hp", suite.keyLength, suite.hash),
        aead = suite.aead,
    )

    /** The 5-byte header-protection mask from a 16-byte ciphertext sample (RFC 9001 §5.4). */
    fun headerMask(keys: Keys, sample: ByteArray): ByteArray = when (keys.aead) {
        Aead.AES_GCM -> Cipher.getInstance("AES/ECB/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(keys.hp, "AES"))
            doFinal(sample).copyOf(5)
        }
        Aead.CHACHA20 -> {
            val counter = ByteBuffer.wrap(sample, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int
            val nonce = sample.copyOfRange(4, 16)
            Cipher.getInstance("ChaCha20").run {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(keys.hp, "ChaCha20"), ChaCha20ParameterSpec(nonce, counter))
                doFinal(ByteArray(5))
            }
        }
    }

    /** Decrypts a packet payload; [header] is the AAD (first byte through the packet number). */
    fun decrypt(keys: Keys, packetNumber: Long, header: ByteArray, packet: ByteArray, offset: Int, length: Int): ByteArray? {
        val nonce = keys.iv.copyOf()
        val pn = ByteBuffer.allocate(8).putLong(packetNumber).array()
        for (i in 0 until 8) nonce[4 + i] = (nonce[4 + i].toInt() xor pn[i].toInt()).toByte()
        return try {
            when (keys.aead) {
                Aead.AES_GCM -> Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.DECRYPT_MODE, SecretKeySpec(keys.key, "AES"), GCMParameterSpec(128, nonce))
                    updateAAD(header)
                    doFinal(packet, offset, length)
                }
                Aead.CHACHA20 -> Cipher.getInstance("ChaCha20-Poly1305").run {
                    init(Cipher.DECRYPT_MODE, SecretKeySpec(keys.key, "ChaCha20"), IvParameterSpec(nonce))
                    updateAAD(header)
                    doFinal(packet, offset, length)
                }
            }
        } catch (e: AEADBadTagException) {
            null
        }
    }

    private fun bytes(hex: String) = ByteArray(hex.length / 2) { ((hex[it * 2].digitToInt(16) shl 4) or hex[it * 2 + 1].digitToInt(16)).toByte() }
}
