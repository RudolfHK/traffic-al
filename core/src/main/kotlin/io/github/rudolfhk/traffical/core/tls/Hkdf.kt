package io.github.rudolfhk.traffical.core.tls

import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** HKDF (RFC 5869) and the TLS 1.3 / QUIC HKDF-Expand-Label (RFC 8446 §7.1). */
internal object Hkdf {

    fun extract(salt: ByteArray, ikm: ByteArray, hash: String): ByteArray {
        val mac = Mac.getInstance(hash)
        val key = if (salt.isEmpty()) ByteArray(macLength(hash)) else salt
        mac.init(SecretKeySpec(key, hash))
        return mac.doFinal(ikm)
    }

    fun expand(prk: ByteArray, info: ByteArray, length: Int, hash: String): ByteArray {
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

    /** HKDF-Expand-Label with an empty context; used for both TLS 1.3 ("tls13 ") and QUIC labels. */
    fun expandLabel(secret: ByteArray, label: String, length: Int, hash: String): ByteArray {
        val fullLabel = "tls13 $label".toByteArray(Charsets.US_ASCII)
        val info = ByteBuffer.allocate(2 + 1 + fullLabel.size + 1)
            .putShort(length.toShort())
            .put(fullLabel.size.toByte()).put(fullLabel)
            .put(0)
            .array()
        return expand(secret, info, length, hash)
    }

    private fun macLength(hash: String): Int = when (hash) {
        "HmacSHA384" -> 48
        "HmacSHA512" -> 64
        else -> 32
    }
}
