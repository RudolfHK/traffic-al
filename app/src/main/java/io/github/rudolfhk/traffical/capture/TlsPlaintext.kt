package io.github.rudolfhk.traffical.capture

import io.github.rudolfhk.traffical.core.analysis.FlowPacket
import io.github.rudolfhk.traffical.core.analysis.FlowReadResult
import io.github.rudolfhk.traffical.core.analysis.PlaintextDissector
import io.github.rudolfhk.traffical.core.analysis.ReadState
import io.github.rudolfhk.traffical.core.capture.Direction
import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import io.github.rudolfhk.traffical.core.quic.QuicDecryptor
import io.github.rudolfhk.traffical.core.tls.Tls12Decryptor
import io.github.rudolfhk.traffical.core.tls.Tls13Decryptor
import io.github.rudolfhk.traffical.core.tls.TlsKeyLog
import java.io.ByteArrayOutputStream

/**
 * Decrypts a connection's application data from the owner-supplied key log (phase 8/11,
 * [TlsKeyStore]) so the app can show what the encrypted traffic contained: TLS 1.2/1.3 over
 * TCP, and QUIC over UDP. The keys are the owner's own (obtainable with root); nothing leaves
 * the device, TLS is never broken or terminated, and pinned apps stay opaque. See
 * docs/DECRYPTION.md.
 *
 * [of] gives the raw request/response text for one connection's detail view; [read] (phase
 * 12) turns a connection into structured HTTP, marking it readable, still-encrypted, or not
 * HTTP, for the data-flow audit.
 */
object TlsPlaintext {
    private const val MAX_CHARS = 16 * 1024

    data class Result(val toServer: String, val toClient: String)

    /** The decrypted request/response as text for the connection detail, or null if not readable. */
    fun of(packets: List<FlowPacket>, flow: FlowInfo): Result? {
        val keyLog = TlsKeyLog.parse(TlsKeyStore.text())
        val bytes = decrypt(packets, flow, keyLog) ?: return null
        return Result(
            toServer = String(bytes.first, Charsets.ISO_8859_1).take(MAX_CHARS),
            toClient = String(bytes.second, Charsets.ISO_8859_1).take(MAX_CHARS),
        )
    }

    /**
     * Reads one connection for the audit: decrypted-and-parsed (READABLE), encrypted but not
     * decryptable (ENCRYPTED: no keys, unsupported, or pinned), or not HTTP (NOT_APPLICABLE).
     */
    fun read(packets: List<FlowPacket>, flow: FlowInfo, keyLog: TlsKeyLog): FlowReadResult {
        if (packets.isEmpty()) return FlowReadResult.NOT_APPLICABLE
        decrypt(packets, flow, keyLog)?.let { (toServer, toClient) ->
            val dissection = PlaintextDissector.dissect(toServer, toClient, flow.protocol)
            if (!dissection.isEmpty) return FlowReadResult(ReadState.READABLE, dissection.requests, dissection.responses)
        }
        if (isEncrypted(flow, packets)) return FlowReadResult.ENCRYPTED
        // Plaintext (e.g. HTTP on port 80): read it straight from the captured payload.
        if (flow.protocol == IpProtocol.TCP) {
            val (toServer, toClient) = streams(packets)
            val dissection = PlaintextDissector.dissect(toServer, toClient, flow.protocol)
            if (!dissection.isEmpty) return FlowReadResult(ReadState.READABLE, dissection.requests, dissection.responses)
        }
        return FlowReadResult.NOT_APPLICABLE
    }

    /** The decrypted application bytes (toServer, toClient), or null if the keys/cipher don't allow it. */
    private fun decrypt(packets: List<FlowPacket>, flow: FlowInfo, keyLog: TlsKeyLog): Pair<ByteArray, ByteArray>? {
        if (keyLog.isEmpty) return null
        return when (flow.protocol) {
            IpProtocol.TCP -> tls(packets, keyLog)
            IpProtocol.UDP -> quic(packets, keyLog)
            else -> null
        }
    }

    private fun tls(packets: List<FlowPacket>, keyLog: TlsKeyLog): Pair<ByteArray, ByteArray>? {
        val (c, s) = streams(packets)
        val tls13 = Tls13Decryptor.decrypt(c, s, keyLog)?.takeUnless { it.isEmpty }
        if (tls13 != null) return tls13.clientToServer to tls13.serverToClient
        val tls12 = Tls12Decryptor.decrypt(c, s, keyLog)?.takeUnless { it.isEmpty } ?: return null
        return tls12.clientToServer to tls12.serverToClient
    }

    private fun quic(packets: List<FlowPacket>, keyLog: TlsKeyLog): Pair<ByteArray, ByteArray>? {
        val client = packets.filter { it.direction == Direction.OUT }.map { it.payload }
        val server = packets.filter { it.direction == Direction.IN }.map { it.payload }
        val transcript = QuicDecryptor.decrypt(client, server, keyLog)?.takeUnless { it.isEmpty } ?: return null
        return transcript.clientToServer to transcript.serverToClient
    }

    /** Concatenates the TCP payloads of each direction in capture order. */
    private fun streams(packets: List<FlowPacket>): Pair<ByteArray, ByteArray> {
        val client = ByteArrayOutputStream()
        val server = ByteArrayOutputStream()
        for (packet in packets) {
            (if (packet.direction == Direction.OUT) client else server).write(packet.payload)
        }
        return client.toByteArray() to server.toByteArray()
    }

    /** Whether a connection carries TLS/QUIC (so, if we couldn't read it, it is encrypted — not empty). */
    private fun isEncrypted(flow: FlowInfo, packets: List<FlowPacket>): Boolean {
        val app = flow.appProtocol?.uppercase().orEmpty()
        if (app.startsWith("TLS") || app.startsWith("QUIC") || app.contains("DOH") || app.contains("DOT")) return true
        if (flow.encryptedDns) return true
        if (flow.remotePort == 443 || flow.remotePort == 853) return true
        // A TLS record on the wire: content type 0x16/0x17 then version 0x03.
        val firstOut = packets.firstOrNull { it.direction == Direction.OUT }?.payload
        if (firstOut != null && firstOut.size >= 3) {
            val type = firstOut[0].toInt() and 0xff
            if ((type == 0x16 || type == 0x17) && (firstOut[1].toInt() and 0xff) == 0x03) return true
        }
        return false
    }
}
