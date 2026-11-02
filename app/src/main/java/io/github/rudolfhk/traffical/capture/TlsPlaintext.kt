package io.github.rudolfhk.traffical.capture

import io.github.rudolfhk.traffical.core.analysis.FlowPacket
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
 * [TlsKeyStore]) so the connection detail can show what the encrypted traffic contained:
 * TLS 1.2/1.3 over TCP, and QUIC over UDP. Returns null when there are no keys for the
 * session, the cipher isn't supported, the version isn't handled, or (for QUIC) the
 * handshake packets are no longer in the buffer. The keys are the owner's own (obtainable
 * with root); nothing leaves the device. See docs/DECRYPTION.md.
 */
object TlsPlaintext {
    private const val MAX_CHARS = 16 * 1024

    data class Result(val toServer: String, val toClient: String)

    fun of(packets: List<FlowPacket>, flow: FlowInfo): Result? {
        val keyLog = TlsKeyLog.parse(TlsKeyStore.text())
        if (keyLog.isEmpty) return null
        return when (flow.protocol) {
            IpProtocol.TCP -> tls(packets, keyLog)
            IpProtocol.UDP -> quic(packets, keyLog)
            else -> null
        }
    }

    private fun tls(packets: List<FlowPacket>, keyLog: TlsKeyLog): Result? {
        val client = ByteArrayOutputStream()
        val server = ByteArrayOutputStream()
        for (packet in packets) {
            (if (packet.direction == Direction.OUT) client else server).write(packet.payload)
        }
        val c = client.toByteArray()
        val s = server.toByteArray()
        // TLS 1.3 first, then TLS 1.2; whichever has the keys for this session.
        val tls13 = Tls13Decryptor.decrypt(c, s, keyLog)?.takeUnless { it.isEmpty }
        val toServer: ByteArray
        val toClient: ByteArray
        if (tls13 != null) {
            toServer = tls13.clientToServer
            toClient = tls13.serverToClient
        } else {
            val tls12 = Tls12Decryptor.decrypt(c, s, keyLog)?.takeUnless { it.isEmpty } ?: return null
            toServer = tls12.clientToServer
            toClient = tls12.serverToClient
        }
        return result(toServer, toClient)
    }

    private fun quic(packets: List<FlowPacket>, keyLog: TlsKeyLog): Result? {
        // Each captured UDP packet carries one QUIC datagram, in order.
        val client = packets.filter { it.direction == Direction.OUT }.map { it.payload }
        val server = packets.filter { it.direction == Direction.IN }.map { it.payload }
        val transcript = QuicDecryptor.decrypt(client, server, keyLog)?.takeUnless { it.isEmpty } ?: return null
        return result(transcript.clientToServer, transcript.serverToClient)
    }

    private fun result(toServer: ByteArray, toClient: ByteArray) = Result(
        toServer = String(toServer, Charsets.ISO_8859_1).take(MAX_CHARS),
        toClient = String(toClient, Charsets.ISO_8859_1).take(MAX_CHARS),
    )
}
