package io.github.rudolfhk.traffical.capture

import io.github.rudolfhk.traffical.core.analysis.FlowPacket
import io.github.rudolfhk.traffical.core.capture.Direction
import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import io.github.rudolfhk.traffical.core.tls.Tls13Decryptor
import io.github.rudolfhk.traffical.core.tls.TlsKeyLog
import java.io.ByteArrayOutputStream

/**
 * Decrypts a TLS 1.3 connection's application data from the owner-supplied key log (phase 8,
 * [TlsKeyStore]) so the connection detail can show what the encrypted traffic contained.
 * Returns null when there are no keys for the session, the cipher isn't supported, or it
 * isn't TLS 1.3. The keys are the owner's own (obtainable with root); nothing leaves the
 * device. See docs/DECRYPTION.md.
 */
object TlsPlaintext {
    private const val MAX_CHARS = 16 * 1024

    data class Result(val toServer: String, val toClient: String)

    fun of(packets: List<FlowPacket>, flow: FlowInfo): Result? {
        if (flow.protocol != IpProtocol.TCP) return null
        val keyLog = TlsKeyLog.parse(TlsKeyStore.text())
        if (keyLog.isEmpty) return null

        val client = ByteArrayOutputStream()
        val server = ByteArrayOutputStream()
        for (packet in packets) {
            (if (packet.direction == Direction.OUT) client else server).write(packet.payload)
        }
        val transcript = Tls13Decryptor.decrypt(client.toByteArray(), server.toByteArray(), keyLog) ?: return null
        if (transcript.isEmpty) return null
        return Result(
            toServer = String(transcript.clientToServer, Charsets.ISO_8859_1).take(MAX_CHARS),
            toClient = String(transcript.serverToClient, Charsets.ISO_8859_1).take(MAX_CHARS),
        )
    }
}
