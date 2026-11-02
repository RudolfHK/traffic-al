package io.github.rudolfhk.traffical.core.tools

import io.github.rudolfhk.traffical.core.capture.CaptureBatch
import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.capture.Direction
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import io.github.rudolfhk.traffical.core.packet.PacketParser
import io.github.rudolfhk.traffical.core.quic.QuicDecryptor
import io.github.rudolfhk.traffical.core.tls.TlsKeyLog
import java.io.File
import java.nio.ByteOrder
import kotlin.system.exitProcess

/**
 * Decrypts the QUIC connections of a host-test capture with the key log the client wrote,
 * and prints the decrypted application streams. Validates the in-app QUIC decryptor
 * (QuicDecryptor) against a real aioquic HTTP/3 session.
 *
 * Usage: quicDecrypt <batches.bin> <keylog.txt> [server-port]
 */
fun main(args: Array<String>) {
    if (args.size < 2) {
        System.err.println("Usage: quicDecrypt <batches.bin> <keylog.txt> [server-port]")
        exitProcess(2)
    }
    val entries = CaptureBatch.decode(File(args[0]).readBytes(), ByteOrder.LITTLE_ENDIAN)
    val keyLog = TlsKeyLog.parse(File(args[1]).readText())
    val serverPort = args.getOrNull(2)?.toIntOrNull() ?: 4433

    // One UDP datagram per captured packet, grouped per connection by the client's port.
    val clientDatagrams = HashMap<Int, MutableList<ByteArray>>()
    val serverDatagrams = HashMap<Int, MutableList<ByteArray>>()
    for (entry in entries) {
        if (entry !is CaptureRecord) continue
        val packet = PacketParser.parse(entry.packet) ?: continue
        if (packet.protocol != IpProtocol.UDP || packet.payloadLength == 0) continue
        val toServer = entry.direction == Direction.OUT
        if (toServer && packet.destinationPort != serverPort) continue
        if (!toServer && packet.sourcePort != serverPort) continue
        val clientPort = if (toServer) packet.sourcePort else packet.destinationPort
        val datagram = entry.packet.copyOfRange(packet.payloadOffset, packet.payloadOffset + packet.payloadLength)
        (if (toServer) clientDatagrams else serverDatagrams).getOrPut(clientPort) { ArrayList() }.add(datagram)
    }

    var decrypted = 0
    for (clientPort in clientDatagrams.keys) {
        val client = clientDatagrams[clientPort] ?: continue
        val server = serverDatagrams[clientPort] ?: continue
        val transcript = QuicDecryptor.decrypt(client, server, keyLog) ?: continue
        if (transcript.isEmpty) continue
        decrypted++
        println("--- QUIC connection from port $clientPort (${transcript.packets} packets) ---")
        println("client -> server (stream bytes, ISO-8859-1):")
        println(String(transcript.clientToServer, Charsets.ISO_8859_1))
        println("server -> client (stream bytes, ISO-8859-1):")
        println(String(transcript.serverToClient, Charsets.ISO_8859_1))
    }
    System.err.println("decrypted $decrypted QUIC connection(s) on port $serverPort")
    if (decrypted == 0) exitProcess(1)
}
