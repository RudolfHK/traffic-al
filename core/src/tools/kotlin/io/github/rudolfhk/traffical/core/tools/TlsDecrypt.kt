package io.github.rudolfhk.traffical.core.tools

import io.github.rudolfhk.traffical.core.capture.CaptureBatch
import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.capture.Direction
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import io.github.rudolfhk.traffical.core.packet.PacketParser
import io.github.rudolfhk.traffical.core.tls.Tls13Decryptor
import io.github.rudolfhk.traffical.core.tls.TlsKeyLog
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteOrder
import kotlin.system.exitProcess

/**
 * Decrypts the TLS 1.3 connections of a host-test capture with the key log the client wrote
 * (tools/host-test), and prints the decrypted application data. Validates the in-app
 * decryption (Tls13Decryptor) against a real session.
 *
 * Usage: tlsDecrypt <batches.bin> <keylog.txt> [server-port]
 */
fun main(args: Array<String>) {
    if (args.size < 2) {
        System.err.println("Usage: tlsDecrypt <batches.bin> <keylog.txt> [server-port]")
        exitProcess(2)
    }
    val entries = CaptureBatch.decode(File(args[0]).readBytes(), ByteOrder.LITTLE_ENDIAN)
    val keyLog = TlsKeyLog.parse(File(args[1]).readText())
    val serverPort = args.getOrNull(2)?.toIntOrNull() ?: 8443

    // Reassemble each TLS connection's two directions, keyed by the client's port.
    val clientStreams = HashMap<Int, ByteArrayOutputStream>()
    val serverStreams = HashMap<Int, ByteArrayOutputStream>()
    for (entry in entries) {
        if (entry !is CaptureRecord) continue
        val packet = PacketParser.parse(entry.packet) ?: continue
        if (packet.protocol != IpProtocol.TCP || packet.payloadLength == 0) continue
        val toServer = entry.direction == Direction.OUT
        if (toServer && packet.destinationPort != serverPort) continue
        if (!toServer && packet.sourcePort != serverPort) continue
        val clientPort = if (toServer) packet.sourcePort else packet.destinationPort
        val stream = (if (toServer) clientStreams else serverStreams).getOrPut(clientPort) { ByteArrayOutputStream() }
        stream.write(entry.packet, packet.payloadOffset, packet.payloadLength)
    }

    var decryptedConnections = 0
    for (clientPort in clientStreams.keys) {
        val client = clientStreams[clientPort]?.toByteArray() ?: continue
        val server = serverStreams[clientPort]?.toByteArray() ?: continue
        val transcript = Tls13Decryptor.decrypt(client, server, keyLog) ?: continue
        if (transcript.isEmpty) continue
        decryptedConnections++
        println("--- connection from port $clientPort (${transcript.records} records) ---")
        println("client -> server:")
        println(String(transcript.clientToServer, Charsets.ISO_8859_1))
        println("server -> client (first 500 bytes):")
        println(String(transcript.serverToClient.copyOf(minOf(500, transcript.serverToClient.size)), Charsets.ISO_8859_1))
    }
    System.err.println("decrypted $decryptedConnections TLS connection(s) on port $serverPort")
    if (decryptedConnections == 0) exitProcess(1)
}
