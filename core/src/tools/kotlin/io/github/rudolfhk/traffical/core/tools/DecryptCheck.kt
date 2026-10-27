package io.github.rudolfhk.traffical.core.tools

import io.github.rudolfhk.traffical.core.capture.CaptureBatch
import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.capture.Direction
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import io.github.rudolfhk.traffical.core.packet.PacketParser
import io.github.rudolfhk.traffical.core.pcap.PcapngWriter
import io.github.rudolfhk.traffical.core.tls.TlsClientHello
import io.github.rudolfhk.traffical.core.tls.TlsKeyLog
import java.io.File
import java.nio.ByteOrder
import kotlin.system.exitProcess

/**
 * Writes a native capture (tools/host-test) as PCAPNG with a TLS key-log Decryption
 * Secrets Block, so Wireshark/tshark can decrypt it (tools/host-test validates this).
 * Only the keys for the TLS sessions seen in the capture are embedded: the key log is
 * supplied by the device owner (here a curl/openssl SSLKEYLOGFILE), never derived here.
 *
 * Usage: decryptCheck <batches.bin> <keylog.txt> <out.pcapng>
 */
fun main(args: Array<String>) {
    if (args.size != 3) {
        System.err.println("Usage: decryptCheck <batches.bin> <keylog.txt> <out.pcapng>")
        exitProcess(2)
    }
    val entries = CaptureBatch.decode(File(args[0]).readBytes(), ByteOrder.LITTLE_ENDIAN)
    val keyLog = TlsKeyLog.parse(File(args[1]).readText())

    val sessions = LinkedHashSet<String>()
    for (entry in entries) {
        if (entry !is CaptureRecord || entry.direction != Direction.OUT) continue
        val packet = PacketParser.parse(entry.packet) ?: continue
        if (packet.protocol != IpProtocol.TCP || packet.payloadLength <= 0) continue
        TlsClientHello.clientRandom(entry.packet, packet.payloadOffset, packet.payloadLength)?.let { sessions += it }
    }

    val matched = keyLog.textFor(sessions)
    var packets = 0
    PcapngWriter(File(args[2]).outputStream().buffered()).use { writer ->
        writer.writeTlsKeyLog(matched)
        for (entry in entries) {
            if (entry is CaptureRecord) {
                writer.writePacket(entry.timestampMicros, entry.packet, comment = "uid=${entry.uid}")
                packets++
            }
        }
    }
    val secrets = if (matched.isEmpty()) 0 else matched.trimEnd('\n').count { it == '\n' } + 1
    println("$packets packets, ${sessions.size} TLS sessions, $secrets of ${keyLog.entries.size} key-log secrets embedded")
}
