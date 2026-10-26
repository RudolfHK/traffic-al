package io.github.rudolfhk.traffical.core.tools

import io.github.rudolfhk.traffical.core.capture.CaptureBatch
import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.capture.FlowTracker
import io.github.rudolfhk.traffical.core.pcap.PcapngWriter
import java.io.File
import java.nio.ByteOrder
import kotlin.system.exitProcess

/**
 * Turns a file of native capture batches (as written by tools/host-test) into a PCAPNG
 * file and the flows tracked by [FlowTracker] as JSON, so the flow tracking can be
 * checked against tshark (tools/host-test/validate_flows.py).
 *
 * Usage: captureReport <batches.bin> <out.pcapng> <out-flows.json>
 */
fun main(args: Array<String>) {
    if (args.size != 3) {
        System.err.println("Usage: captureReport <batches.bin> <out.pcapng> <out-flows.json>")
        exitProcess(2)
    }
    val entries = CaptureBatch.decode(File(args[0]).readBytes(), ByteOrder.LITTLE_ENDIAN)
    val tracker = FlowTracker()
    var packets = 0
    PcapngWriter(File(args[1]).outputStream().buffered()).use { writer ->
        for (entry in entries) {
            tracker.process(entry)
            if (entry is CaptureRecord) {
                writer.writePacket(entry.timestampMicros, entry.packet, comment = "uid=${entry.uid}")
                packets++
            }
        }
    }
    val flows = tracker.snapshot()
    File(args[2]).writeText(flows.joinToString(",\n", "[\n", "\n]\n") { it.toJson() })
    println("$packets packets, ${entries.size - packets} detections, ${flows.size} flows")
}

private fun FlowInfo.toJson(): String = listOf(
    "id" to id,
    "uid" to uid,
    "protocol" to protocol,
    "local" to localAddress.hostAddress,
    "localPort" to localPort,
    "remote" to remoteAddress.hostAddress,
    "remotePort" to remotePort,
    "packetsOut" to packetsOut,
    "packetsIn" to packetsIn,
    "bytesOut" to bytesOut,
    "bytesIn" to bytesIn,
    "firstSeenMicros" to firstSeenMicros,
    "lastSeenMicros" to lastSeenMicros,
    "blocked" to blocked,
    "closed" to closed,
    "sni" to sni,
    "serverName" to serverName,
    "dnsName" to dnsName,
    "appProtocol" to appProtocol,
    "category" to category,
).joinToString(", ", "  {", "}") { (key, value) -> "\"$key\": ${jsonValue(value)}" }

private fun jsonValue(value: Any?): String = when (value) {
    null -> "null"
    is Number, is Boolean -> value.toString()
    else -> buildString {
        append('"')
        for (c in value.toString()) {
            when {
                c == '"' || c == '\\' -> append('\\').append(c)
                c < ' ' -> append("\\u%04x".format(c.code))
                else -> append(c)
            }
        }
        append('"')
    }
}
