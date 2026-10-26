package io.github.rudolfhk.traffical.core.tools

import io.github.rudolfhk.traffical.core.capture.CaptureBatch
import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.export.StreamFormat
import io.github.rudolfhk.traffical.core.export.UdpExporter
import io.github.rudolfhk.traffical.core.recording.Recording
import io.github.rudolfhk.traffical.core.recording.RecordingWriter
import io.github.rudolfhk.traffical.core.recording.Recordings
import java.io.File
import java.net.InetSocketAddress
import java.nio.ByteOrder
import kotlin.system.exitProcess

/**
 * Writes the packets of a host-test capture the way the app does during a capture:
 * - as a recording with small segments, exported to `recording.pcapng`;
 * - as a recording with a storage limit that forces deleting old segments, exported to
 *   `recording-limited.pcapng`;
 * - over UDP as PCAP to [pcapTarget] and as PCAPNG to [pcapngTarget].
 * tools/host-test/validate_export.py then checks all of it with tshark.
 *
 * Usage: exportCheck <batches.bin> <out dir> <pcap host:port> <pcapng host:port>
 */
fun main(args: Array<String>) {
    if (args.size != 4) {
        System.err.println("Usage: exportCheck <batches.bin> <out dir> <pcap host:port> <pcapng host:port>")
        exitProcess(2)
    }
    val records = CaptureBatch.decode(File(args[0]).readBytes(), ByteOrder.LITTLE_ENDIAN).filterIsInstance<CaptureRecord>()
    val out = File(args[1]).apply { mkdirs() }
    fun comment(record: CaptureRecord) = "uid=${record.uid} app=test"

    val full = record(File(out, "recordings"), records, maxTotalBytes = Long.MAX_VALUE / 2, segmentBytes = SEGMENT_BYTES, ::comment)
    File(out, "recording.pcapng").outputStream().use { Recordings.export(full, it) }

    val limited = record(File(out, "recordings-limited"), records, LIMIT_BYTES, SEGMENT_BYTES, ::comment)
    File(out, "recording-limited.pcapng").outputStream().use { Recordings.export(limited, it) }

    val sent = listOf(args[2] to StreamFormat.PCAP, args[3] to StreamFormat.PCAPNG).map { (target, format) ->
        UdpExporter(address(target), format).use { exporter ->
            records.forEachIndexed { i, record ->
                exporter.send(record.timestampMicros, record.packet, comment(record))
                // The capture is replayed much faster than it happened: give the receiver time.
                if (i % PACE_PACKETS == 0) Thread.sleep(1)
            }
            check(exporter.errors == 0L) { "UDP send errors: ${exporter.lastError}" }
            exporter.packets
        }
    }

    File(out, "export.json").writeText(
        """{"packets": ${records.size}, "segments": ${full.segments.size}, "limitBytes": $LIMIT_BYTES, """ +
            """"limitedSegments": ${limited.segments.size}, "limitedTruncated": ${limited.truncated}, """ +
            """"udpPcap": ${sent[0]}, "udpPcapng": ${sent[1]}}""" + "\n",
    )
    println(
        "${records.size} packets: recording of ${full.segments.size} segments, limited recording of " +
            "${limited.segments.size} segments (${limited.bytes} bytes), ${sent[0]} + ${sent[1]} sent over UDP",
    )
}

private const val SEGMENT_BYTES = 4L * 1024 * 1024
private const val LIMIT_BYTES = 20L * 1024 * 1024
private const val PACE_PACKETS = 20

private fun record(
    root: File,
    records: List<CaptureRecord>,
    maxTotalBytes: Long,
    segmentBytes: Long,
    comment: (CaptureRecord) -> String,
): Recording {
    root.deleteRecursively()
    RecordingWriter(root, startMillis = records.first().timestampMicros / 1000, maxTotalBytes, segmentBytes).use { writer ->
        for (record in records) writer.write(record.timestampMicros, record.packet, comment(record))
    }
    return Recordings.list(root).single()
}

private fun address(target: String): InetSocketAddress =
    InetSocketAddress(target.substringBeforeLast(':'), target.substringAfterLast(':').toInt())
