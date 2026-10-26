package io.github.rudolfhk.traffical.core.tools

import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.StreamingAead
import com.google.crypto.tink.streamingaead.StreamingAeadConfig
import io.github.rudolfhk.traffical.core.capture.CaptureBatch
import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.recording.ExportResult
import io.github.rudolfhk.traffical.core.recording.RecordingStore
import io.github.rudolfhk.traffical.core.recording.SegmentCodec
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.ByteOrder
import kotlin.system.exitProcess

/**
 * Writes the packets of a host-test capture the way the app records them, and exports
 * each recording to a PCAPNG file for tools/host-test/validate_export.py:
 * - `recording.pcapng`: unencrypted, in small segments;
 * - `recording-limited.pcapng`: with a storage limit that forces deleting old segments;
 * - `recording-encrypted.pcapng`: encrypted like in the app (Tink streaming AEAD);
 * - `recording-cut.pcapng`: the encrypted recording with its last segment cut off, as
 *   when the capture is killed while writing.
 *
 * Usage: exportCheck <batches.bin> <out dir>
 */
fun main(args: Array<String>) {
    if (args.size != 2) {
        System.err.println("Usage: exportCheck <batches.bin> <out dir>")
        exitProcess(2)
    }
    val records = CaptureBatch.decode(File(args[0]).readBytes(), ByteOrder.LITTLE_ENDIAN).filterIsInstance<CaptureRecord>()
    val out = File(args[1]).apply { mkdirs() }

    val full = record(RecordingStore(File(out, "recordings"), SegmentCodec.Plain), records, Long.MAX_VALUE / 2)
    val fullResult = export(full, File(out, "recording.pcapng"))

    val limited = record(RecordingStore(File(out, "recordings-limited"), SegmentCodec.Plain), records, LIMIT_BYTES)
    val limitedRecording = limited.list().single()
    export(limited, File(out, "recording-limited.pcapng"))

    val encrypted = record(RecordingStore(File(out, "recordings-encrypted"), TinkCodec(newStreamingAead())), records, Long.MAX_VALUE / 2)
    val encryptedResult = export(encrypted, File(out, "recording-encrypted.pcapng"))
    val segments = encrypted.list().single().segments
    RandomAccessFile(segments.last(), "rw").use { it.setLength(it.length() * 2 / 3) }
    val cutResult = export(encrypted, File(out, "recording-cut.pcapng"))

    File(out, "export.json").writeText(
        """{"packets": ${records.size}, "segments": ${segments.size}, "limitBytes": $LIMIT_BYTES, """ +
            """"limitedSegments": ${limitedRecording.segments.size}, "limitedTruncated": ${limitedRecording.truncated}, """ +
            """"exported": ${fullResult.packets}, "encryptedExported": ${encryptedResult.packets}, """ +
            """"encryptedDamaged": ${encryptedResult.damagedSegments}, "cutExported": ${cutResult.packets}, """ +
            """"cutDamaged": ${cutResult.damagedSegments}}""" + "\n",
    )
    println(
        "${records.size} packets: recording of ${segments.size} segments, limited recording of " +
            "${limitedRecording.segments.size} segments (${limitedRecording.bytes} bytes), encrypted export " +
            "${encryptedResult.packets} packets, cut-off export ${cutResult.packets} packets",
    )
}

private const val SEGMENT_BYTES = 4L * 1024 * 1024
private const val LIMIT_BYTES = 20L * 1024 * 1024

private class TinkCodec(private val aead: StreamingAead) : SegmentCodec {
    override val suffix = ".enc"
    override fun encrypting(out: OutputStream, associatedData: ByteArray): OutputStream =
        aead.newEncryptingStream(out, associatedData)
    override fun decrypting(input: InputStream, associatedData: ByteArray): InputStream =
        aead.newDecryptingStream(input, associatedData)
}

private fun newStreamingAead(): StreamingAead {
    StreamingAeadConfig.register()
    @Suppress("DEPRECATION")
    return KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM_HKDF_4KB")).getPrimitive(StreamingAead::class.java)
}

private fun record(store: RecordingStore, records: List<CaptureRecord>, maxTotalBytes: Long): RecordingStore {
    store.root.deleteRecursively()
    store.writer(startMillis = records.first().timestampMicros / 1000, maxTotalBytes, SEGMENT_BYTES).use { writer ->
        for (record in records) writer.write(record.timestampMicros, record.packet, "uid=${record.uid} app=test")
    }
    return store
}

private fun export(store: RecordingStore, file: File): ExportResult =
    file.outputStream().buffered().use { store.export(store.list().single(), it) }
