package io.github.rudolfhk.traffical.core.recording

import io.github.rudolfhk.traffical.core.pcap.Pcapng
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.Locale

/**
 * How segment files are stored. The app encrypts them (Tink streaming AEAD with a key in
 * the Android Keystore); [Plain] is the unencrypted format of earlier versions.
 */
interface SegmentCodec {
    /** File name suffix of segments in this format. */
    val suffix: String

    /** [associatedData] binds the ciphertext to one segment of one recording. */
    fun encrypting(out: OutputStream, associatedData: ByteArray): OutputStream

    fun decrypting(input: InputStream, associatedData: ByteArray): InputStream

    object Plain : SegmentCodec {
        override val suffix = ".pcapng"
        override fun encrypting(out: OutputStream, associatedData: ByteArray) = out
        override fun decrypting(input: InputStream, associatedData: ByteArray) = input
    }
}

/**
 * One recorded capture: the directory `<root>/<startMillis>/` with numbered segments
 * (`000001<suffix>`, ...). Each segment holds a complete PCAPNG section, so the segments
 * in order form one multi-section PCAPNG file.
 */
data class Recording(
    val directory: File,
    val startMillis: Long,
    /** When the newest segment was last written. */
    val endMillis: Long,
    /** On storage (with encryption overhead). */
    val bytes: Long,
    /** Oldest first. */
    val segments: List<File>,
    /** The oldest segments were deleted to stay within the storage limit. */
    val truncated: Boolean,
) {
    val name: String get() = directory.name
}

/** Result of [RecordingStore.export]. */
data class ExportResult(
    val bytes: Long,
    val packets: Long,
    /** Segments that ended early (the capture was killed) or failed to decrypt. */
    val damagedSegments: Int,
)

/** The recordings under [root], stored with [codec]. Not thread-safe. */
class RecordingStore(val root: File, val codec: SegmentCodec) {

    /** All recordings, newest first. */
    fun list(): List<Recording> = list(codec.suffix)

    fun totalBytes(): Long = list().sumOf { it.bytes }

    /**
     * Writes the segments of [recording] as one PCAPNG stream, except [exclude] (the segment
     * still being written). Only complete PCAPNG blocks are copied: a segment that ends
     * early or fails to decrypt contributes what it has up to there.
     */
    fun export(recording: Recording, out: OutputStream, exclude: File? = null): ExportResult {
        var bytes = 0L
        var packets = 0L
        var damaged = 0
        for (segment in recording.segments) {
            if (segment == exclude) continue
            val copy = try {
                segment.inputStream().use { file ->
                    val input = codec.decrypting(BufferedInputStream(file, BUFFER_SIZE), associatedData(recording.name, segment))
                    Pcapng.copyBlocks(input, out)
                }
            } catch (e: IOException) {
                null // could not even open the segment
            }
            if (copy == null || !copy.complete) damaged++
            if (copy != null) {
                bytes += copy.bytes
                packets += copy.packets
            }
        }
        out.flush()
        return ExportResult(bytes, packets, damaged)
    }

    fun delete(recording: Recording): Boolean = recording.directory.deleteRecursively()

    /**
     * Deletes the oldest segments, across all recordings, until the recordings take at most
     * [maxBytes]. [keep] (the segment being written) is never deleted.
     */
    fun trim(maxBytes: Long, keep: File? = null) {
        val segments = list().asReversed().flatMap { recording -> recording.segments.map { recording to it } }
        var total = segments.sumOf { it.second.length() }
        for ((recording, segment) in segments) {
            if (total <= maxBytes) break
            if (segment == keep) continue
            val size = segment.length()
            if (segment.delete()) total -= size
            if (recording.directory.listFiles().isNullOrEmpty()) recording.directory.delete()
        }
    }

    /**
     * Rewrites the segments stored with [from] (e.g. unencrypted ones of an earlier version)
     * with this store's codec and deletes the originals. Returns the number of segments.
     */
    fun migrate(from: SegmentCodec): Int {
        if (from.suffix == codec.suffix) return 0
        var migrated = 0
        for (recording in list(from.suffix)) {
            for (segment in recording.segments) {
                val target = File(segment.parentFile, segment.name.removeSuffix(from.suffix) + codec.suffix)
                segment.inputStream().use { input ->
                    open(target, recording.name).use { output ->
                        from.decrypting(input, associatedData(recording.name, segment)).copyTo(output)
                    }
                }
                segment.delete()
                migrated++
            }
        }
        return migrated
    }

    /** A new recording starting at [startMillis]. */
    fun writer(startMillis: Long, maxTotalBytes: Long, segmentBytes: Long = RecordingWriter.defaultSegmentBytes(maxTotalBytes)) =
        RecordingWriter(this, startMillis, maxTotalBytes, segmentBytes)

    internal fun segmentFile(directory: File, index: Int) =
        File(directory, String.format(Locale.ROOT, "%06d%s", index, codec.suffix))

    /** A new segment file, encrypted for its place in [recordingName]. */
    internal fun open(file: File, recordingName: String): OutputStream =
        codec.encrypting(BufferedOutputStream(file.outputStream(), BUFFER_SIZE), associatedData(recordingName, file))

    private fun list(suffix: String): List<Recording> =
        root.listFiles().orEmpty()
            .mapNotNull { dir -> dir.name.toLongOrNull()?.let { start -> read(dir, start, suffix) } }
            .sortedByDescending { it.startMillis }

    private fun read(dir: File, startMillis: Long, suffix: String): Recording? {
        val segments = dir.listFiles { file -> file.name.endsWith(suffix) }.orEmpty()
            .mapNotNull { file -> file.name.removeSuffix(suffix).toIntOrNull()?.let { it to file } }
            .sortedBy { it.first }
        if (segments.isEmpty()) return null
        return Recording(
            directory = dir,
            startMillis = startMillis,
            endMillis = segments.maxOf { it.second.lastModified() },
            bytes = segments.sumOf { it.second.length() },
            segments = segments.map { it.second },
            truncated = segments.first().first != 1,
        )
    }

    /** "<recording>/<segment number>": a segment can't be swapped with another one unnoticed. */
    private fun associatedData(recordingName: String, segment: File): ByteArray {
        val number = segment.name.substringBefore('.')
        return "$recordingName/$number".toByteArray(Charsets.UTF_8)
    }

    private companion object {
        const val BUFFER_SIZE = 256 * 1024
    }
}

/**
 * Writes captured packets as a new [Recording] in [store]. A new segment starts when the
 * current one reaches [segmentBytes]; then the oldest segments of all recordings are
 * deleted so that everything stays within [maxTotalBytes].
 */
class RecordingWriter internal constructor(
    private val store: RecordingStore,
    startMillis: Long,
    maxTotalBytes: Long,
    private val segmentBytes: Long,
) : Closeable {

    val directory = File(store.root, startMillis.toString())
    private var segmentIndex = 0
    private var segmentWritten = 0L
    private var out: OutputStream? = null

    /** Lowering the limit deletes old segments right away. */
    var maxTotalBytes: Long = maxTotalBytes
        set(value) {
            field = value
            store.trim(value - segmentBytes, keep = currentSegment)
        }

    /** The segment currently written, or null before the first packet and after [close]. */
    var currentSegment: File? = null
        private set

    var packets = 0L
        private set

    /** PCAPNG bytes written (before encryption). */
    var bytes = 0L
        private set

    fun write(timestampMicros: Long, data: ByteArray, comment: String?) {
        val block = Pcapng.packet(timestampMicros, data, comment = comment)
        val stream = out?.takeIf { segmentWritten < segmentBytes } ?: startSegment()
        stream.write(block)
        segmentWritten += block.size
        bytes += block.size
        packets++
    }

    /** Hands the written data to the file system (encrypted data in whole cipher segments). */
    fun flush() {
        out?.flush()
    }

    /** Finishes the current segment; the next packet starts a new one. */
    fun rotate() {
        val finished = out
        out = null
        currentSegment = null
        finished?.close()
    }

    override fun close() = rotate()

    private fun startSegment(): OutputStream {
        rotate()
        directory.mkdirs()
        val file = store.segmentFile(directory, ++segmentIndex)
        val stream = store.open(file, directory.name)
        val header = Pcapng.header()
        stream.write(header)
        segmentWritten = header.size.toLong()
        bytes += header.size
        out = stream
        currentSegment = file
        store.trim(maxTotalBytes - segmentBytes, keep = file)
        return stream
    }

    companion object {
        private const val MAX_SEGMENT_BYTES = 64L * 1024 * 1024

        /** Segments of 64 MB, but at least four segments within the limit. */
        fun defaultSegmentBytes(maxTotalBytes: Long) = minOf(MAX_SEGMENT_BYTES, maxOf(1L, maxTotalBytes / 4))
    }
}
