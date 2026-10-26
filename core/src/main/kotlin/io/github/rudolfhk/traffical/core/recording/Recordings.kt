package io.github.rudolfhk.traffical.core.recording

import io.github.rudolfhk.traffical.core.pcap.Pcapng
import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.File
import java.io.OutputStream
import java.util.Locale

/**
 * One recorded capture: the directory `<root>/<startMillis>/` with numbered PCAPNG
 * segments (`000001.pcapng`, ...). Each segment is a complete PCAPNG file, so the segments
 * concatenated in order form one multi-section PCAPNG file.
 */
data class Recording(
    val directory: File,
    val startMillis: Long,
    /** When the newest segment was last written. */
    val endMillis: Long,
    val bytes: Long,
    /** Oldest first. */
    val segments: List<File>,
    /** The oldest segments were deleted to stay within the storage limit. */
    val truncated: Boolean,
) {
    val name: String get() = directory.name
}

object Recordings {
    private const val SEGMENT_SUFFIX = ".pcapng"

    /** All recordings under [root], newest first. */
    fun list(root: File): List<Recording> =
        root.listFiles().orEmpty()
            .mapNotNull { dir -> dir.name.toLongOrNull()?.let { start -> read(dir, start) } }
            .sortedByDescending { it.startMillis }

    fun totalBytes(root: File): Long = list(root).sumOf { it.bytes }

    /**
     * Writes the segments of [recording] as one PCAPNG stream, except [exclude] (the segment
     * still being written). Returns the number of bytes written.
     */
    fun export(recording: Recording, out: OutputStream, exclude: File? = null): Long {
        var written = 0L
        for (segment in recording.segments) {
            if (segment == exclude) continue
            segment.inputStream().use { written += it.copyTo(out) }
        }
        out.flush()
        return written
    }

    fun delete(recording: Recording): Boolean = recording.directory.deleteRecursively()

    /**
     * Deletes the oldest segments, across all recordings, until the recordings take at most
     * [maxBytes]. [keep] (the segment being written) is never deleted.
     */
    fun trim(root: File, maxBytes: Long, keep: File? = null) {
        val segments = list(root).asReversed().flatMap { recording -> recording.segments.map { recording to it } }
        var total = segments.sumOf { it.second.length() }
        for ((recording, segment) in segments) {
            if (total <= maxBytes) break
            if (segment == keep) continue
            val size = segment.length()
            if (segment.delete()) total -= size
            if (recording.directory.listFiles().isNullOrEmpty()) recording.directory.delete()
        }
    }

    internal fun segmentName(index: Int) = String.format(Locale.ROOT, "%06d%s", index, SEGMENT_SUFFIX)

    private fun read(dir: File, startMillis: Long): Recording? {
        val segments = dir.listFiles { file -> file.name.endsWith(SEGMENT_SUFFIX) }.orEmpty()
            .mapNotNull { file -> file.name.removeSuffix(SEGMENT_SUFFIX).toIntOrNull()?.let { it to file } }
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
}

/**
 * Writes captured packets as a new [Recording] under [root]. A new segment starts when
 * the current one reaches [segmentBytes]; then the oldest segments of all recordings are
 * deleted so that everything stays within [maxTotalBytes].
 */
class RecordingWriter(
    private val root: File,
    startMillis: Long,
    maxTotalBytes: Long,
    private val segmentBytes: Long = defaultSegmentBytes(maxTotalBytes),
) : Closeable {

    /** Lowering the limit deletes old segments right away. */
    var maxTotalBytes: Long = maxTotalBytes
        set(value) {
            field = value
            Recordings.trim(root, value - segmentBytes, keep = currentSegment)
        }

    val directory = File(root, startMillis.toString())
    private var segmentIndex = 0
    private var segmentWritten = 0L
    private var out: OutputStream? = null

    /** The segment currently written, or null before the first packet and after [close]. */
    var currentSegment: File? = null
        private set

    var packets = 0L
        private set

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

    fun flush() {
        out?.flush()
    }

    /** Finishes the current segment; the next packet starts a new one. */
    fun rotate() {
        out?.close()
        out = null
        currentSegment = null
    }

    override fun close() = rotate()

    private fun startSegment(): OutputStream {
        rotate()
        directory.mkdirs()
        val file = File(directory, Recordings.segmentName(++segmentIndex))
        val stream = BufferedOutputStream(file.outputStream(), BUFFER_SIZE)
        val header = Pcapng.header()
        stream.write(header)
        stream.flush()
        segmentWritten = header.size.toLong()
        bytes += header.size
        out = stream
        currentSegment = file
        Recordings.trim(root, maxTotalBytes - segmentBytes, keep = file)
        return stream
    }

    companion object {
        private const val MAX_SEGMENT_BYTES = 64L * 1024 * 1024
        private const val BUFFER_SIZE = 256 * 1024

        /** Segments of 64 MB, but at least four segments within the limit. */
        fun defaultSegmentBytes(maxTotalBytes: Long) = minOf(MAX_SEGMENT_BYTES, maxOf(1L, maxTotalBytes / 4))
    }
}
