package io.github.rudolfhk.traffical.core.recording

import io.github.rudolfhk.traffical.core.pcap.Pcapng
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RecordingsTest {
    private val root = Files.createTempDirectory("recordings").toFile()
    private val packet = ByteArray(1000) { it.toByte() }
    private val blockSize = Pcapng.packet(0, packet, comment = "uid=10001 app=com.example").size

    @AfterTest
    fun cleanup() {
        root.deleteRecursively()
    }

    @Test
    fun `segments rotate and form one multi-section file`() {
        RecordingWriter(root, startMillis = 1_000, maxTotalBytes = 1_000_000, segmentBytes = 10_000L).use { writer ->
            repeat(25) { writer.write(it * 1000L, packet, "uid=10001 app=com.example") }
            assertEquals(25, writer.packets)
        }
        val recording = Recordings.list(root).single()
        assertEquals("1000", recording.name)
        assertFalse(recording.truncated)
        // 10 packet blocks fill a segment of 10 kB (header + 9 blocks stay below it).
        assertEquals(3, recording.segments.size)
        assertEquals(recording.segments.sumOf { it.length() }, recording.bytes)

        val out = ByteArrayOutputStream()
        Recordings.export(recording, out)
        val blocks = blockTypes(out.toByteArray())
        assertEquals(3, blocks.count { it == Pcapng.BLOCK_SECTION_HEADER })
        assertEquals(25, blocks.count { it == Pcapng.BLOCK_ENHANCED_PACKET })
    }

    @Test
    fun `oldest segments of all recordings are deleted to stay within the limit`() {
        val segment = 5_000L
        RecordingWriter(root, 1_000, maxTotalBytes = 20_000, segmentBytes = segment).use { old ->
            repeat(12) { old.write(it.toLong(), packet, "a") }
        }
        assertEquals(3, Recordings.list(root).single().segments.size)

        RecordingWriter(root, 2_000, maxTotalBytes = 20_000, segmentBytes = segment).use { new ->
            repeat(30) { new.write(it.toLong(), packet, "b") }
            // The segment being written is never deleted.
            assertTrue(new.currentSegment!!.exists())
        }
        val recordings = Recordings.list(root)
        // The old recording went first, then the oldest segments of the new one.
        assertEquals(listOf("2000"), recordings.map { it.name })
        assertTrue(recordings.single().truncated)
        // Everything but the last segment fits the limit minus one segment.
        val total = Recordings.totalBytes(root)
        assertTrue(total <= 20_000 + blockSize, "total $total")
    }

    @Test
    fun `export skips the segment still being written`() {
        val writer = RecordingWriter(root, 3_000, maxTotalBytes = 1_000_000, segmentBytes = 3_000L)
        repeat(5) { writer.write(it.toLong(), packet, null) }
        writer.flush()
        val recording = Recordings.list(root).single()
        val out = ByteArrayOutputStream()
        Recordings.export(recording, out, exclude = writer.currentSegment)
        val expected = recording.segments.filter { it != writer.currentSegment }.flatMap { it.readBytes().toList() }
        assertContentEquals(expected.toByteArray(), out.toByteArray())
        writer.close()
        assertTrue(Recordings.delete(recording))
        assertTrue(Recordings.list(root).isEmpty())
    }

    @Test
    fun `segment size keeps at least four segments within the limit`() {
        assertEquals(64L * 1024 * 1024, RecordingWriter.defaultSegmentBytes(4L shl 30))
        assertEquals(64L * 1024 * 1024, RecordingWriter.defaultSegmentBytes(256L shl 20))
        assertEquals(25L shl 20, RecordingWriter.defaultSegmentBytes(100L shl 20))
    }

    @Test
    fun `ignores foreign files`() {
        File(root, "notes").mkdirs()
        File(root, "123").mkdirs()
        File(root, "123/readme.txt").writeText("x")
        assertTrue(Recordings.list(root).isEmpty())
    }

    private fun blockTypes(file: ByteArray): List<Int> {
        val buffer = ByteBuffer.wrap(file).order(ByteOrder.LITTLE_ENDIAN)
        val types = mutableListOf<Int>()
        var pos = 0
        while (pos < file.size) {
            types += buffer.getInt(pos)
            val length = buffer.getInt(pos + 4)
            assertEquals(length, buffer.getInt(pos + length - 4))
            pos += length
        }
        return types
    }
}
