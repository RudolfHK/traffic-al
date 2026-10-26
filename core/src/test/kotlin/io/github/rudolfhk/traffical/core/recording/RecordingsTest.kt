package io.github.rudolfhk.traffical.core.recording

import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.StreamingAead
import com.google.crypto.tink.streamingaead.StreamingAeadConfig
import io.github.rudolfhk.traffical.core.pcap.Pcapng
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The app's codec, built here with a plain JVM keyset instead of the Android Keystore. */
private class TinkCodec(private val aead: StreamingAead) : SegmentCodec {
    override val suffix = ".enc"
    override fun encrypting(out: OutputStream, associatedData: ByteArray): OutputStream =
        aead.newEncryptingStream(out, associatedData)
    override fun decrypting(input: InputStream, associatedData: ByteArray): InputStream =
        aead.newDecryptingStream(input, associatedData)
}

class RecordingsTest {
    private val root = Files.createTempDirectory("recordings").toFile()
    private val packet = ByteArray(1000) { it.toByte() }
    private val blockSize = Pcapng.packet(0, packet, comment = "uid=10001 app=com.example").size
    private val plain = RecordingStore(root, SegmentCodec.Plain)
    private val encrypted = RecordingStore(root, TinkCodec(newStreamingAead()))

    @AfterTest
    fun cleanup() {
        root.deleteRecursively()
    }

    @Test
    fun `segments rotate and form one multi-section file`() {
        plain.writer(startMillis = 1_000, maxTotalBytes = 1_000_000, segmentBytes = 10_000L).use { writer ->
            repeat(25) { writer.write(it * 1000L, packet, "uid=10001 app=com.example") }
            assertEquals(25, writer.packets)
        }
        val recording = plain.list().single()
        assertEquals("1000", recording.name)
        assertFalse(recording.truncated)
        // 10 packet blocks fill a segment of 10 kB (header + 9 blocks stay below it).
        assertEquals(3, recording.segments.size)
        assertEquals(recording.segments.sumOf { it.length() }, recording.bytes)

        val out = ByteArrayOutputStream()
        assertEquals(ExportResult(out.size().toLong() + recording.bytes, 25, 0), plain.export(recording, out))
        val blocks = blockTypes(out.toByteArray())
        assertEquals(3, blocks.count { it == Pcapng.BLOCK_SECTION_HEADER })
        assertEquals(25, blocks.count { it == Pcapng.BLOCK_ENHANCED_PACKET })
    }

    @Test
    fun `encrypted segments hold no plaintext and export the same PCAPNG`() {
        val reference = ByteArrayOutputStream()
        plain.writer(1_000, 1_000_000, 10_000L).use { w -> repeat(25) { w.write(it.toLong(), packet, "app") } }
        plain.export(plain.list().single(), reference)
        plain.delete(plain.list().single())

        encrypted.writer(1_000, 1_000_000, 10_000L).use { w -> repeat(25) { w.write(it.toLong(), packet, "app") } }
        val recording = encrypted.list().single()
        assertEquals(3, recording.segments.size)
        for (segment in recording.segments) {
            val bytes = segment.readBytes()
            assertFalse(bytes.asList().windowed(4).any { it == listOf<Byte>(0x0A, 0x0D, 0x0D, 0x0A) }, "SHB visible in $segment")
            assertFalse(String(bytes, Charsets.ISO_8859_1).contains("traffic-al"))
        }
        val out = ByteArrayOutputStream()
        val result = encrypted.export(recording, out)
        assertEquals(25, result.packets)
        assertEquals(0, result.damagedSegments)
        assertContentEquals(reference.toByteArray(), out.toByteArray())
    }

    @Test
    fun `a segment cut off by a killed capture exports its complete blocks`() {
        encrypted.writer(1_000, 1_000_000, 10_000L).use { w -> repeat(25) { w.write(it.toLong(), packet, "app") } }
        val recording = encrypted.list().single()
        // Cut the middle segment like a process killed while writing it.
        RandomAccessFile(recording.segments[1], "rw").use { it.setLength(it.length() - 300) }

        val out = ByteArrayOutputStream()
        val result = encrypted.export(recording, out)
        assertEquals(1, result.damagedSegments)
        assertTrue(result.packets in 11 until 25, "packets ${result.packets}")
        // Still a valid file: whole blocks only, and the third section follows intact.
        val blocks = blockTypes(out.toByteArray())
        assertEquals(3, blocks.count { it == Pcapng.BLOCK_SECTION_HEADER })
        assertEquals(result.packets.toInt(), blocks.count { it == Pcapng.BLOCK_ENHANCED_PACKET })
    }

    @Test
    fun `a segment moved to another recording does not decrypt`() {
        encrypted.writer(1_000, 1_000_000, 10_000L).use { w -> repeat(5) { w.write(it.toLong(), packet, "a") } }
        encrypted.writer(2_000, 1_000_000, 10_000L).use { w -> repeat(5) { w.write(it.toLong(), packet, "b") } }
        val (newer, older) = encrypted.list()
        older.segments.single().copyTo(newer.segments.single(), overwrite = true)
        val result = encrypted.export(encrypted.list().first(), ByteArrayOutputStream())
        assertEquals(1, result.damagedSegments)
        assertEquals(0, result.packets)
    }

    @Test
    fun `plain recordings of earlier versions are migrated to encrypted ones`() {
        plain.writer(1_000, 1_000_000, 10_000L).use { w -> repeat(25) { w.write(it.toLong(), packet, "app") } }
        val reference = ByteArrayOutputStream().also { plain.export(plain.list().single(), it) }

        assertEquals(3, encrypted.migrate(SegmentCodec.Plain))
        assertTrue(plain.list().isEmpty())
        val out = ByteArrayOutputStream()
        encrypted.export(encrypted.list().single(), out)
        assertContentEquals(reference.toByteArray(), out.toByteArray())
    }

    @Test
    fun `oldest segments of all recordings are deleted to stay within the limit`() {
        val segment = 5_000L
        plain.writer(1_000, maxTotalBytes = 20_000, segmentBytes = segment).use { old ->
            repeat(12) { old.write(it.toLong(), packet, "a") }
        }
        assertEquals(3, plain.list().single().segments.size)

        plain.writer(2_000, maxTotalBytes = 20_000, segmentBytes = segment).use { new ->
            repeat(30) { new.write(it.toLong(), packet, "b") }
            // The segment being written is never deleted.
            assertTrue(new.currentSegment!!.exists())
        }
        val recordings = plain.list()
        // The old recording went first, then the oldest segments of the new one.
        assertEquals(listOf("2000"), recordings.map { it.name })
        assertTrue(recordings.single().truncated)
        val total = plain.totalBytes()
        assertTrue(total <= 20_000 + blockSize, "total $total")
    }

    @Test
    fun `export skips the segment still being written`() {
        val writer = plain.writer(3_000, maxTotalBytes = 1_000_000, segmentBytes = 3_000L)
        repeat(5) { writer.write(it.toLong(), packet, null) }
        writer.flush()
        val recording = plain.list().single()
        val out = ByteArrayOutputStream()
        plain.export(recording, out, exclude = writer.currentSegment)
        val expected = recording.segments.filter { it != writer.currentSegment }.flatMap { it.readBytes().toList() }
        assertContentEquals(expected.toByteArray(), out.toByteArray())
        writer.close()
        assertTrue(plain.delete(recording))
        assertTrue(plain.list().isEmpty())
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
        assertTrue(plain.list().isEmpty())
        assertTrue(encrypted.list().isEmpty())
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

    private companion object {
        fun newStreamingAead(): StreamingAead {
            StreamingAeadConfig.register()
            @Suppress("DEPRECATION")
            return KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM_HKDF_4KB")).getPrimitive(StreamingAead::class.java)
        }
    }
}
