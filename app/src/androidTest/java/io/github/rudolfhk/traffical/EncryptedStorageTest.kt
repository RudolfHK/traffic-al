package io.github.rudolfhk.traffical

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.recording.RecordingStore
import io.github.rudolfhk.traffical.core.recording.SegmentCodec
import io.github.rudolfhk.traffical.history.HistoryStore
import io.github.rudolfhk.traffical.history.StoredLookup
import io.github.rudolfhk.traffical.security.AppLock
import io.github.rudolfhk.traffical.security.Keys
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.InetAddress

/**
 * Runs the encrypted storage on Android (Keystore, Tink, SQLCipher), which the JVM tests
 * in core can't. The app's Application has set up Keys and AppLock already.
 */
@RunWith(AndroidJUnit4::class)
class EncryptedStorageTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val packet = ByteArray(1200) { it.toByte() }

    @Test
    fun recordingsAreEncryptedAndExportAsPcapng() {
        val root = File(context.cacheDir, "test-recordings").apply { deleteRecursively() }
        val store = RecordingStore(root, Keys.recordingCodec)
        store.writer(startMillis = 1_000, maxTotalBytes = 10_000_000, segmentBytes = 50_000).use { writer ->
            repeat(200) { writer.write(it * 1000L, packet, "uid=10123 app=com.example") }
        }
        val recording = store.list().single()
        assertTrue(recording.segments.size > 1)
        for (segment in recording.segments) {
            assertFalse(String(segment.readBytes(), Charsets.ISO_8859_1).contains("com.example"))
        }

        val out = ByteArrayOutputStream()
        val result = store.export(recording, out)
        assertEquals(200L, result.packets)
        assertEquals(0, result.damagedSegments)
        val reference = ByteArrayOutputStream()
        val plain = RecordingStore(File(context.cacheDir, "test-plain").apply { deleteRecursively() }, SegmentCodec.Plain)
        plain.writer(1_000, 10_000_000, 50_000).use { writer ->
            repeat(200) { writer.write(it * 1000L, packet, "uid=10123 app=com.example") }
        }
        plain.export(plain.list().single(), reference)
        assertArrayEquals(reference.toByteArray(), out.toByteArray())
        // Starts with a PCAPNG section header block.
        assertArrayEquals(byteArrayOf(0x0A, 0x0D, 0x0D, 0x0A), out.toByteArray().copyOf(4))
        root.deleteRecursively()
    }

    @Test
    fun plainRecordingsAreMigrated() {
        val root = File(context.cacheDir, "test-migration").apply { deleteRecursively() }
        RecordingStore(root, SegmentCodec.Plain).writer(2_000, 10_000_000, 50_000).use { writer ->
            repeat(100) { writer.write(it.toLong(), packet, "a") }
        }
        val encrypted = RecordingStore(root, Keys.recordingCodec)
        assertTrue(encrypted.migrate(SegmentCodec.Plain) > 1)
        assertTrue(RecordingStore(root, SegmentCodec.Plain).list().isEmpty())
        assertEquals(100L, encrypted.export(encrypted.list().single(), ByteArrayOutputStream()).packets)
        root.deleteRecursively()
    }

    @Test
    fun secretsAndDatabaseKeyRoundTrip() {
        val key = Keys.databaseKey()
        assertEquals(32, key.size)
        assertArrayEquals(key, Keys.databaseKey())
        Keys.storeSecret("test", byteArrayOf(1, 2, 3))
        assertArrayEquals(byteArrayOf(1, 2, 3), Keys.loadSecret("test"))
        Keys.storeSecret("test", null)
        assertNull(Keys.loadSecret("test"))
    }

    @Test
    fun historyDatabaseIsEncryptedAndSurvivesReopening() {
        val name = "test-history.db"
        context.deleteDatabase(name)
        val flow = FlowInfo(
            id = 1_793_000_000_000_042, uid = 10123, ipVersion = 4, protocol = 6,
            localAddress = InetAddress.getByName("10.215.173.1"), localPort = 40000,
            remoteAddress = InetAddress.getByName("142.250.186.34"), remotePort = 443,
            sni = "example.com", dnsName = "example.com", bytesOut = 100, bytesIn = 2000,
            packetsOut = 3, packetsIn = 4, firstSeenMicros = 1, lastSeenMicros = 2,
            blocked = false, closed = true, encryptedDns = false,
            appProtocol = "TLS", category = "Web", serverName = null, breed = "Safe",
        )
        val lookup = StoredLookup(7, 1000, 10123, "example.com", "A", listOf("1.2.3.4", "5.6.7.8"), 0, 12)
        val first = HistoryStore(context, name)
        first.save(listOf(flow), listOf(lookup))
        first.load(10).get() // runs after the save

        val loaded = HistoryStore(context, name).load(10).get()
        assertEquals(listOf(flow), loaded.connections)
        val stored = loaded.lookups.single()
        assertEquals(listOf(lookup.id, lookup.uid, lookup.domain, lookup.answers), listOf(stored.id, stored.uid, stored.domain, stored.answers))

        val header = String(context.getDatabasePath(name).readBytes().copyOf(16), Charsets.ISO_8859_1)
        assertFalse("database file is plain SQLite", header.startsWith("SQLite format 3"))
    }

    @Test
    fun pinLocksAndUnlocks() {
        AppLock.setPin("2468".toCharArray())
        assertTrue(AppLock.state.value.enabled)
        assertEquals(AppLock.Attempt.WrongPin, AppLock.unlock("1111".toCharArray()))
        assertEquals(AppLock.Attempt.Unlocked, AppLock.unlock("2468".toCharArray()))
        assertFalse(AppLock.state.value.locked)
        AppLock.disable()
        assertFalse(AppLock.state.value.enabled)
    }
}
