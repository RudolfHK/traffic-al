package io.github.rudolfhk.traffical.enrichment

import android.content.Context
import android.content.res.AssetManager
import android.util.Log
import io.github.rudolfhk.traffical.core.enrichment.Enrichment
import io.github.rudolfhk.traffical.core.enrichment.IpDatabase
import io.github.rudolfhk.traffical.core.enrichment.TrackerList
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.FileNotFoundException
import java.io.InputStream
import java.nio.channels.FileChannel
import java.util.concurrent.atomic.AtomicBoolean
import java.util.zip.GZIPInputStream
import kotlin.concurrent.thread

/**
 * The bundled offline data (IP country/network, trackers). Loaded on first use by a screen,
 * in the background; a capture running without the app open never loads it.
 */
object EnrichmentStore {
    private const val TAG = "EnrichmentStore"
    private val _enrichment = MutableStateFlow<Enrichment?>(null)
    val enrichment: StateFlow<Enrichment?> = _enrichment.asStateFlow()
    private val started = AtomicBoolean()

    /** Why a part of the data could not be loaded (shown in the settings). */
    val errors: StateFlow<List<String>> get() = _errors
    private val _errors = MutableStateFlow<List<String>>(emptyList())

    val current: Enrichment? get() = _enrichment.value

    fun load(context: Context) {
        if (!started.compareAndSet(false, true)) return
        val assets = context.applicationContext.assets
        thread(name = "enrichment", isDaemon = true) {
            val ips = read("IP database") { ipDatabase(assets) }
            val trackers = read("tracker list") { open(assets, "trackers.tsv").use(TrackerList::read) }
            _enrichment.value = Enrichment(ips, trackers)
        }
    }

    /**
     * The database is about 15 MB, more than the heap some devices give an app, so it is
     * memory-mapped straight from the APK (stored uncompressed, see app/build.gradle.kts).
     */
    private fun ipDatabase(assets: AssetManager): IpDatabase {
        val buffer = try {
            assets.openFd("enrichment/ip.bin").use { fd ->
                fd.createInputStream().channel.use { it.map(FileChannel.MapMode.READ_ONLY, fd.startOffset, fd.length) }
            }
        } catch (e: FileNotFoundException) {
            // Compressed after all: fall back to the heap.
            Log.w(TAG, "IP database cannot be mapped", e)
            return open(assets, "ip.bin").use(IpDatabase::load)
        }
        return IpDatabase.open(buffer)
    }

    /**
     * The repository keeps the data gzipped (enrichment/ip.bin.gz); the Android Gradle
     * plugin's asset merger decompresses .gz assets and drops the suffix, like aapt did.
     */
    private fun open(assets: AssetManager, name: String): InputStream = try {
        assets.open("enrichment/$name")
    } catch (e: FileNotFoundException) {
        GZIPInputStream(assets.open("enrichment/$name.gz"))
    }

    private fun <T> read(what: String, block: () -> T): T? = try {
        block()
    } catch (e: Throwable) {
        // Also OutOfMemoryError: the app works without the data.
        Log.e(TAG, "$what unavailable", e)
        _errors.value = _errors.value + "$what: $e"
        null
    }
}
