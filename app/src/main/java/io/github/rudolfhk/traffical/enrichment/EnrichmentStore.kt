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
            val ips = read("IP database") { open(assets, "ip.bin").use(IpDatabase::read) }
            val trackers = read("tracker list") { open(assets, "trackers.tsv").use(TrackerList::read) }
            _enrichment.value = Enrichment(ips, trackers)
        }
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
