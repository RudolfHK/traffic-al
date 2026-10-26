package io.github.rudolfhk.traffical.enrichment

import android.content.Context
import android.util.Log
import io.github.rudolfhk.traffical.core.enrichment.Enrichment
import io.github.rudolfhk.traffical.core.enrichment.IpDatabase
import io.github.rudolfhk.traffical.core.enrichment.TrackerList
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
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

    val current: Enrichment? get() = _enrichment.value

    fun load(context: Context) {
        if (!started.compareAndSet(false, true)) return
        val assets = context.applicationContext.assets
        thread(name = "enrichment", isDaemon = true) {
            val ips = read("IP database") { GZIPInputStream(assets.open("enrichment/ip.bin.gz")).use(IpDatabase::read) }
            val trackers = read("tracker list") { GZIPInputStream(assets.open("enrichment/trackers.tsv.gz")).use(TrackerList::read) }
            _enrichment.value = Enrichment(ips, trackers)
        }
    }

    private fun <T> read(what: String, block: () -> T): T? = try {
        block()
    } catch (e: Exception) {
        Log.e(TAG, "$what unavailable", e)
        null
    }
}
