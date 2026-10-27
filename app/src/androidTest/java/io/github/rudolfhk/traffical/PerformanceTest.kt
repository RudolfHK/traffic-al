package io.github.rudolfhk.traffical

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.rudolfhk.traffical.capture.CaptureRepository
import io.github.rudolfhk.traffical.core.capture.SyntheticTraffic
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The capture pipeline of the app on ART (see docs/PERFORMANCE.md): the work the capture
 * thread does for each batch of the native engine, while a screen shows the connection
 * list. The traffic (134 MB) is far more than the packet buffer may keep.
 */
@RunWith(AndroidJUnit4::class)
class PerformanceTest {

    @After
    fun clear() = CaptureRepository.clear()

    @Test
    fun captureProcessingKeepsUpWithinTheHeap() {
        val traffic = SyntheticTraffic(flows = 3_000)
        val runtime = Runtime.getRuntime()
        val ui = CoroutineScope(Dispatchers.Default).launch { CaptureRepository.connections.collect { } }
        var nanos = 0L
        var slowest = 0L
        var batches = 0
        var maxUsed = 0L
        var bytes = 0L
        try {
            for (batch in traffic.batches()) { // generating the traffic is not measured
                val start = System.nanoTime()
                CaptureRepository.onBatch(batch)
                val took = System.nanoTime() - start
                nanos += took
                slowest = maxOf(slowest, took)
                batches++
                bytes += batch.size
                maxUsed = maxOf(maxUsed, runtime.totalMemory() - runtime.freeMemory())
            }
        } finally {
            ui.cancel()
        }

        val seconds = nanos / 1e9
        val packetsPerSecond = (traffic.packets / seconds).toLong()
        val result = """{"packets": ${traffic.packets}, "megabytes": ${bytes / 1_000_000}, """ +
            """"pipeline_packets_per_s": $packetsPerSecond, "pipeline_mbit_per_s": ${(bytes * 8 / seconds / 1e6).toLong()}, """ +
            """"batches": $batches, "slowest_batch_ms": ${slowest / 1_000_000}, """ +
            """"heap_max_mb": ${runtime.maxMemory() / 1_000_000}, "heap_used_peak_mb": ${maxUsed / 1_000_000}}"""
        // Read by tools/emulator/bench.py from the log.
        Log.i(TAG, result)

        assertTrue("$packetsPerSecond packets/s", packetsPerSecond >= MIN_PACKETS_PER_SECOND)
    }

    private companion object {
        const val TAG = "TrafficAlPerf"

        /** About 500 Mbit/s of 1,400-byte packets. */
        const val MIN_PACKETS_PER_SECOND = 50_000
    }
}
