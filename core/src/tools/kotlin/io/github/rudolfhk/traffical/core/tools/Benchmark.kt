package io.github.rudolfhk.traffical.core.tools

import io.github.rudolfhk.traffical.core.analysis.ConnectionFilter
import io.github.rudolfhk.traffical.core.analysis.TimeRange
import io.github.rudolfhk.traffical.core.analysis.TimelineSummary
import io.github.rudolfhk.traffical.core.analysis.TrafficTimeline
import io.github.rudolfhk.traffical.core.analysis.dashboard
import io.github.rudolfhk.traffical.core.capture.CaptureBatch
import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.capture.Direction
import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.capture.FlowTracker
import io.github.rudolfhk.traffical.core.capture.SyntheticTraffic
import io.github.rudolfhk.traffical.core.enrichment.Destination
import io.github.rudolfhk.traffical.core.enrichment.Enrichment
import io.github.rudolfhk.traffical.core.enrichment.IpDatabase
import io.github.rudolfhk.traffical.core.enrichment.TrackerList
import io.github.rudolfhk.traffical.core.recording.RecordingStore
import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.zip.GZIPInputStream

/**
 * The work the app does in Kotlin, on synthetic traffic (see docs/PERFORMANCE.md):
 * the capture thread's batch processing, building and filtering the connection list,
 * the dashboard, and encrypted recording.
 *
 *   ./gradlew -p core benchmark --args="<enrichment assets dir> [result.json]"
 */
fun main(args: Array<String>) {
    val enrichment = loadEnrichment(File(args[0]))
    val traffic = SyntheticTraffic(flows = 3_000)
    val batches = traffic.batches().toList()
    val bytes = batches.sumOf { batch -> CaptureBatch.decode(batch).sumOf { (it as? CaptureRecord)?.packet?.size ?: 0 }.toLong() }
    val results = LinkedHashMap<String, Any>()
    results["packets"] = traffic.packets
    results["megabytes"] = bytes / 1e6

    // The capture thread: decode, track flows, count traffic, keep packets (CaptureRepository.onBatch).
    var pipeline: Pipeline? = null
    val pipelineSeconds = measure(rounds = 7) {
        pipeline = Pipeline().also { p -> batches.forEach(p::onBatch) }
    }
    results["pipeline_packets_per_s"] = (traffic.packets / pipelineSeconds).toLong()
    results["pipeline_mbit_per_s"] = (bytes * 8 / pipelineSeconds / 1e6).toLong()

    val flows = pipeline!!
    val labels = (0 until 100_000).associateWith { "App $it" }
    val now = flows.lastMicros

    // The connection list: the most recent 2,000 connections with their destinations.
    lateinit var list: List<Pair<FlowInfo, Destination?>>
    results["connection_list_ms"] = millis(measure(rounds = 30) {
        list = flows.tracker.snapshot(2_000).map { it to enrichment.destination(it) }
    })
    results["connection_list_size"] = list.size

    val search = ConnectionFilter(text = "google")
    var matches = 0
    results["filter_text_ms"] = millis(measure(rounds = 30) {
        matches = list.count { (flow, destination) -> search.matches(flow, labels.getValue(flow.uid), null, now, destination) }
    })
    results["filter_matches"] = matches

    results["dashboard_ms"] = millis(measure(rounds = 30) {
        dashboard(flows.tracker.snapshot(2_000), flows.timeline, TimeRange.FIVE_MINUTES, now) { enrichment.destination(it) }
    })
    // The part the app does while holding the capture's lock.
    results["dashboard_under_lock_ms"] = millis(measure(rounds = 30) {
        TimelineSummary.of(flows.timeline, flows.tracker.snapshot(2_000), TimeRange.FIVE_MINUTES, now)
    })

    val addresses = list.map { it.first.remoteAddress }
    var found = 0
    val lookupSeconds = measure(rounds = 7) {
        repeat(50) { found = addresses.count { enrichment.ips?.network(it) != null } }
    }
    results["ip_lookups_per_s"] = (addresses.size * 50 / lookupSeconds).toLong()
    results["ip_lookups_found"] = "$found/${addresses.size}"

    // Recording: PCAPNG with the app as packet comment, encrypted like in the app.
    val records = batches.flatMap { batch -> CaptureBatch.decode(batch).filterIsInstance<CaptureRecord>() }
    val root = Files.createTempDirectory("benchmark").toFile()
    val store = RecordingStore(root, TinkCodec(newStreamingAead()))
    var recorded = 0L
    val recordingSeconds = measure(rounds = 5) {
        val writer = store.writer(System.currentTimeMillis(), maxTotalBytes = 4L shl 30)
        for (record in records) writer.write(record.timestampMicros, record.packet, "uid=${record.uid} app=${labels.getValue(record.uid)}")
        writer.close()
        recorded = writer.bytes
        store.list().forEach(store::delete)
    }
    root.deleteRecursively()
    results["recording_mb_per_s"] = (recorded / recordingSeconds / 1e6).toLong()

    // Heap used per packet kept in memory (the capture buffer), small and full-size packets.
    results["heap_bytes_per_buffered_packet"] = mapOf(
        "54 B" to heapPerRecord(54),
        "1440 B" to heapPerRecord(1_440),
    )

    val json = toJson(results)
    println(json)
    args.getOrNull(1)?.let { File(it).writeText(json + "\n") }
}

/** The per-batch work of CaptureRepository.onBatch, without the Android parts. */
private class Pipeline {
    val tracker = FlowTracker()
    val timeline = TrafficTimeline()
    val packets = ArrayDeque<CaptureRecord>()
    var bufferedBytes = 0L
    var lastMicros = 0L

    fun onBatch(batch: ByteArray) {
        for (entry in CaptureBatch.decode(batch)) {
            tracker.process(entry)
            if (entry !is CaptureRecord) continue
            timeline.add(entry.timestampMicros, entry.uid, entry.direction == Direction.OUT, entry.packet.size)
            packets.addLast(entry)
            bufferedBytes += entry.packet.size
            while (bufferedBytes > BUFFER_BYTES) bufferedBytes -= packets.removeFirst().packet.size
            lastMicros = entry.timestampMicros
        }
    }

    companion object {
        const val BUFFER_BYTES = 64L * 1024 * 1024
    }
}

/** Median seconds of [rounds] runs of [block], after two warm-up runs. */
private fun measure(rounds: Int, block: () -> Unit): Double {
    repeat(2) { block() }
    val times = List(rounds) {
        val start = System.nanoTime()
        block()
        (System.nanoTime() - start) / 1e9
    }
    return times.sorted()[rounds / 2]
}

private fun millis(seconds: Double) = Math.round(seconds * 10_000) / 10.0

private fun heapPerRecord(size: Int): Long {
    val count = 100_000
    val runtime = Runtime.getRuntime()
    fun used(): Long {
        repeat(3) { System.gc() }
        return runtime.totalMemory() - runtime.freeMemory()
    }
    val before = used()
    val kept = ArrayDeque<CaptureRecord>()
    repeat(count) { kept.addLast(CaptureRecord(it.toLong(), 10_000, Direction.IN, false, ByteArray(size))) }
    val after = used()
    check(kept.size == count)
    return (after - before) / count
}

private fun loadEnrichment(dir: File): Enrichment {
    // Mapped like in the app (the repository keeps the file gzipped).
    val ipFile = Files.createTempFile("ip", ".bin").toFile().apply { deleteOnExit() }
    GZIPInputStream(File(dir, "ip.bin.gz").inputStream()).use { input -> ipFile.outputStream().use { input.copyTo(it) } }
    val ips = FileChannel.open(ipFile.toPath(), StandardOpenOption.READ).use { channel ->
        IpDatabase.open(channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size()))
    }
    val trackers = GZIPInputStream(File(dir, "trackers.tsv.gz").inputStream()).use(TrackerList::read)
    return Enrichment(ips, trackers)
}

private fun toJson(value: Any?, indent: String = ""): String = when (value) {
    is Map<*, *> -> value.entries.joinToString(",\n", "{\n", "\n$indent}") { (k, v) -> "$indent  \"$k\": ${toJson(v, "$indent  ")}" }
    is String -> "\"$value\""
    is Double -> String.format(java.util.Locale.ROOT, "%.1f", value)
    else -> value.toString()
}
