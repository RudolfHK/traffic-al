package io.github.rudolfhk.traffical.capture

import android.util.Log
import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.export.UdpExporter
import io.github.rudolfhk.traffical.core.recording.Recording
import io.github.rudolfhk.traffical.core.recording.RecordingWriter
import io.github.rudolfhk.traffical.core.recording.Recordings
import io.github.rudolfhk.traffical.model.AppSettings
import io.github.rudolfhk.traffical.model.RecorderStatus
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicLong

/**
 * Saves captured packets as a recording and streams them over UDP, on its own thread so
 * the capture thread never waits for the storage or the network. All state except the
 * queue size is only touched on that thread.
 */
class CaptureRecorder(
    private val root: File,
    private val comment: (CaptureRecord) -> String?,
) {
    private val executor = Executors.newSingleThreadExecutor { Thread(it, "recorder") }
    private val queuedBytes = AtomicLong()

    private val _status = MutableStateFlow(RecorderStatus())
    val status: StateFlow<RecorderStatus> = _status.asStateFlow()

    private var running = false
    private var writer: RecordingWriter? = null
    private var storageError: String? = null
    private var exporter: UdpExporter? = null
    private var exporterKey: String? = null
    private var udpError: String? = null
    private var dropped = 0L
    private var publishedAtMillis = 0L

    fun start(settings: AppSettings) = executor.execute {
        running = true
        dropped = 0
        storageError = null
        apply(settings)
    }

    fun stop() = executor.execute {
        running = false
        closeWriter()
        closeExporter()
        udpError = null
        publish(force = true)
    }

    /** Applies changed settings; a running capture switches recording and export on or off. */
    fun configure(settings: AppSettings) = executor.execute { apply(settings) }

    /** Called on the capture thread. Drops the packets if the recorder fell behind. */
    fun submit(records: List<CaptureRecord>) {
        if (records.isEmpty()) return
        val bytes = records.sumOf { it.packet.size.toLong() }
        if (queuedBytes.get() > MAX_QUEUED_BYTES) {
            executor.execute { dropped += records.size }
            return
        }
        queuedBytes.addAndGet(bytes)
        executor.execute {
            queuedBytes.addAndGet(-bytes)
            write(records)
        }
    }

    /**
     * The recording [name] as it is on disk, with only finished segments: the segment being
     * written is finished first, so a running recording can be exported.
     */
    fun finishedRecording(name: String): Future<Recording?> = executor.submit(
        Callable {
            val active = writer
            if (active != null && active.directory.name == name) active.rotate()
            Recordings.list(root).firstOrNull { it.name == name }
        },
    )

    /** Deletes a recording that is not being written. */
    fun delete(name: String): Future<Boolean> = executor.submit(
        Callable {
            if (writer?.directory?.name == name) return@Callable false
            Recordings.list(root).firstOrNull { it.name == name }?.let(Recordings::delete) ?: false
        },
    )

    private fun apply(settings: AppSettings) {
        val limit = settings.storageLimitBytes
        val current = writer
        when {
            running && settings.recordToStorage && current == null && storageError == null ->
                writer = RecordingWriter(root, System.currentTimeMillis(), limit)
            current != null && !settings.recordToStorage -> closeWriter()
            current != null -> current.maxTotalBytes = limit
            else -> Recordings.trim(root, limit)
        }

        val key = if (running && settings.udpExport && settings.udpHost.isNotBlank()) {
            "${settings.udpHost.trim()}:${settings.udpPort}|${settings.udpFormat}"
        } else {
            null
        }
        if (key != exporterKey) {
            closeExporter()
            exporterKey = key
            udpError = null
            if (key != null) {
                exporter = try {
                    val target = InetSocketAddress(InetAddress.getByName(settings.udpHost.trim()), settings.udpPort)
                    UdpExporter(target, settings.udpFormat)
                } catch (e: IOException) {
                    udpError = e.message ?: e.javaClass.simpleName
                    null
                }
            }
        }
        publish(force = true)
    }

    private fun write(records: List<CaptureRecord>) {
        if (!running) return
        val recording = writer
        val udp = exporter
        if (recording == null && udp == null) return
        for (record in records) {
            val text = comment(record)
            if (recording != null && writer != null) {
                try {
                    recording.write(record.timestampMicros, record.packet, text)
                } catch (e: IOException) {
                    Log.e(TAG, "recording stopped", e)
                    storageError = e.message ?: e.javaClass.simpleName
                    closeWriter()
                }
            }
            udp?.send(record.timestampMicros, record.packet, text)
        }
        try {
            writer?.flush()
        } catch (e: IOException) {
            storageError = e.message ?: e.javaClass.simpleName
            closeWriter()
        }
        publish(force = false)
    }

    private fun closeWriter() {
        try {
            writer?.close()
        } catch (e: IOException) {
            Log.w(TAG, "closing recording", e)
        }
        writer = null
    }

    private fun closeExporter() {
        exporter?.close()
        exporter = null
        exporterKey = null
    }

    private fun publish(force: Boolean) {
        val now = System.currentTimeMillis()
        if (!force && now - publishedAtMillis < PUBLISH_INTERVAL_MILLIS) return
        publishedAtMillis = now
        val udp = exporter
        _status.value = RecorderStatus(
            recording = writer?.directory?.name,
            recordedBytes = writer?.bytes ?: 0,
            udpTarget = exporterKey?.substringBefore('|')?.takeIf { udp != null },
            udpPackets = udp?.packets ?: 0,
            udpError = udpError ?: udp?.lastError?.let { it.message ?: it.javaClass.simpleName },
            storageError = storageError,
            droppedPackets = dropped,
        )
    }

    private companion object {
        const val TAG = "CaptureRecorder"
        const val MAX_QUEUED_BYTES = 32L * 1024 * 1024
        const val PUBLISH_INTERVAL_MILLIS = 1_000L
    }
}
