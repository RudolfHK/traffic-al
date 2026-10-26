package io.github.rudolfhk.traffical.capture

import android.util.Log
import io.github.rudolfhk.traffical.core.capture.CaptureRecord
import io.github.rudolfhk.traffical.core.recording.Recording
import io.github.rudolfhk.traffical.core.recording.RecordingStore
import io.github.rudolfhk.traffical.core.recording.RecordingWriter
import io.github.rudolfhk.traffical.core.recording.SegmentCodec
import io.github.rudolfhk.traffical.model.AppSettings
import io.github.rudolfhk.traffical.model.RecorderStatus
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.io.IOException
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicLong

/**
 * Saves captured packets as encrypted recordings, on its own thread so the capture thread
 * never waits for the storage. All state except the queue size is only touched on that
 * thread.
 */
class CaptureRecorder(
    root: File,
    codec: () -> SegmentCodec,
    private val comment: (CaptureRecord) -> String?,
) {
    private val executor = Executors.newSingleThreadExecutor { Thread(it, "recorder") }
    private val queuedBytes = AtomicLong()

    private val _status = MutableStateFlow(RecorderStatus())
    val status: StateFlow<RecorderStatus> = _status.asStateFlow()

    private var store: RecordingStore? = null
    private var running = false
    private var writer: RecordingWriter? = null
    private var storageError: String? = null
    private var dropped = 0L
    private var publishedAtMillis = 0L

    init {
        // Creating the keys takes a moment; recordings of earlier versions are unencrypted.
        executor.execute {
            store = try {
                RecordingStore(root, codec()).also { store ->
                    val migrated = store.migrate(SegmentCodec.Plain)
                    if (migrated > 0) Log.i(TAG, "encrypted $migrated segments of earlier recordings")
                }
            } catch (e: Exception) {
                Log.e(TAG, "recording encryption unavailable", e)
                storageError = e.message ?: e.javaClass.simpleName
                null
            }
        }
    }

    fun start(settings: AppSettings) = executor.execute {
        running = true
        dropped = 0
        if (store != null) storageError = null
        apply(settings)
    }

    fun stop() = executor.execute {
        running = false
        closeWriter()
        publish(force = true)
    }

    /** Applies changed settings; a running capture switches recording on or off. */
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

    /** The saved recordings, newest first. */
    fun list(): Future<List<Recording>> = executor.submit(Callable { store?.list().orEmpty() })

    /**
     * The store and the recording [name] with only finished segments: the segment being
     * written is finished first, so a running recording can be exported.
     */
    fun finishedRecording(name: String): Future<Pair<RecordingStore, Recording>?> = executor.submit(
        Callable {
            val store = store ?: return@Callable null
            val active = writer
            if (active != null && active.directory.name == name) active.rotate()
            store.list().firstOrNull { it.name == name }?.let { store to it }
        },
    )

    /** Deletes a recording that is not being written. */
    fun delete(name: String): Future<Boolean> = executor.submit(
        Callable {
            val store = store ?: return@Callable false
            if (writer?.directory?.name == name) return@Callable false
            store.list().firstOrNull { it.name == name }?.let(store::delete) ?: false
        },
    )

    /** Deletes every recording; a running one starts over. */
    fun deleteAll(): Future<*> = executor.submit(
        Runnable {
            val store = store ?: return@Runnable
            val restart = writer != null
            closeWriter()
            store.list().forEach(store::delete)
            if (restart) writer = store.writer(System.currentTimeMillis(), currentLimit)
            publish(force = true)
        },
    )

    private var currentLimit = AppSettings().storageLimitBytes

    private fun apply(settings: AppSettings) {
        val store = store
        currentLimit = settings.storageLimitBytes
        val current = writer
        when {
            store == null -> Unit
            running && settings.recordToStorage && current == null && storageError == null ->
                writer = store.writer(System.currentTimeMillis(), currentLimit)
            current != null && !settings.recordToStorage -> closeWriter()
            current != null -> current.maxTotalBytes = currentLimit
            else -> store.trim(currentLimit)
        }
        publish(force = true)
    }

    private fun write(records: List<CaptureRecord>) {
        if (!running) return
        val recording = writer ?: return
        try {
            for (record in records) recording.write(record.timestampMicros, record.packet, comment(record))
            recording.flush()
        } catch (e: IOException) {
            Log.e(TAG, "recording stopped", e)
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

    private fun publish(force: Boolean) {
        val now = System.currentTimeMillis()
        if (!force && now - publishedAtMillis < PUBLISH_INTERVAL_MILLIS) return
        publishedAtMillis = now
        _status.value = RecorderStatus(
            recording = writer?.directory?.name,
            recordedBytes = writer?.bytes ?: 0,
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
