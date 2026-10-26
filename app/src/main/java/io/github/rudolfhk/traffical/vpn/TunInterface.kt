package io.github.rudolfhk.traffical.vpn

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import java.io.Closeable
import java.io.FileOutputStream
import java.io.IOException
import java.io.InterruptedIOException

/**
 * Owns the TUN file descriptor: a dedicated thread reads packets, any thread may write.
 * A blocking read() on a TUN fd is not interrupted by closing it, so the reader polls the
 * TUN fd together with a pipe that [close] uses to wake it up.
 */
class TunInterface(private val pfd: ParcelFileDescriptor, private val mtu: Int) : Closeable {

    private val tunFd = pfd.fileDescriptor
    private val output = FileOutputStream(tunFd)
    private val wakeupPipe = Os.pipe()
    private var reader: Thread? = null

    @Volatile
    private var closed = false

    /** Starts reading; [onPacket] runs on the reader thread with (packet, timestamp in µs). */
    fun start(onPacket: (ByteArray, Long) -> Unit) {
        check(reader == null) { "already started" }
        reader = Thread({ readLoop(onPacket) }, "tun-reader").apply { start() }
    }

    fun write(packet: ByteArray) {
        synchronized(output) {
            if (closed) return
            try {
                output.write(packet)
            } catch (e: IOException) {
                Log.w(TAG, "TUN write failed (${packet.size} bytes)", e)
            }
        }
    }

    private fun readLoop(onPacket: (ByteArray, Long) -> Unit) {
        val buffer = ByteArray(mtu)
        val tunPoll = StructPollfd().apply {
            fd = tunFd
            events = OsConstants.POLLIN.toShort()
        }
        val wakeupPoll = StructPollfd().apply {
            fd = wakeupPipe[0]
            events = OsConstants.POLLIN.toShort()
        }
        val polls = arrayOf(tunPoll, wakeupPoll)

        while (!closed) {
            try {
                Os.poll(polls, -1)
            } catch (e: ErrnoException) {
                if (e.errno == OsConstants.EINTR) continue
                Log.e(TAG, "poll failed", e)
                break
            }
            if (wakeupPoll.revents.toInt() != 0) break

            val tunEvents = tunPoll.revents.toInt()
            if (tunEvents and OsConstants.POLLIN != 0) {
                val length = try {
                    Os.read(tunFd, buffer, 0, buffer.size)
                } catch (e: ErrnoException) {
                    if (e.errno == OsConstants.EINTR || e.errno == OsConstants.EAGAIN) continue
                    Log.e(TAG, "TUN read failed", e)
                    break
                } catch (_: InterruptedIOException) {
                    break
                }
                if (length > 0) onPacket(buffer.copyOf(length), System.currentTimeMillis() * 1000)
            } else if (tunEvents and (OsConstants.POLLERR or OsConstants.POLLHUP) != 0) {
                break
            }
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        closeQuietly { Os.close(wakeupPipe[1]) }
        reader?.join(READER_JOIN_TIMEOUT_MS)
        closeQuietly { Os.close(wakeupPipe[0]) }
        synchronized(output) { closeQuietly { pfd.close() } }
    }

    private inline fun closeQuietly(block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            Log.w(TAG, "close failed", e)
        }
    }

    private companion object {
        const val TAG = "TunInterface"
        const val READER_JOIN_TIMEOUT_MS = 2_000L
    }
}
