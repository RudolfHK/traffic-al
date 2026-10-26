package io.github.rudolfhk.traffical.vpn

import androidx.annotation.Keep
import java.net.InetAddress

/**
 * Kotlin side of the native capture engine (app/src/main/cpp): zdtun forwards every
 * connection of the TUN interface over normal sockets and reports each packet.
 * One instance runs once: [run] blocks until [stop], then call [destroy].
 */
class NativeCapture(private val listener: Listener) {

    interface Listener {
        /** Owner uid of a new connection, or -1. Called on the capture thread. */
        fun resolveUid(
            ipVersion: Int,
            protocol: Int,
            source: InetAddress,
            sourcePort: Int,
            destination: InetAddress,
            destinationPort: Int,
        ): Int

        /** A batch of packet records (see CaptureBatch). Called on the capture thread. */
        fun onPackets(batch: ByteArray)

        /** Excludes a socket of the engine from the VPN. */
        fun protect(socket: Int): Boolean
    }

    private val handle: Long = nativeCreate()

    // Guards the handle against calls (e.g. from network callbacks) racing with destroy().
    private var destroyed = false

    init {
        check(handle != 0L) { "Native capture engine could not be created" }
    }

    /** Sets the virtual DNS server announced by the VPN and the real resolver it maps to. */
    @Synchronized
    fun setDns(virtualDns: String, upstreamDns: String): Boolean =
        !destroyed && nativeSetDns(handle, virtualDns, upstreamDns)

    /** Blocks DNS-over-TLS/QUIC (port 853) so automatic Private DNS falls back to plain DNS. */
    @Synchronized
    fun setBlockPrivateDns(block: Boolean) {
        if (!destroyed) nativeSetBlockPrivateDns(handle, block)
    }

    /** Runs the forwarding loop on the calling thread. Returns 0 after [stop], -1 on error. */
    fun run(tunFd: Int, mtu: Int): Int = nativeRun(handle, tunFd, mtu)

    @Synchronized
    fun stop() {
        if (!destroyed) nativeStop(handle)
    }

    /** Frees the engine; only after [run] has returned. */
    @Synchronized
    fun destroy() {
        if (destroyed) return
        destroyed = true
        nativeDestroy(handle)
    }

    @Keep
    @Suppress("unused") // called from native code
    private fun resolveUid(
        ipVersion: Int,
        protocol: Int,
        source: ByteArray,
        sourcePort: Int,
        destination: ByteArray,
        destinationPort: Int,
    ): Int = listener.resolveUid(
        ipVersion,
        protocol,
        InetAddress.getByAddress(source),
        sourcePort,
        InetAddress.getByAddress(destination),
        destinationPort,
    )

    @Keep
    @Suppress("unused") // called from native code
    private fun onPackets(batch: ByteArray) = listener.onPackets(batch)

    @Keep
    @Suppress("unused") // called from native code
    private fun protect(socket: Int): Boolean = listener.protect(socket)

    private external fun nativeCreate(): Long
    private external fun nativeDestroy(handle: Long)
    private external fun nativeSetDns(handle: Long, virtualDns: String, upstreamDns: String): Boolean
    private external fun nativeSetBlockPrivateDns(handle: Long, block: Boolean)
    private external fun nativeRun(handle: Long, tunFd: Int, mtu: Int): Int
    private external fun nativeStop(handle: Long)

    private companion object {
        init {
            System.loadLibrary("trafficcapture")
        }
    }
}
