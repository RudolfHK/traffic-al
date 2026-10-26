package io.github.rudolfhk.traffical.core.export

import io.github.rudolfhk.traffical.core.pcap.Pcap
import io.github.rudolfhk.traffical.core.pcap.Pcapng
import java.io.Closeable
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress

enum class StreamFormat {
    /** PCAP with raw IP packets, exactly like PCAPdroid's UDP exporter. */
    PCAP,

    /** PCAPNG with the app of each packet as its comment. */
    PCAPNG,
}

/**
 * Streams captured packets to [target] over UDP, one packet per datagram, preceded by
 * one datagram with the file header. Receivers that start later build the header
 * themselves (PCAPdroid's udp_receiver.py and tools/udp-receiver.py do).
 */
class UdpExporter(
    private val target: InetSocketAddress,
    val format: StreamFormat,
    private val socket: DatagramSocket = DatagramSocket(),
) : Closeable {

    private var headerSent = false

    var packets = 0L
        private set

    /** Send errors, e.g. while the network to [target] is down. Packets are then dropped. */
    var errors = 0L
        private set

    var lastError: IOException? = null
        private set

    fun send(timestampMicros: Long, data: ByteArray, comment: String?) {
        if (!headerSent) {
            headerSent = transmit(if (format == StreamFormat.PCAP) Pcap.header() else Pcapng.header())
            if (!headerSent) return
        }
        val datagram = when (format) {
            StreamFormat.PCAP -> Pcap.record(timestampMicros, data)
            StreamFormat.PCAPNG -> Pcapng.packet(timestampMicros, data, comment = comment)
        }
        if (transmit(datagram)) packets++
    }

    override fun close() = socket.close()

    private fun transmit(bytes: ByteArray): Boolean = try {
        socket.send(DatagramPacket(bytes, bytes.size, target))
        true
    } catch (e: IOException) {
        errors++
        lastError = e
        false
    }
}
