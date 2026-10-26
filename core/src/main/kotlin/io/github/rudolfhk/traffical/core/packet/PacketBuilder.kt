package io.github.rudolfhk.traffical.core.packet

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/** Builds raw IP packets, e.g. to write into a TUN interface or for tests. */
object PacketBuilder {

    private const val TTL = 64

    /** Builds an IPv4 or IPv6 UDP packet; both addresses must be of the same family. */
    fun udp(
        source: InetAddress,
        sourcePort: Int,
        destination: InetAddress,
        destinationPort: Int,
        payload: ByteArray,
        payloadOffset: Int = 0,
        payloadLength: Int = payload.size - payloadOffset,
    ): ByteArray {
        val udpLength = 8 + payloadLength
        require(udpLength <= 0xffff) { "UDP payload too large: $payloadLength" }

        val packet = ipHeader(source, destination, IpProtocol.UDP, udpLength)
        val udp = packet.size - udpLength
        packet.put16(udp, sourcePort)
        packet.put16(udp + 2, destinationPort)
        packet.put16(udp + 4, udpLength)
        payload.copyInto(packet, udp + 8, payloadOffset, payloadOffset + payloadLength)

        val checksum = transportChecksum(packet, udp, IpProtocol.UDP)
        packet.put16(udp + 6, if (checksum == 0) 0xffff else checksum)
        return packet
    }

    /** Builds an IPv4 or IPv6 TCP segment without options. */
    fun tcp(
        source: InetAddress,
        sourcePort: Int,
        destination: InetAddress,
        destinationPort: Int,
        sequence: Long,
        acknowledgement: Long,
        flags: Int,
        payload: ByteArray = ByteArray(0),
        window: Int = 65535,
    ): ByteArray {
        val tcpLength = 20 + payload.size
        val packet = ipHeader(source, destination, IpProtocol.TCP, tcpLength)
        val tcp = packet.size - tcpLength
        packet.put16(tcp, sourcePort)
        packet.put16(tcp + 2, destinationPort)
        packet.put32(tcp + 4, sequence)
        packet.put32(tcp + 8, acknowledgement)
        packet[tcp + 12] = 0x50 // data offset: 5 words, no options
        packet[tcp + 13] = flags.toByte()
        packet.put16(tcp + 14, window)
        payload.copyInto(packet, tcp + 20)
        packet.put16(tcp + 16, transportChecksum(packet, tcp, IpProtocol.TCP))
        return packet
    }

    /** Allocates a packet with a complete IP header followed by [payloadLength] zero bytes. */
    private fun ipHeader(source: InetAddress, destination: InetAddress, protocol: Int, payloadLength: Int): ByteArray =
        when {
            source is Inet4Address && destination is Inet4Address -> ByteArray(20 + payloadLength).apply {
                this[0] = 0x45
                put16(2, size)
                put16(6, 0x4000) // don't fragment
                this[8] = TTL.toByte()
                this[9] = protocol.toByte()
                source.address.copyInto(this, 12)
                destination.address.copyInto(this, 16)
                put16(10, Checksum.finish(Checksum.add(0, this, 0, 20)))
            }
            source is Inet6Address && destination is Inet6Address -> ByteArray(40 + payloadLength).apply {
                this[0] = 0x60
                put16(4, payloadLength)
                this[6] = protocol.toByte()
                this[7] = TTL.toByte()
                source.address.copyInto(this, 8)
                destination.address.copyInto(this, 24)
            }
            else -> throw IllegalArgumentException("Mixed address families: $source -> $destination")
        }

    /** TCP/UDP checksum over the pseudo header and the transport segment starting at [offset]. */
    private fun transportChecksum(packet: ByteArray, offset: Int, protocol: Int): Int {
        val isIpv4 = offset == 20
        val length = packet.size - offset
        var sum = Checksum.add(0, packet, if (isIpv4) 12 else 8, if (isIpv4) 8 else 32) // addresses
        sum += protocol + length
        sum = Checksum.add(sum, packet, offset, length)
        return Checksum.finish(sum)
    }
}

internal object Checksum {
    /** Adds big-endian 16-bit words to a running one's-complement sum. */
    fun add(sum: Long, buf: ByteArray, offset: Int, length: Int): Long {
        var s = sum
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            s += buf.u16(i)
            i += 2
        }
        if (i < end) s += buf.u8(i) shl 8
        return s
    }

    fun finish(sum: Long): Int {
        var s = sum
        while (s ushr 16 != 0L) s = (s and 0xffff) + (s ushr 16)
        return s.inv().toInt() and 0xffff
    }
}

internal fun ByteArray.put16(index: Int, value: Int) {
    this[index] = (value ushr 8).toByte()
    this[index + 1] = value.toByte()
}

internal fun ByteArray.put32(index: Int, value: Long) {
    put16(index, (value ushr 16).toInt() and 0xffff)
    put16(index + 2, value.toInt() and 0xffff)
}
