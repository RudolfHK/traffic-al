package io.github.rudolfhk.traffical.core.packet

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/** Builds raw IP packets to be written back into a TUN interface. */
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

        val ipHeaderLength = when {
            source is Inet4Address && destination is Inet4Address -> 20
            source is Inet6Address && destination is Inet6Address -> 40
            else -> throw IllegalArgumentException("Mixed address families: $source -> $destination")
        }
        val packet = ByteArray(ipHeaderLength + udpLength)
        val src = source.address
        val dst = destination.address

        if (ipHeaderLength == 20) {
            packet[0] = 0x45
            packet.put16(2, packet.size)
            packet.put16(6, 0x4000) // don't fragment
            packet[8] = TTL.toByte()
            packet[9] = IpProtocol.UDP.toByte()
            src.copyInto(packet, 12)
            dst.copyInto(packet, 16)
            packet.put16(10, Checksum.finish(Checksum.add(0, packet, 0, 20)))
        } else {
            packet[0] = 0x60
            packet.put16(4, udpLength)
            packet[6] = IpProtocol.UDP.toByte()
            packet[7] = TTL.toByte()
            src.copyInto(packet, 8)
            dst.copyInto(packet, 24)
        }

        val udp = ipHeaderLength
        packet.put16(udp, sourcePort)
        packet.put16(udp + 2, destinationPort)
        packet.put16(udp + 4, udpLength)
        payload.copyInto(packet, udp + 8, payloadOffset, payloadOffset + payloadLength)

        var sum = Checksum.add(0, src, 0, src.size)
        sum = Checksum.add(sum, dst, 0, dst.size)
        sum += IpProtocol.UDP + udpLength
        sum = Checksum.add(sum, packet, udp, udpLength)
        val checksum = Checksum.finish(sum)
        packet.put16(udp + 6, if (checksum == 0) 0xffff else checksum)
        return packet
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
