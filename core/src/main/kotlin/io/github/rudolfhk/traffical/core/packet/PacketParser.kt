package io.github.rudolfhk.traffical.core.packet

import java.net.InetAddress

/** Parses raw IP packets as read from a TUN interface (no link-layer header). */
object PacketParser {

    private const val IPV6_HOP_BY_HOP = 0
    private const val IPV6_ROUTING = 43
    private const val IPV6_FRAGMENT = 44
    private const val IPV6_AUTH = 51
    private const val IPV6_DEST_OPTS = 60

    /** Returns null for truncated, malformed or non-IP data. */
    fun parse(buf: ByteArray, offset: Int = 0, length: Int = buf.size - offset): Packet? {
        if (offset < 0 || length < 1 || offset + length > buf.size) return null
        return when (buf.u8(offset) ushr 4) {
            4 -> parseIpv4(buf, offset, length)
            6 -> parseIpv6(buf, offset, length)
            else -> null
        }
    }

    private fun parseIpv4(buf: ByteArray, off: Int, available: Int): Packet? {
        if (available < 20) return null
        val headerLength = (buf.u8(off) and 0x0f) * 4
        val totalLength = buf.u16(off + 2)
        if (headerLength < 20 || totalLength < headerLength || totalLength > available) return null

        val fragmentOffset = buf.u16(off + 6) and 0x1fff
        val protocol = buf.u8(off + 9)
        val source = InetAddress.getByAddress(buf.copyOfRange(off + 12, off + 16))
        val destination = InetAddress.getByAddress(buf.copyOfRange(off + 16, off + 20))

        return withTransport(
            ipVersion = 4,
            protocol = protocol,
            source = source,
            destination = destination,
            buf = buf,
            packetStart = off,
            packetLength = totalLength,
            transportOffset = off + headerLength,
            isFirstFragment = fragmentOffset == 0,
        )
    }

    private fun parseIpv6(buf: ByteArray, off: Int, available: Int): Packet? {
        if (available < 40) return null
        val totalLength = 40 + buf.u16(off + 4)
        if (totalLength > available) return null

        val source = InetAddress.getByAddress(buf.copyOfRange(off + 8, off + 24))
        val destination = InetAddress.getByAddress(buf.copyOfRange(off + 24, off + 40))
        val end = off + totalLength

        var next = buf.u8(off + 6)
        var pos = off + 40
        var isFirstFragment = true
        while (next == IPV6_HOP_BY_HOP || next == IPV6_ROUTING || next == IPV6_FRAGMENT ||
            next == IPV6_AUTH || next == IPV6_DEST_OPTS
        ) {
            if (pos + 8 > end) return null
            val headerLength = when (next) {
                IPV6_FRAGMENT -> {
                    if ((buf.u16(pos + 2) ushr 3) != 0) isFirstFragment = false
                    8
                }
                IPV6_AUTH -> (buf.u8(pos + 1) + 2) * 4
                else -> (buf.u8(pos + 1) + 1) * 8
            }
            next = buf.u8(pos)
            pos += headerLength
        }
        if (pos > end) return null

        return withTransport(
            ipVersion = 6,
            protocol = next,
            source = source,
            destination = destination,
            buf = buf,
            packetStart = off,
            packetLength = totalLength,
            transportOffset = pos,
            isFirstFragment = isFirstFragment,
        )
    }

    private fun withTransport(
        ipVersion: Int,
        protocol: Int,
        source: InetAddress,
        destination: InetAddress,
        buf: ByteArray,
        packetStart: Int,
        packetLength: Int,
        transportOffset: Int,
        isFirstFragment: Boolean,
    ): Packet? {
        val end = packetStart + packetLength
        val ipOnly = Packet(
            ipVersion, protocol, source, destination, packetLength,
            sourcePort = 0, destinationPort = 0, tcpFlags = 0,
            payloadOffset = transportOffset, payloadLength = end - transportOffset,
        )
        if (!isFirstFragment) return ipOnly

        return when (protocol) {
            IpProtocol.TCP -> {
                if (transportOffset + 20 > end) return null
                val dataOffset = (buf.u8(transportOffset + 12) ushr 4) * 4
                if (dataOffset < 20 || transportOffset + dataOffset > end) return null
                ipOnly.copy(
                    sourcePort = buf.u16(transportOffset),
                    destinationPort = buf.u16(transportOffset + 2),
                    tcpFlags = buf.u8(transportOffset + 13),
                    payloadOffset = transportOffset + dataOffset,
                    payloadLength = end - transportOffset - dataOffset,
                )
            }
            IpProtocol.UDP -> {
                if (transportOffset + 8 > end) return null
                val udpLength = buf.u16(transportOffset + 4)
                if (udpLength < 8) return null
                ipOnly.copy(
                    sourcePort = buf.u16(transportOffset),
                    destinationPort = buf.u16(transportOffset + 2),
                    payloadOffset = transportOffset + 8,
                    payloadLength = minOf(udpLength, end - transportOffset) - 8,
                )
            }
            else -> ipOnly
        }
    }
}

internal fun ByteArray.u8(index: Int): Int = this[index].toInt() and 0xff

internal fun ByteArray.u16(index: Int): Int = (u8(index) shl 8) or u8(index + 1)
