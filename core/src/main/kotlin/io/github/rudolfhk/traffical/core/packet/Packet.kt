package io.github.rudolfhk.traffical.core.packet

import java.net.InetAddress

object IpProtocol {
    const val ICMP = 1
    const val TCP = 6
    const val UDP = 17
    const val ICMPV6 = 58

    fun name(protocol: Int): String = when (protocol) {
        ICMP -> "ICMP"
        TCP -> "TCP"
        UDP -> "UDP"
        ICMPV6 -> "ICMPv6"
        else -> "IP-$protocol"
    }
}

object TcpFlags {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
}

/**
 * A parsed IPv4 or IPv6 packet. All offsets are absolute indexes into the buffer that
 * was passed to [PacketParser.parse]; nothing is copied.
 *
 * Ports and [tcpFlags] are 0 when the packet is neither TCP nor UDP, or is a non-first
 * fragment (then [payloadOffset] points directly behind the IP headers).
 */
data class Packet(
    val ipVersion: Int,
    val protocol: Int,
    val source: InetAddress,
    val destination: InetAddress,
    /** Length of the whole IP packet in bytes. */
    val length: Int,
    val sourcePort: Int,
    val destinationPort: Int,
    val tcpFlags: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
) {
    val hasPorts: Boolean get() = sourcePort != 0 || destinationPort != 0
}
