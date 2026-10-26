package io.github.rudolfhk.traffical.vpn

import android.net.VpnService
import android.os.SystemClock
import android.system.OsConstants
import io.github.rudolfhk.traffical.capture.AppResolver
import io.github.rudolfhk.traffical.capture.CaptureRepository
import io.github.rudolfhk.traffical.capture.DnsEvent
import io.github.rudolfhk.traffical.core.dns.DnsMessage
import io.github.rudolfhk.traffical.core.dns.DnsType
import io.github.rudolfhk.traffical.core.packet.Packet
import io.github.rudolfhk.traffical.core.packet.PacketBuilder
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Answers DNS queries sent to the VPN's virtual DNS server by relaying them to the real
 * resolver of the underlying network, and records who asked for what.
 */
class DnsForwarder(
    private val vpn: VpnService,
    private val apps: AppResolver,
    private val upstreamServers: () -> List<InetAddress>,
    private val writeToTun: (ByteArray) -> Unit,
) {

    /** Handles one query packet read from the TUN interface. Blocks for up to a few seconds. */
    fun forward(packet: ByteArray, parsed: Packet, timestampMicros: Long) {
        val query = packet.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength)
        val uid = apps.ownerUid(
            OsConstants.IPPROTO_UDP,
            InetSocketAddress(parsed.source, parsed.sourcePort),
            InetSocketAddress(parsed.destination, parsed.destinationPort),
        )
        val app = apps.appInfo(uid)
        CaptureRepository.recordPacket(packet, timestampMicros, app.describe())

        val started = SystemClock.elapsedRealtime()
        val response = upstreamServers().firstNotNullOfOrNull { exchange(it, query) }
        val latency = SystemClock.elapsedRealtime() - started

        if (response != null) {
            val reply = PacketBuilder.udp(
                parsed.destination, parsed.destinationPort,
                parsed.source, parsed.sourcePort,
                response,
            )
            writeToTun(reply)
            CaptureRepository.recordPacket(reply, System.currentTimeMillis() * 1000, app.describe())
        }

        val question = DnsMessage.parse(query)?.questions?.firstOrNull() ?: return
        val answer = response?.let { DnsMessage.parse(it) }
        CaptureRepository.addEvent(
            DnsEvent(
                id = CaptureRepository.nextEventId(),
                timestampMillis = timestampMicros / 1000,
                app = app,
                domain = question.name,
                queryType = DnsType.name(question.type),
                answers = answer?.answers
                    ?.filter { it.type == DnsType.A || it.type == DnsType.AAAA || it.type == DnsType.CNAME }
                    ?.map { it.data }
                    .orEmpty(),
                rcode = answer?.rcode,
                latencyMillis = latency,
            ),
        )
    }

    private fun exchange(server: InetAddress, query: ByteArray): ByteArray? = try {
        DatagramSocket().use { socket ->
            vpn.protect(socket)
            socket.soTimeout = TIMEOUT_MS
            socket.connect(server, DNS_PORT)
            socket.send(DatagramPacket(query, query.size))
            val buffer = ByteArray(MAX_RESPONSE_SIZE)
            val response = DatagramPacket(buffer, buffer.size)
            socket.receive(response)
            buffer.copyOf(response.length)
        }
    } catch (_: IOException) {
        null
    }

    private companion object {
        const val DNS_PORT = 53
        const val TIMEOUT_MS = 3_000
        const val MAX_RESPONSE_SIZE = 65_535 - 28
    }
}
