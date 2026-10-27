package io.github.rudolfhk.traffical.core.capture

import io.github.rudolfhk.traffical.core.packet.PacketBuilder
import io.github.rudolfhk.traffical.core.packet.TcpFlags
import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Capture batches as the native engine produces them (see [CaptureBatch]), for benchmarks
 * and tests: each connection looks up its server name (DNS over UDP), opens a TCP
 * connection, sends a TLS ClientHello with the name, downloads [dataPacketsPerFlow]
 * segments that the app acknowledges, gets an nDPI result and closes. [concurrentFlows]
 * connections are interleaved; every fourth one uses IPv6. Generated lazily (little
 * memory) and deterministically.
 */
class SyntheticTraffic(
    private val flows: Int,
    private val dataPacketsPerFlow: Int = 30,
    private val payloadBytes: Int = 1400,
    private val concurrentFlows: Int = 100,
    private val startMicros: Long = 1_800_000_000_000_000L,
    private val order: ByteOrder = ByteOrder.nativeOrder(),
    private val maxBatchBytes: Int = 512 * 1024,
) {
    private class Packet(val uid: Int, val kind: Int, val data: ByteArray)

    /** IP packets in all batches (not counting the nDPI results). */
    val packets: Int get() = flows * (9 + dataPacketsPerFlow + dataPacketsPerFlow / 2 + dataPacketsPerFlow % 2)

    /** The encoded batches, in order. */
    fun batches(): Sequence<ByteArray> = sequence {
        val batch = ByteArrayOutputStream(maxBatchBytes)
        var micros = startMicros

        // Round robin over a window of open connections; a finished one makes room for the next.
        val active = ArrayDeque<Iterator<Packet>>()
        var next = 0
        while (next < flows || active.isNotEmpty()) {
            while (active.size < concurrentFlows && next < flows) active.addLast(flowPackets(next++).iterator())
            val flow = active.removeFirst()
            val packet = flow.next()
            if (flow.hasNext()) active.addLast(flow)

            if (batch.size() + HEADER + packet.data.size > maxBatchBytes) {
                yield(batch.toByteArray())
                batch.reset()
            }
            batch.write(header(micros, packet.uid, packet.data.size, packet.kind))
            batch.write(packet.data)
            micros += 20
        }
        if (batch.size() > 0) yield(batch.toByteArray())
    }

    private fun flowPackets(index: Int): Sequence<Packet> = sequence {
        val uid = FIRST_UID + index % APPS
        val host = HOSTS[index % HOSTS.size]
        val ipv6 = index % 4 == 3
        val app = if (ipv6) APP_V6 else APP_V4
        val dns = if (ipv6) DNS_V6 else DNS_V4
        val server = serverAddress(index, ipv6)
        val appPort = 30_000 + index % 30_000
        val dnsPort = 40_000 + index % 20_000
        val queryId = index and 0xffff

        yield(Packet(uid, KIND_OUT, PacketBuilder.udp(app, dnsPort, dns, 53, dnsMessage(queryId, host, ipv6, null))))
        yield(Packet(uid, KIND_IN, PacketBuilder.udp(dns, 53, app, dnsPort, dnsMessage(queryId, host, ipv6, server))))

        var appSeq = 1_000L
        var serverSeq = 5_000L
        fun tcp(outgoing: Boolean, flags: Int, payload: ByteArray = EMPTY) = Packet(
            uid,
            if (outgoing) KIND_OUT else KIND_IN,
            if (outgoing) {
                PacketBuilder.tcp(app, appPort, server, 443, appSeq, serverSeq, flags, payload)
            } else {
                PacketBuilder.tcp(server, 443, app, appPort, serverSeq, appSeq, flags, payload)
            },
        )

        yield(tcp(true, TcpFlags.SYN))
        appSeq++
        yield(tcp(false, TcpFlags.SYN or TcpFlags.ACK))
        serverSeq++
        yield(tcp(true, TcpFlags.ACK))
        val hello = clientHello(host)
        yield(tcp(true, TcpFlags.PSH or TcpFlags.ACK, hello))
        appSeq += hello.size
        val payload = ByteArray(payloadBytes) { (it * 31 + index).toByte() }
        for (i in 0 until dataPacketsPerFlow) {
            yield(tcp(false, TcpFlags.ACK, payload))
            serverSeq += payload.size
            if (i % 2 == 1 || i == dataPacketsPerFlow - 1) yield(tcp(true, TcpFlags.ACK))
            if (i == 2) yield(Packet(uid, KIND_INFO, flowInfo(ipv6, app, appPort, server, host)))
        }
        yield(tcp(true, TcpFlags.FIN or TcpFlags.ACK))
        appSeq++
        yield(tcp(false, TcpFlags.FIN or TcpFlags.ACK))
        serverSeq++
        yield(tcp(true, TcpFlags.ACK))
    }

    private fun header(micros: Long, uid: Int, length: Int, kind: Int): ByteArray =
        ByteBuffer.allocate(HEADER).order(order)
            .putLong(micros).putInt(uid).putShort(length.toShort()).put(kind.toByte()).put(0)
            .array()

    /** A capture_flow_info_t with nDPI's result for the connection. */
    private fun flowInfo(ipv6: Boolean, app: InetAddress, appPort: Int, server: InetAddress, host: String): ByteArray {
        val strings = listOf("TLS.Google", "Web", host, "Safe").map { it.toByteArray(Charsets.UTF_8) }
        val buffer = ByteBuffer.allocate(FLOW_INFO + strings.sumOf { 1 + it.size }).order(order)
        buffer.put((if (ipv6) 6 else 4).toByte()).put(6) // TCP
        buffer.putShort(appPort.toShort()).putShort(443)
        buffer.put(app.address.copyOf(16)).put(server.address.copyOf(16))
        buffer.putShort(91).putShort(126).putShort(5) // TLS, Google, Web
        for (string in strings) buffer.put(string.size.toByte()).put(string)
        return buffer.array()
    }

    /** Distinct servers in a few real networks, so the destinations resolve in the bundled data. */
    private fun serverAddress(index: Int, ipv6: Boolean): InetAddress {
        val base = (if (ipv6) SERVERS_V6 else SERVERS_V4)[index % 7].address
        base[base.size - 1] = (base[base.size - 1] + index / 7).toByte()
        return InetAddress.getByAddress(base)
    }

    companion object {
        private const val HEADER = CaptureBatch.HEADER_SIZE
        private const val FLOW_INFO = 44
        private const val KIND_IN = 0
        private const val KIND_OUT = 1
        private const val KIND_INFO = 2
        private const val FIRST_UID = 10_100
        private const val APPS = 40
        private val EMPTY = ByteArray(0)

        private val APP_V4: InetAddress = InetAddress.getByName("10.215.173.1")
        private val APP_V6: InetAddress = InetAddress.getByName("fd00:7a1:c0de::1")
        private val DNS_V4: InetAddress = InetAddress.getByName("10.215.173.2")
        private val DNS_V6: InetAddress = InetAddress.getByName("fd00:7a1:c0de::2")

        private val SERVERS_V4 = listOf(
            "142.250.185.0", "157.240.20.0", "104.16.132.0", "151.101.1.0", "193.99.144.0", "52.94.236.0", "13.107.42.0",
        ).map { InetAddress.getByName(it) }
        private val SERVERS_V6 = listOf(
            "2a00:1450:4001:830::", "2a03:2880:f12f:83::", "2606:4700::6810:8400", "2a04:4e42::",
            "2a02:2e0:3fe:1001::", "2600:1f18:631e:2f00::", "2620:1ec:21::",
        ).map { InetAddress.getByName(it) }

        /** Trackers from the bundled list and ordinary services. */
        val HOSTS = listOf(
            "googleads.g.doubleclick.net", "www.google.com", "graph.facebook.com", "app-measurement.com",
            "i.ytimg.com", "www.heise.de", "settings.crashlytics.com", "api.example.org", "mtalk.google.com",
            "cdn.jsdelivr.net", "firebaseinstallations.googleapis.com", "www.wikipedia.org",
        )

        /** A DNS query for an A ([ipv6]: AAAA) record, or with [answer] the response. */
        fun dnsMessage(id: Int, host: String, ipv6: Boolean, answer: InetAddress?): ByteArray {
            val name = ByteArrayOutputStream()
            for (label in host.split('.')) {
                name.write(label.length)
                name.write(label.toByteArray(Charsets.US_ASCII))
            }
            name.write(0)
            val type: Short = if (ipv6) 28 else 1
            val answerBytes = answer?.let { 12 + it.address.size } ?: 0
            val buffer = ByteBuffer.allocate(12 + name.size() + 4 + answerBytes)
            buffer.putShort(id.toShort()).putShort((if (answer == null) 0x0100 else 0x8180).toShort())
            buffer.putShort(1).putShort((if (answer == null) 0 else 1).toShort()).putShort(0).putShort(0)
            buffer.put(name.toByteArray()).putShort(type).putShort(1)
            if (answer != null) {
                buffer.putShort(0xc00c.toShort()).putShort(type).putShort(1).putInt(300)
                buffer.putShort(answer.address.size.toShort()).put(answer.address)
            }
            return buffer.array()
        }

        /** A minimal TLS 1.2 ClientHello with a server_name extension. */
        fun clientHello(host: String): ByteArray {
            val name = host.toByteArray(Charsets.US_ASCII)
            val sni = ByteBuffer.allocate(9 + name.size)
                .putShort(0).putShort((5 + name.size).toShort()) // server_name extension
                .putShort((3 + name.size).toShort()).put(0).putShort(name.size.toShort()).put(name)
                .array()
            val body = ByteBuffer.allocate(2 + 32 + 1 + 4 + 2 + 2 + sni.size)
                .putShort(0x0303).put(ByteArray(32) { it.toByte() }).put(0)
                .putShort(2).putShort(0x1301).put(1).put(0)
                .putShort(sni.size.toShort()).put(sni)
                .array()
            return ByteBuffer.allocate(9 + body.size)
                .put(0x16).putShort(0x0301).putShort((4 + body.size).toShort())
                .put(1).put(0).putShort(body.size.toShort()).put(body)
                .array()
        }
    }
}
