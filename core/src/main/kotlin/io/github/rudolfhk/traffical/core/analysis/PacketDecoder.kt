package io.github.rudolfhk.traffical.core.analysis

import io.github.rudolfhk.traffical.core.dns.DnsMessage
import io.github.rudolfhk.traffical.core.dns.DnsType
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import io.github.rudolfhk.traffical.core.tls.SniResult
import io.github.rudolfhk.traffical.core.tls.TlsSni

/** A packet's payload in human-readable form: a one-line [summary] and detail [lines]. */
data class DecodedPacket(val summary: String, val lines: List<String>)

/**
 * Turns a transport payload into a readable description, for the connection detail view.
 * It reads what is already in the clear — DNS, HTTP and the TLS handshake (including the
 * server name) — and reports encrypted application data as such. It never throws on
 * malformed or truncated input: it falls back to a short text or byte summary, so the UI
 * can always offer it next to the hex dump.
 */
object PacketDecoder {
    private const val DNS_PORT = 53
    private const val HTTP_PORT = 80

    private val HTTP_METHODS = setOf("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE")

    fun decode(payload: ByteArray, protocol: Int, remotePort: Int, localPort: Int = 0, outgoing: Boolean = true): DecodedPacket {
        if (payload.isEmpty()) return DecodedPacket("no payload", emptyList())
        return try {
            decodeOrThrow(payload, protocol, remotePort, localPort, outgoing)
        } catch (e: Exception) {
            text(payload) // any parsing slip degrades to a safe text/byte view
        }
    }

    private fun decodeOrThrow(payload: ByteArray, protocol: Int, remotePort: Int, localPort: Int, outgoing: Boolean): DecodedPacket {
        val onDnsPort = remotePort == DNS_PORT || localPort == DNS_PORT
        if (onDnsPort) {
            val dns = if (protocol == IpProtocol.TCP) {
                if (payload.size < 2) null else DnsMessage.parse(payload, 2, payload.size - 2)
            } else {
                DnsMessage.parse(payload)
            }
            if (dns != null) return dns(dns)
        }
        if (protocol == IpProtocol.TCP) {
            tls(payload)?.let { return it }
            http(payload)?.let { return it }
        }
        return text(payload)
    }

    private fun dns(message: DnsMessage): DecodedPacket {
        val kind = if (message.isResponse) "response" else "query"
        val question = message.questions.firstOrNull()
        val summary = buildString {
            append("DNS ").append(kind)
            question?.let { append(" ").append(DnsType.name(it.type)).append(" ").append(it.name) }
        }
        val lines = ArrayList<String>()
        for (q in message.questions) lines += "question: ${DnsType.name(q.type)} ${q.name}"
        for (a in message.answers) lines += "answer: ${DnsType.name(a.type)} ${a.name} -> ${a.data}"
        if (message.isResponse) lines += "status: ${rcodeName(message.rcode)}"
        return DecodedPacket(summary, lines)
    }

    /** TLS record layer; reads the handshake (incl. the ClientHello server name) in the clear. */
    private fun tls(payload: ByteArray): DecodedPacket? {
        val type = payload[0].toInt() and 0xff
        if (type !in 0x14..0x17 || payload.size < 5) return null
        val version = u16(payload, 1)
        if (version !in 0x0300..0x0304) return null // not a TLS record

        val lines = ArrayList<String>()
        var summary: String? = null
        var pos = 0
        var records = 0
        while (pos + 5 <= payload.size && records < 16) {
            val recordType = payload[pos].toInt() and 0xff
            val recordLength = u16(payload, pos + 3)
            val bodyStart = pos + 5
            val bodyEnd = minOf(bodyStart + recordLength, payload.size)
            when (recordType) {
                0x16 -> { // Handshake
                    val hs = handshake(payload, bodyStart, bodyEnd)
                    lines += "TLS handshake: $hs"
                    if (summary == null) summary = "TLS $hs"
                }
                0x17 -> {
                    lines += "TLS application data (encrypted), ${recordLength} bytes"
                    if (summary == null) summary = "TLS application data (encrypted)"
                }
                0x15 -> lines += "TLS alert"
                0x14 -> lines += "TLS change cipher spec"
            }
            records++
            if (recordLength == 0) break
            pos = bodyStart + recordLength
        }
        return summary?.let { DecodedPacket(it, lines) }
    }

    private fun handshake(payload: ByteArray, start: Int, end: Int): String {
        if (start >= end) return "fragment"
        return when (payload[start].toInt() and 0xff) {
            // The SNI parser reads from the record start (the whole payload begins there).
            1 -> (TlsSni.parse(payload) as? SniResult.Found)?.let { "ClientHello (server name ${it.hostname})" } ?: "ClientHello"
            2 -> "ServerHello"
            4 -> "NewSessionTicket"
            8 -> "EncryptedExtensions"
            11 -> "Certificate"
            12 -> "ServerKeyExchange"
            13 -> "CertificateRequest"
            14 -> "ServerHelloDone"
            15 -> "CertificateVerify"
            16 -> "ClientKeyExchange"
            20 -> "Finished"
            else -> "message type ${payload[start].toInt() and 0xff}"
        }
    }

    /** HTTP/1.x request or response, if the payload starts like one. */
    private fun http(payload: ByteArray): DecodedPacket? {
        val firstLineEnd = indexOfCrlf(payload, 0, minOf(payload.size, 8 * 1024)) ?: return null
        val firstLine = String(payload, 0, firstLineEnd, Charsets.ISO_8859_1)
        val method = firstLine.substringBefore(' ')
        val isRequest = method in HTTP_METHODS
        val isResponse = firstLine.startsWith("HTTP/")
        if (!isRequest && !isResponse) return null

        val lines = ArrayList<String>()
        var pos = firstLineEnd + 2
        var headers = 0
        while (pos < payload.size && headers < 100) {
            val end = indexOfCrlf(payload, pos, payload.size) ?: break
            if (end == pos) break // blank line: end of headers
            lines += String(payload, pos, end - pos, Charsets.ISO_8859_1)
            pos = end + 2
            headers++
        }
        return DecodedPacket(if (isRequest) "HTTP $firstLine" else firstLine, lines)
    }

    private fun text(payload: ByteArray): DecodedPacket {
        val printable = payload.count { it.toInt() in 0x20..0x7e || it.toInt() == 0x09 || it.toInt() == 0x0a || it.toInt() == 0x0d }
        if (printable >= payload.size * 9 / 10) {
            val preview = String(payload, 0, minOf(payload.size, 2 * 1024), Charsets.ISO_8859_1)
            return DecodedPacket("text, ${payload.size} bytes", preview.lineSequence().take(40).toList())
        }
        return DecodedPacket("binary data, ${payload.size} bytes", emptyList())
    }

    private fun indexOfCrlf(buf: ByteArray, from: Int, to: Int): Int? {
        var i = from
        while (i + 1 < to) {
            if (buf[i].toInt() == 0x0d && buf[i + 1].toInt() == 0x0a) return i
            i++
        }
        return null
    }

    private fun rcodeName(rcode: Int): String = when (rcode) {
        0 -> "NoError"
        1 -> "FormErr"
        2 -> "ServFail"
        3 -> "NXDomain"
        5 -> "Refused"
        else -> "rcode $rcode"
    }

    private fun u16(buf: ByteArray, i: Int) = ((buf[i].toInt() and 0xff) shl 8) or (buf[i + 1].toInt() and 0xff)
}
