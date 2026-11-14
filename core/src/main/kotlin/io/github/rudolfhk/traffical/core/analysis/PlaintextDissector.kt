package io.github.rudolfhk.traffical.core.analysis

import io.github.rudolfhk.traffical.core.packet.IpProtocol
import java.io.ByteArrayOutputStream

/** One HTTP header field. */
data class HttpHeader(val name: String, val value: String)

enum class HttpKind { REQUEST, RESPONSE }

/** Which application protocol the decrypted bytes turned out to be. */
enum class HttpProtocol { HTTP_1, HTTP_2, HTTP_3, OTHER }

/**
 * One HTTP message recovered from decrypted application data. For a request [method],
 * [authority] and [path] are set; for a response [status]. [headers] excludes HTTP/2 pseudo
 * headers. [bodyPreview] is a bounded, printable view of the body ("" if empty or binary).
 */
data class HttpMessage(
    val kind: HttpKind,
    val method: String? = null,
    val authority: String? = null,
    val path: String? = null,
    val status: Int? = null,
    val headers: List<HttpHeader> = emptyList(),
    val contentType: String? = null,
    val bodyPreview: String = "",
    val bodyBytes: Int = 0,
) {
    fun header(name: String): String? = headers.firstOrNull { it.name.equals(name, ignoreCase = true) }?.value

    /** A one-line description, e.g. "POST example.com/track" or "HTTP 200". */
    val line: String
        get() = when (kind) {
            HttpKind.REQUEST -> buildString {
                append(method ?: "?")
                append(' ')
                append(authority ?: "")
                append(path ?: "")
            }.trim()
            HttpKind.RESPONSE -> "HTTP ${status ?: "?"}"
        }
}

/** The HTTP messages recovered from one connection's decrypted streams. */
data class Dissection(
    val protocol: HttpProtocol,
    val requests: List<HttpMessage>,
    val responses: List<HttpMessage>,
) {
    val isEmpty: Boolean get() = requests.isEmpty() && responses.isEmpty()

    companion object {
        val EMPTY = Dissection(HttpProtocol.OTHER, emptyList(), emptyList())
    }
}

/**
 * Turns the decrypted application bytes of a connection (client→server and server→client)
 * into structured [HttpMessage]s, so a data-flow audit can say what an app sent where. It
 * reads HTTP/1.x fully, HTTP/2 including HPACK-compressed headers ([HpackDecoder]), and
 * HTTP/3 stream data over QUIC (DATA frames; QPACK headers are not decoded — noted, not
 * guessed). It never throws: anything unparsable degrades to an empty or partial result.
 *
 * It only reads bytes the caller already decrypted with the owner's keys (phase 8/11);
 * nothing here weakens TLS or leaves the device.
 */
object PlaintextDissector {
    private const val MAX_MESSAGES = 64
    private const val MAX_BODY_PREVIEW = 4096
    private const val MAX_FRAMES = 4096
    private val HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
    private val HTTP_METHODS = setOf("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE")

    /** Dissects a connection; [protocol] is the IP protocol (TCP → HTTP/1 or /2, UDP → HTTP/3). */
    fun dissect(toServer: ByteArray, toClient: ByteArray, protocol: Int): Dissection = try {
        when (protocol) {
            IpProtocol.UDP -> http3(toServer, toClient)
            else -> if (startsWith(toServer, HTTP2_PREFACE)) {
                http2(toServer, toClient)
            } else {
                http1(toServer, toClient)
            }
        }
    } catch (_: Exception) {
        Dissection.EMPTY
    }

    // ---- HTTP/1.x ----------------------------------------------------------------------

    private fun http1(toServer: ByteArray, toClient: ByteArray): Dissection {
        val requests = parseHttp1(toServer, HttpKind.REQUEST)
        val responses = parseHttp1(toClient, HttpKind.RESPONSE)
        if (requests.isEmpty() && responses.isEmpty()) return Dissection.EMPTY
        return Dissection(HttpProtocol.HTTP_1, requests, responses)
    }

    private fun parseHttp1(buf: ByteArray, kind: HttpKind): List<HttpMessage> {
        val out = ArrayList<HttpMessage>()
        var pos = 0
        while (pos < buf.size && out.size < MAX_MESSAGES) {
            val lineEnd = indexOfCrlf(buf, pos, buf.size) ?: break
            val startLine = String(buf, pos, lineEnd - pos, Charsets.ISO_8859_1)
            val firstWord = startLine.substringBefore(' ')
            val isRequest = firstWord in HTTP_METHODS
            val isResponse = startLine.startsWith("HTTP/")
            if (!isRequest && !isResponse) break

            var p = lineEnd + 2
            val headers = ArrayList<HttpHeader>()
            while (p < buf.size && headers.size < 200) {
                val end = indexOfCrlf(buf, p, buf.size) ?: break
                if (end == p) { p += 2; break } // blank line ends headers
                val header = String(buf, p, end - p, Charsets.ISO_8859_1)
                val colon = header.indexOf(':')
                if (colon > 0) headers += HttpHeader(header.take(colon).trim(), header.substring(colon + 1).trim())
                p = end + 2
            }

            val contentLength = headers.firstOrNull { it.name.equals("content-length", true) }?.value?.trim()?.toIntOrNull()
            val chunked = headers.any { it.name.equals("transfer-encoding", true) && it.value.contains("chunked", true) }
            val body: ByteArray
            when {
                chunked -> { val (b, np) = readChunked(buf, p); body = b; p = np }
                contentLength != null -> {
                    val end = minOf(p + contentLength.coerceAtLeast(0), buf.size)
                    body = buf.copyOfRange(p, end); p = end
                }
                isResponse -> { body = buf.copyOfRange(p, buf.size); p = buf.size } // no delimiter: rest is body
                else -> body = ByteArray(0)
            }

            out += message(kind, startLine, headers, body)
            if (p <= pos) break // no progress: stop
            pos = p
        }
        return out
    }

    private fun message(kind: HttpKind, startLine: String, headers: List<HttpHeader>, body: ByteArray): HttpMessage {
        val contentType = headers.firstOrNull { it.name.equals("content-type", true) }?.value
        return if (kind == HttpKind.REQUEST) {
            val parts = startLine.split(' ')
            val method = parts.getOrNull(0)
            val target = parts.getOrNull(1) ?: ""
            val host = headers.firstOrNull { it.name.equals("host", true) }?.value
            val (authority, path) = splitTarget(target, host)
            HttpMessage(kind, method = method, authority = authority, path = path, headers = headers,
                contentType = contentType, bodyPreview = preview(body), bodyBytes = body.size)
        } else {
            val status = startLine.split(' ').getOrNull(1)?.toIntOrNull()
            HttpMessage(kind, status = status, headers = headers, contentType = contentType,
                bodyPreview = preview(body), bodyBytes = body.size)
        }
    }

    private fun splitTarget(target: String, host: String?): Pair<String?, String?> {
        if (target.startsWith("http://") || target.startsWith("https://")) {
            val rest = target.substringAfter("://")
            val authority = rest.substringBefore('/')
            val path = rest.substring(authority.length).ifEmpty { "/" }
            return authority to path
        }
        return host to target
    }

    private fun readChunked(buf: ByteArray, start: Int): Pair<ByteArray, Int> {
        val out = ByteArrayOutputStream()
        var p = start
        var guard = 0
        while (p < buf.size && guard < 10_000 && out.size() < MAX_BODY_PREVIEW * 4) {
            guard++
            val end = indexOfCrlf(buf, p, buf.size) ?: break
            val sizeHex = String(buf, p, end - p, Charsets.ISO_8859_1).substringBefore(';').trim()
            val size = sizeHex.toIntOrNull(16) ?: break
            p = end + 2
            if (size == 0) break
            val chunkEnd = minOf(p + size, buf.size)
            out.write(buf, p, chunkEnd - p)
            p = chunkEnd
            if (p + 2 <= buf.size) p += 2 // trailing CRLF
        }
        return out.toByteArray() to p
    }

    // ---- HTTP/2 ------------------------------------------------------------------------

    private class Stream {
        val headers = ArrayList<HttpHeader>()
        val data = ByteArrayOutputStream()
        val pending = ByteArrayOutputStream() // header-block fragment awaiting END_HEADERS
    }

    private fun http2(toServer: ByteArray, toClient: ByteArray): Dissection {
        val requests = parseHttp2(toServer, HTTP2_PREFACE.size, HttpKind.REQUEST)
        val responses = parseHttp2(toClient, 0, HttpKind.RESPONSE)
        if (requests.isEmpty() && responses.isEmpty()) return Dissection.EMPTY
        return Dissection(HttpProtocol.HTTP_2, requests, responses)
    }

    private fun parseHttp2(buf: ByteArray, startOffset: Int, kind: HttpKind): List<HttpMessage> {
        val decoder = HpackDecoder()
        val streams = LinkedHashMap<Int, Stream>()
        var pos = startOffset
        var frames = 0
        while (pos + 9 <= buf.size && frames < MAX_FRAMES) {
            frames++
            val length = u24(buf, pos)
            val type = buf[pos + 3].toInt() and 0xff
            val flags = buf[pos + 4].toInt() and 0xff
            val streamId = u32(buf, pos + 5) and 0x7fffffff
            val payloadStart = pos + 9
            val payloadEnd = minOf(payloadStart + length, buf.size)
            if (payloadStart > buf.size) break
            when (type) {
                0x0 -> { // DATA
                    val (from, to) = dePad(buf, payloadStart, payloadEnd, flags and 0x08 != 0)
                    val s = streams.getOrPut(streamId) { Stream() }
                    if (s.data.size() < MAX_BODY_PREVIEW * 4) s.data.write(buf, from, to - from)
                }
                0x1, 0x9 -> { // HEADERS (0x1) or CONTINUATION (0x9)
                    var from = payloadStart
                    var to = payloadEnd
                    if (type == 0x1) {
                        val padded = flags and 0x08 != 0
                        if (padded && payloadStart < buf.size) to -= (buf[payloadStart].toInt() and 0xff)
                        if (padded) from += 1 // skip the pad-length octet
                        if (flags and 0x20 != 0) from += 5 // priority (exclusive dep + weight)
                    }
                    val s = streams.getOrPut(streamId) { Stream() }
                    if (from in 0..to && to <= buf.size) s.pending.write(buf, from, to - from)
                    if (flags and 0x04 != 0) { // END_HEADERS: decode in frame order
                        s.headers += decoder.decode(s.pending.toByteArray())
                        s.pending.reset()
                    }
                }
            }
            pos = payloadEnd
        }
        val out = ArrayList<HttpMessage>()
        for ((_, s) in streams) {
            if (s.headers.isEmpty() && s.data.size() == 0) continue
            out += http2Message(kind, s.headers, s.data.toByteArray())
            if (out.size >= MAX_MESSAGES) break
        }
        return out
    }

    private fun http2Message(kind: HttpKind, headers: List<HttpHeader>, body: ByteArray): HttpMessage {
        val regular = headers.filter { !it.name.startsWith(":") }
        fun pseudo(n: String) = headers.firstOrNull { it.name == n }?.value
        val contentType = regular.firstOrNull { it.name.equals("content-type", true) }?.value
        return if (kind == HttpKind.REQUEST) {
            HttpMessage(kind, method = pseudo(":method"), authority = pseudo(":authority"), path = pseudo(":path"),
                headers = regular, contentType = contentType, bodyPreview = preview(body), bodyBytes = body.size)
        } else {
            HttpMessage(kind, status = pseudo(":status")?.toIntOrNull(), headers = regular,
                contentType = contentType, bodyPreview = preview(body), bodyBytes = body.size)
        }
    }

    private fun dePad(buf: ByteArray, start: Int, end: Int, padded: Boolean): Pair<Int, Int> {
        if (!padded || start >= end) return start to end
        val pad = buf[start].toInt() and 0xff
        return (start + 1) to maxOf(start + 1, end - pad)
    }

    // ---- HTTP/3 (over QUIC) ------------------------------------------------------------

    private fun http3(toServer: ByteArray, toClient: ByteArray): Dissection {
        val req = parseHttp3(toServer, HttpKind.REQUEST)
        val resp = parseHttp3(toClient, HttpKind.RESPONSE)
        if (req == null && resp == null) {
            // Not recognizable HTTP/3 framing; still offer the raw stream as a body preview.
            if (toServer.isEmpty() && toClient.isEmpty()) return Dissection.EMPTY
            return Dissection(
                HttpProtocol.HTTP_3,
                listOfNotNull(rawMessage(HttpKind.REQUEST, toServer)),
                listOfNotNull(rawMessage(HttpKind.RESPONSE, toClient)),
            )
        }
        return Dissection(HttpProtocol.HTTP_3, listOfNotNull(req), listOfNotNull(resp))
    }

    private fun parseHttp3(buf: ByteArray, kind: HttpKind): HttpMessage? {
        if (buf.isEmpty()) return null
        val data = ByteArrayOutputStream()
        var sawHeaders = false
        var sawFrame = false
        var pos = 0
        var frames = 0
        while (pos < buf.size && frames < MAX_FRAMES) {
            frames++
            val (type, p1) = readVarint(buf, pos) ?: break
            val (len, p2) = readVarint(buf, p1) ?: break
            val end = minOf(p2 + len.toInt().coerceAtLeast(0), buf.size)
            when (type) {
                0x0L -> { if (data.size() < MAX_BODY_PREVIEW * 4) data.write(buf, p2, end - p2); sawFrame = true }
                0x1L -> { sawHeaders = true; sawFrame = true } // HEADERS: QPACK, not decoded here
            }
            if (end <= pos) break
            pos = end
        }
        if (!sawFrame) return null
        val headers = if (sawHeaders) listOf(HttpHeader("(headers)", "QPACK-compressed, not decoded in app")) else emptyList()
        val body = data.toByteArray()
        return HttpMessage(kind, headers = headers, bodyPreview = preview(body), bodyBytes = body.size)
    }

    private fun rawMessage(kind: HttpKind, buf: ByteArray): HttpMessage? {
        if (buf.isEmpty()) return null
        return HttpMessage(kind, bodyPreview = preview(buf), bodyBytes = buf.size)
    }

    // ---- shared helpers ----------------------------------------------------------------

    /** A bounded, printable preview of a body; "" when empty or mostly binary. */
    private fun preview(body: ByteArray): String {
        if (body.isEmpty()) return ""
        val n = minOf(body.size, MAX_BODY_PREVIEW)
        var printable = 0
        for (i in 0 until n) {
            val c = body[i].toInt() and 0xff
            if (c in 0x20..0x7e || c == 0x09 || c == 0x0a || c == 0x0d) printable++
        }
        if (printable < n * 85 / 100) return ""
        return String(body, 0, n, Charsets.ISO_8859_1)
    }

    private fun startsWith(buf: ByteArray, prefix: ByteArray): Boolean {
        if (buf.size < prefix.size) return false
        for (i in prefix.indices) if (buf[i] != prefix[i]) return false
        return true
    }

    private fun indexOfCrlf(buf: ByteArray, from: Int, to: Int): Int? {
        var i = from
        while (i + 1 < to) {
            if (buf[i].toInt() == 0x0d && buf[i + 1].toInt() == 0x0a) return i
            i++
        }
        return null
    }

    /** QUIC/HTTP-3 variable-length integer (RFC 9000 §16). Returns value and next index. */
    private fun readVarint(buf: ByteArray, pos: Int): Pair<Long, Int>? {
        if (pos >= buf.size) return null
        val first = buf[pos].toInt() and 0xff
        val lenBytes = 1 shl (first ushr 6)
        if (pos + lenBytes > buf.size) return null
        var value = (first and 0x3f).toLong()
        for (i in 1 until lenBytes) value = (value shl 8) or (buf[pos + i].toLong() and 0xff)
        return value to (pos + lenBytes)
    }

    private fun u24(buf: ByteArray, i: Int) =
        ((buf[i].toInt() and 0xff) shl 16) or ((buf[i + 1].toInt() and 0xff) shl 8) or (buf[i + 2].toInt() and 0xff)

    private fun u32(buf: ByteArray, i: Int) =
        ((buf[i].toInt() and 0xff) shl 24) or ((buf[i + 1].toInt() and 0xff) shl 16) or
            ((buf[i + 2].toInt() and 0xff) shl 8) or (buf[i + 3].toInt() and 0xff)
}
