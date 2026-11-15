package io.github.rudolfhk.traffical.core.analysis

/**
 * HPACK (RFC 7541) header-block decoder, for reading HTTP/2 request/response headers once a
 * connection's application data has been decrypted with the owner's keys (phase 12). HTTP/2
 * compresses headers with HPACK, so without this the method, authority, path, cookies and
 * auth tokens — exactly the fields a data-flow audit cares about — would be opaque.
 *
 * One [HpackDecoder] is used per direction and keeps the dynamic table across the whole
 * connection. It never throws: malformed or truncated input yields the headers decoded so
 * far. Huffman coverage is the printable-ASCII range (RFC 7541 Appendix B symbols 0–126),
 * which is every character that appears in real header names and values; a Huffman-coded
 * non-ASCII byte ends that string early rather than producing a wrong character.
 */
internal object Hpack {
    /** RFC 7541 Appendix A static table (index 1..61); value is "" where the entry has none. */
    val STATIC: List<Pair<String, String>> = listOf(
        "" to "", // index 0 unused
        ":authority" to "",
        ":method" to "GET",
        ":method" to "POST",
        ":path" to "/",
        ":path" to "/index.html",
        ":scheme" to "http",
        ":scheme" to "https",
        ":status" to "200",
        ":status" to "204",
        ":status" to "206",
        ":status" to "304",
        ":status" to "400",
        ":status" to "404",
        ":status" to "500",
        "accept-charset" to "",
        "accept-encoding" to "gzip, deflate",
        "accept-language" to "",
        "accept-ranges" to "",
        "accept" to "",
        "access-control-allow-origin" to "",
        "age" to "",
        "allow" to "",
        "authorization" to "",
        "cache-control" to "",
        "content-disposition" to "",
        "content-encoding" to "",
        "content-language" to "",
        "content-length" to "",
        "content-location" to "",
        "content-range" to "",
        "content-type" to "",
        "cookie" to "",
        "date" to "",
        "etag" to "",
        "expect" to "",
        "expires" to "",
        "from" to "",
        "host" to "",
        "if-match" to "",
        "if-modified-since" to "",
        "if-none-match" to "",
        "if-range" to "",
        "if-unmodified-since" to "",
        "last-modified" to "",
        "link" to "",
        "location" to "",
        "max-forwards" to "",
        "proxy-authenticate" to "",
        "proxy-authorization" to "",
        "range" to "",
        "referer" to "",
        "refresh" to "",
        "retry-after" to "",
        "server" to "",
        "set-cookie" to "",
        "strict-transport-security" to "",
        "transfer-encoding" to "",
        "user-agent" to "",
        "vary" to "",
        "via" to "",
        "www-authenticate" to "",
    )

    // RFC 7541 Appendix B Huffman codes for symbols 0..126, as (code, bitLength). The long
    // codes for bytes 127..255 are omitted deliberately: they never appear in ASCII header
    // text, and because the code is prefix-free an omitted code simply ends the string early
    // (graceful) instead of mis-decoding. EOS (256) is handled as end-of-input padding.
    private val HUFF: Array<IntArray> = arrayOf(
        intArrayOf(0x1ff8, 13), intArrayOf(0x7fffd8, 23), intArrayOf(0xfffffe2, 28), intArrayOf(0xfffffe3, 28),
        intArrayOf(0xfffffe4, 28), intArrayOf(0xfffffe5, 28), intArrayOf(0xfffffe6, 28), intArrayOf(0xfffffe7, 28),
        intArrayOf(0xfffffe8, 28), intArrayOf(0xffffea, 24), intArrayOf(0x3ffffffc, 30), intArrayOf(0xfffffe9, 28),
        intArrayOf(0xfffffea, 28), intArrayOf(0x3ffffffd, 30), intArrayOf(0xfffffeb, 28), intArrayOf(0xfffffec, 28),
        intArrayOf(0xfffffed, 28), intArrayOf(0xfffffee, 28), intArrayOf(0xfffffef, 28), intArrayOf(0xffffff0, 28),
        intArrayOf(0xffffff1, 28), intArrayOf(0xffffff2, 28), intArrayOf(0x3ffffffe, 30), intArrayOf(0xffffff3, 28),
        intArrayOf(0xffffff4, 28), intArrayOf(0xffffff5, 28), intArrayOf(0xffffff6, 28), intArrayOf(0xffffff7, 28),
        intArrayOf(0xffffff8, 28), intArrayOf(0xffffff9, 28), intArrayOf(0xffffffa, 28), intArrayOf(0xffffffb, 28),
        intArrayOf(0x14, 6), intArrayOf(0x3f8, 10), intArrayOf(0x3f9, 10), intArrayOf(0xffa, 12),
        intArrayOf(0x1ff9, 13), intArrayOf(0x15, 6), intArrayOf(0xf8, 8), intArrayOf(0x7fa, 11),
        intArrayOf(0x3fa, 10), intArrayOf(0x3fb, 10), intArrayOf(0xf9, 8), intArrayOf(0x7fb, 11),
        intArrayOf(0xfa, 8), intArrayOf(0x16, 6), intArrayOf(0x17, 6), intArrayOf(0x18, 6),
        intArrayOf(0x0, 5), intArrayOf(0x1, 5), intArrayOf(0x2, 5), intArrayOf(0x19, 6),
        intArrayOf(0x1a, 6), intArrayOf(0x1b, 6), intArrayOf(0x1c, 6), intArrayOf(0x1d, 6),
        intArrayOf(0x1e, 6), intArrayOf(0x1f, 6), intArrayOf(0x5c, 7), intArrayOf(0xfb, 8),
        intArrayOf(0x7ffc, 15), intArrayOf(0x20, 6), intArrayOf(0xffd, 12), intArrayOf(0x7ffd, 15),
        intArrayOf(0x1ffa, 13), intArrayOf(0x21, 6), intArrayOf(0x5d, 7), intArrayOf(0x5e, 7),
        intArrayOf(0x5f, 7), intArrayOf(0x60, 7), intArrayOf(0x61, 7), intArrayOf(0x62, 7),
        intArrayOf(0x63, 7), intArrayOf(0x64, 7), intArrayOf(0x65, 7), intArrayOf(0x66, 7),
        intArrayOf(0x67, 7), intArrayOf(0x68, 7), intArrayOf(0x69, 7), intArrayOf(0x6a, 7),
        intArrayOf(0x6b, 7), intArrayOf(0x6c, 7), intArrayOf(0x6d, 7), intArrayOf(0x6e, 7),
        intArrayOf(0x6f, 7), intArrayOf(0x70, 7), intArrayOf(0x71, 7), intArrayOf(0x72, 7),
        intArrayOf(0xfc, 8), intArrayOf(0x73, 7), intArrayOf(0xfd, 8), intArrayOf(0x1ffb, 13),
        intArrayOf(0x7fff0, 19), intArrayOf(0x1ffc, 13), intArrayOf(0x3ffc, 14), intArrayOf(0x22, 6),
        intArrayOf(0x7ffe, 15), intArrayOf(0x3, 5), intArrayOf(0x23, 6), intArrayOf(0x4, 5),
        intArrayOf(0x24, 6), intArrayOf(0x5, 5), intArrayOf(0x25, 6), intArrayOf(0x26, 6),
        intArrayOf(0x27, 6), intArrayOf(0x6, 5), intArrayOf(0x74, 7), intArrayOf(0x75, 7),
        intArrayOf(0x28, 6), intArrayOf(0x29, 6), intArrayOf(0x2a, 6), intArrayOf(0x7, 5),
        intArrayOf(0x2b, 6), intArrayOf(0x76, 7), intArrayOf(0x2c, 6), intArrayOf(0x8, 5),
        intArrayOf(0x9, 5), intArrayOf(0x2d, 6), intArrayOf(0x77, 7), intArrayOf(0x78, 7),
        intArrayOf(0x79, 7), intArrayOf(0x7a, 7), intArrayOf(0x7b, 7), intArrayOf(0x7ffc, 15),
    )

    // (bitLength shl 32) | code  ->  symbol, built once from HUFF.
    private val CODE_TO_SYM: HashMap<Long, Int> = HashMap<Long, Int>(256).apply {
        for (sym in HUFF.indices) {
            val code = HUFF[sym][0].toLong() and 0xffffffffL
            val len = HUFF[sym][1]
            put((len.toLong() shl 32) or code, sym)
        }
    }

    private const val MAX_STRING = 64 * 1024

    /** Decodes a Huffman string; stops at the first byte that cannot be an ASCII symbol. */
    fun huffman(data: ByteArray): String {
        val out = StringBuilder()
        var cur = 0L
        var bits = 0
        for (b in data) {
            cur = (cur shl 8) or (b.toLong() and 0xff)
            bits += 8
            // Keep only the unconsumed low bits so cur cannot overflow on long strings.
            if (bits < 64) cur = cur and ((1L shl bits) - 1)
            // Decode every complete code now buffered. When the leading bits match no code,
            // the next symbol is simply longer than what is buffered, so break and read more
            // input; any bits left once the stream ends are the all-ones EOS padding.
            while (true) {
                var matched = false
                val maxLen = minOf(bits, 30)
                var len = 5
                while (len <= maxLen) {
                    val code = (cur ushr (bits - len)) and ((1L shl len) - 1)
                    val sym = CODE_TO_SYM[(len.toLong() shl 32) or code]
                    if (sym != null) {
                        if (sym == 256) return out.toString() // EOS is not expected mid-string
                        out.append(sym.toChar())
                        bits -= len
                        matched = true
                        break
                    }
                    len++
                }
                if (!matched || out.length >= MAX_STRING) break
            }
            if (out.length >= MAX_STRING) break
        }
        return out.toString()
    }

    /** HPACK integer with an [prefixBits]-bit prefix at [pos]. Returns value and next index. */
    fun decodeInt(buf: ByteArray, pos: Int, prefixBits: Int): IntArray {
        val mask = (1 shl prefixBits) - 1
        var value = buf[pos].toInt() and mask
        var p = pos + 1
        if (value < mask) return intArrayOf(value, p)
        var shift = 0
        while (p < buf.size) {
            val b = buf[p].toInt() and 0xff
            p++
            value += (b and 0x7f) shl shift
            shift += 7
            if (b and 0x80 == 0) break
            if (shift > 28) break // guard against a runaway integer
        }
        return intArrayOf(value, p)
    }

    /** HPACK string literal at [pos] (H flag + length + octets). Returns value and next index. */
    fun decodeString(buf: ByteArray, pos: Int): Pair<String, Int> {
        val huff = (buf[pos].toInt() and 0x80) != 0
        val (len, p) = decodeInt(buf, pos, 7).let { it[0] to it[1] }
        val end = minOf(p + len, buf.size)
        val slice = buf.copyOfRange(p, end)
        val s = if (huff) huffman(slice) else String(slice, Charsets.ISO_8859_1)
        return s to end
    }
}

/**
 * A stateful HPACK decoder for one direction of an HTTP/2 connection; call [decode] for each
 * header block in order so the dynamic table stays consistent. Never throws.
 */
internal class HpackDecoder(private var maxSize: Int = 4096) {
    private val dynamic = ArrayDeque<Pair<String, String>>() // most-recent first
    private var size = 0

    fun decode(block: ByteArray): List<HttpHeader> {
        val out = ArrayList<HttpHeader>()
        var i = 0
        try {
            while (i < block.size) {
                val b = block[i].toInt() and 0xff
                when {
                    b and 0x80 != 0 -> { // indexed header field
                        val r = Hpack.decodeInt(block, i, 7); i = r[1]
                        entryAt(r[0])?.let { out += HttpHeader(it.first, it.second) }
                    }
                    b and 0x40 != 0 -> { // literal with incremental indexing
                        i = readNameValue(block, i, 6, out, index = true)
                    }
                    b and 0x20 != 0 -> { // dynamic table size update
                        val r = Hpack.decodeInt(block, i, 5); i = r[1]; resize(r[0])
                    }
                    else -> { // without indexing (0x00) or never indexed (0x10)
                        i = readNameValue(block, i, 4, out, index = false)
                    }
                }
            }
        } catch (_: Exception) {
            // Truncated or malformed block: keep what decoded cleanly.
        }
        return out
    }

    private fun readNameValue(buf: ByteArray, pos: Int, prefixBits: Int, out: MutableList<HttpHeader>, index: Boolean): Int {
        val r = Hpack.decodeInt(buf, pos, prefixBits)
        val nameIndex = r[0]
        var p = r[1]
        val name: String
        if (nameIndex == 0) {
            val (n, pn) = Hpack.decodeString(buf, p); name = n; p = pn
        } else {
            name = entryAt(nameIndex)?.first ?: ""
        }
        val (value, pv) = Hpack.decodeString(buf, p)
        if (index) insert(name, value)
        out += HttpHeader(name, value)
        return pv
    }

    private fun entryAt(index: Int): Pair<String, String>? = when {
        index in 1..61 -> Hpack.STATIC[index]
        index >= 62 && index - 62 < dynamic.size -> dynamic[index - 62]
        else -> null
    }

    private fun insert(name: String, value: String) {
        dynamic.addFirst(name to value)
        size += name.length + value.length + 32
        evict()
    }

    private fun resize(newMax: Int) {
        maxSize = newMax
        evict()
    }

    private fun evict() {
        while (size > maxSize && dynamic.isNotEmpty()) {
            val (n, v) = dynamic.removeLast()
            size -= n.length + v.length + 32
        }
    }
}
