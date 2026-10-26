package io.github.rudolfhk.traffical.core.dns

import java.net.InetAddress

object DnsType {
    const val A = 1
    const val NS = 2
    const val CNAME = 5
    const val SOA = 6
    const val PTR = 12
    const val MX = 15
    const val TXT = 16
    const val AAAA = 28
    const val SRV = 33
    const val SVCB = 64
    const val HTTPS = 65

    fun name(type: Int): String = when (type) {
        A -> "A"
        NS -> "NS"
        CNAME -> "CNAME"
        SOA -> "SOA"
        PTR -> "PTR"
        MX -> "MX"
        TXT -> "TXT"
        AAAA -> "AAAA"
        SRV -> "SRV"
        SVCB -> "SVCB"
        HTTPS -> "HTTPS"
        else -> "TYPE$type"
    }
}

data class DnsQuestion(val name: String, val type: Int)

/** [data] is an IP address for A/AAAA, a domain for CNAME/NS/PTR, and empty otherwise. */
data class DnsRecord(val name: String, val type: Int, val ttl: Long, val data: String)

/**
 * The parts of a DNS message (RFC 1035) needed for traffic attribution: the questions and
 * the answer section. Authority and additional sections are ignored.
 */
data class DnsMessage(
    val id: Int,
    val isResponse: Boolean,
    val rcode: Int,
    val questions: List<DnsQuestion>,
    val answers: List<DnsRecord>,
) {
    companion object {
        private const val MAX_NAME_LENGTH = 255
        private const val MAX_POINTER_JUMPS = 32

        /** Returns null if the message is truncated or malformed. */
        fun parse(buf: ByteArray, offset: Int = 0, length: Int = buf.size - offset): DnsMessage? = try {
            Reader(buf, offset, length).message()
        } catch (malformed: MalformedDnsException) {
            null
        }
    }

    private class MalformedDnsException : Exception()

    private class Reader(private val buf: ByteArray, private val start: Int, length: Int) {
        private val end = start + length
        private var pos = start

        fun message(): DnsMessage {
            if (start < 0 || end > buf.size) throw MalformedDnsException()
            val id = u16()
            val flags = u16()
            val questionCount = u16()
            val answerCount = u16()
            skip(4) // authority + additional counts

            val questions = List(questionCount) {
                val name = name()
                val type = u16()
                skip(2) // class
                DnsQuestion(name, type)
            }
            val answers = List(answerCount) { record() }

            return DnsMessage(
                id = id,
                isResponse = flags and 0x8000 != 0,
                rcode = flags and 0x000f,
                questions = questions,
                answers = answers,
            )
        }

        private fun record(): DnsRecord {
            val name = name()
            val type = u16()
            skip(2) // class
            val ttl = (u16().toLong() shl 16) or u16().toLong()
            val dataLength = u16()
            val dataStart = pos
            need(dataLength)
            val data = when {
                type == DnsType.A && dataLength == 4 ||
                    type == DnsType.AAAA && dataLength == 16 ->
                    InetAddress.getByAddress(buf.copyOfRange(dataStart, dataStart + dataLength)).hostAddress
                type == DnsType.CNAME || type == DnsType.NS || type == DnsType.PTR -> name()
                else -> ""
            }
            pos = dataStart + dataLength
            return DnsRecord(name, type, ttl, data)
        }

        /** Reads a possibly compressed domain name and leaves [pos] behind it. */
        private fun name(): String {
            val labels = StringBuilder()
            var cursor = pos
            var resumeAt = -1
            var jumps = 0
            while (true) {
                if (cursor >= end) throw MalformedDnsException()
                val len = buf[cursor].toInt() and 0xff
                when {
                    len == 0 -> {
                        cursor++
                        break
                    }
                    len and 0xc0 == 0xc0 -> {
                        if (cursor + 1 >= end || ++jumps > MAX_POINTER_JUMPS) throw MalformedDnsException()
                        if (resumeAt < 0) resumeAt = cursor + 2
                        cursor = start + (((len and 0x3f) shl 8) or (buf[cursor + 1].toInt() and 0xff))
                    }
                    len and 0xc0 != 0 -> throw MalformedDnsException()
                    else -> {
                        if (cursor + 1 + len > end) throw MalformedDnsException()
                        if (labels.isNotEmpty()) labels.append('.')
                        for (i in cursor + 1..cursor + len) labels.append((buf[i].toInt() and 0xff).toChar())
                        if (labels.length > MAX_NAME_LENGTH) throw MalformedDnsException()
                        cursor += 1 + len
                    }
                }
            }
            pos = if (resumeAt >= 0) resumeAt else cursor
            return if (labels.isEmpty()) "." else labels.toString()
        }

        private fun u16(): Int {
            need(2)
            val value = ((buf[pos].toInt() and 0xff) shl 8) or (buf[pos + 1].toInt() and 0xff)
            pos += 2
            return value
        }

        private fun skip(count: Int) {
            need(count)
            pos += count
        }

        private fun need(count: Int) {
            if (pos + count > end) throw MalformedDnsException()
        }
    }
}
