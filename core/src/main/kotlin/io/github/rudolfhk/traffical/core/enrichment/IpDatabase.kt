package io.github.rudolfhk.traffical.core.enrichment

import java.io.DataOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer

/** An autonomous system: the network that announces an address, e.g. AS15169 "Google LLC". */
data class Network(val asn: Int, val organization: String)

/**
 * Country and network of IP addresses, from range tables (built from DB-IP Lite by
 * BuildEnrichment). The tables are searched in place, so the app can memory-map the file
 * instead of loading it onto the heap. IPv6 is resolved per /64 network.
 *
 * Layout (big endian): "TALIPDB2", version, country codes, networks (AS number and the
 * offset and length of the organization in a UTF-8 blob), the blob, then four range
 * tables (country IPv4, country IPv6, network IPv4, network IPv6). A table is a count
 * and sorted entries of (start, value): IPv4 starts are 32-bit, IPv6 starts the upper
 * 64 bits of the address. An address belongs to the last entry starting at or below it;
 * value -1 marks a gap.
 */
class IpDatabase private constructor(buffer: ByteBuffer) {
    private val data = buffer.duplicate()
    val version: String
    private val countries: Array<String>
    private val networkCount: Int
    private val networksAt: Int
    private val namesAt: Int
    private val country4: RangeTable
    private val country6: RangeTable
    private val network4: RangeTable
    private val network6: RangeTable
    private val networkCache = object : LinkedHashMap<Int, Network>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, Network>) = size > NETWORK_CACHE_SIZE
    }

    init {
        val reader = data.duplicate()
        val magic = ByteArray(MAGIC.length).also(reader::get)
        if (String(magic, Charsets.US_ASCII) != MAGIC) throw IOException("not an IP database")
        version = readString(reader)
        countries = Array(reader.int) { readString(reader) }
        networkCount = reader.int
        networksAt = reader.position()
        reader.position(networksAt + networkCount * NETWORK_SIZE)
        val namesLength = reader.int
        namesAt = reader.position()
        reader.position(namesAt + namesLength)
        country4 = tableAt(reader, wide = false)
        country6 = tableAt(reader, wide = true)
        network4 = tableAt(reader, wide = false)
        network6 = tableAt(reader, wide = true)
    }

    /** ISO 3166 country code ("US"), or null if unknown. */
    fun country(address: InetAddress): String? = index(address, country4, country6)?.let(countries::get)

    fun network(address: InetAddress): Network? {
        val index = index(address, network4, network6) ?: return null
        synchronized(networkCache) { networkCache[index]?.let { return it } }
        val at = networksAt + index * NETWORK_SIZE
        val name = ByteArray(data.getInt(at + 8))
        data.duplicate().apply { position(namesAt + data.getInt(at + 4)) }.get(name)
        val network = Network(data.getInt(at), String(name, Charsets.UTF_8))
        synchronized(networkCache) { networkCache[index] = network }
        return network
    }

    private fun index(address: InetAddress, v4: RangeTable, v6: RangeTable): Int? {
        val key = ByteBuffer.wrap(address.address)
        val index = when (address) {
            is Inet4Address -> v4.lookup(key.int.toLong() and 0xffffffffL)
            is Inet6Address -> v6.lookup(key.long)
            else -> -1
        }
        return index.takeIf { it >= 0 }
    }

    /** One table inside [data]: [count] entries of 8 (IPv4) or 12 (IPv6) bytes from [at]. */
    private inner class RangeTable(private val at: Int, private val count: Int, private val wide: Boolean) {
        private val size = if (wide) 12 else 8

        fun lookup(key: Long): Int {
            var low = 0
            var high = count - 1
            var found = -1
            while (low <= high) {
                val mid = (low + high) ushr 1
                if (java.lang.Long.compareUnsigned(start(mid), key) <= 0) {
                    found = mid
                    low = mid + 1
                } else {
                    high = mid - 1
                }
            }
            return if (found < 0) -1 else data.getInt(at + found * size + size - 4)
        }

        private fun start(i: Int): Long =
            if (wide) data.getLong(at + i * size) else data.getInt(at + i * size).toLong() and 0xffffffffL
    }

    /** The table starting at [reader]'s position; moves [reader] past it. */
    private fun tableAt(reader: ByteBuffer, wide: Boolean): RangeTable {
        val count = reader.int
        val table = RangeTable(reader.position(), count, wide)
        reader.position(reader.position() + count * if (wide) 12 else 8)
        return table
    }

    companion object {
        private const val MAGIC = "TALIPDB2"
        private const val NETWORK_SIZE = 12
        private const val NETWORK_CACHE_SIZE = 4096

        /** A database in [buffer] (e.g. memory-mapped), which must stay unchanged. */
        fun open(buffer: ByteBuffer): IpDatabase = IpDatabase(buffer)

        /** Reads a whole database onto the heap. */
        fun load(input: InputStream): IpDatabase = open(ByteBuffer.wrap(input.readBytes()))

        private fun readString(reader: ByteBuffer): String {
            val bytes = ByteArray(reader.short.toInt() and 0xffff).also(reader::get)
            return String(bytes, Charsets.UTF_8)
        }
    }

    /**
     * Collects ranges ([start], [end] inclusive) and writes the database. Ranges of one
     * table must not overlap; addresses outside all ranges are unknown.
     */
    class Builder(private val version: String) {
        private val countryIds = LinkedHashMap<String, Int>()
        private val networkIds = LinkedHashMap<Network, Int>()
        private val country4 = ArrayList<Range>()
        private val country6 = ArrayList<Range>()
        private val network4 = ArrayList<Range>()
        private val network6 = ArrayList<Range>()

        fun addCountry(start: InetAddress, end: InetAddress, country: String) {
            val id = countryIds.getOrPut(country) { countryIds.size }
            (if (start.address.size == 4) country4 else country6) += Range(number(start), number(end), id)
        }

        fun addNetwork(start: InetAddress, end: InetAddress, network: Network) {
            val id = networkIds.getOrPut(network) { networkIds.size }
            (if (start.address.size == 4) network4 else network6) += Range(number(start), number(end), id)
        }

        /** Writes the database (uncompressed; the repository keeps it gzipped). */
        fun write(output: OutputStream) {
            val out = DataOutputStream(output)
            out.write(MAGIC.toByteArray(Charsets.US_ASCII))
            writeString(out, version)
            out.writeInt(countryIds.size)
            countryIds.keys.forEach { writeString(out, it) }

            val names = networkIds.keys.map { it.organization.toByteArray(Charsets.UTF_8) }
            out.writeInt(networkIds.size)
            var offset = 0
            for ((i, network) in networkIds.keys.withIndex()) {
                out.writeInt(network.asn)
                out.writeInt(offset)
                out.writeInt(names[i].size)
                offset += names[i].size
            }
            out.writeInt(offset)
            names.forEach(out::write)

            writeTable(out, starts(country4, V4_MAX), wide = false)
            writeTable(out, slash64(starts(country6, V6_MAX)), wide = true)
            writeTable(out, starts(network4, V4_MAX), wide = false)
            writeTable(out, slash64(starts(network6, V6_MAX)), wide = true)
            out.flush()
        }

        private fun writeTable(out: DataOutputStream, entries: List<Pair<BigInteger, Int>>, wide: Boolean) {
            out.writeInt(entries.size)
            for ((start, value) in entries) {
                if (wide) out.writeLong(start.toLong()) else out.writeInt(start.toInt())
                out.writeInt(value)
            }
        }

        private fun number(address: InetAddress) = BigInteger(1, address.address)

        private companion object {
            val V4_MAX: BigInteger = BigInteger.ONE.shiftLeft(32) - BigInteger.ONE
            val V6_MAX: BigInteger = BigInteger.ONE.shiftLeft(128) - BigInteger.ONE

            /** Range starts with their values, and the starts of gaps (-1) between and after them. */
            fun starts(ranges: List<Range>, max: BigInteger): List<Pair<BigInteger, Int>> {
                val sorted = ranges.sortedBy { it.start }
                val starts = ArrayList<Pair<BigInteger, Int>>(sorted.size + sorted.size / 4)
                for ((i, range) in sorted.withIndex()) {
                    if (i > 0) {
                        val previousEnd = sorted[i - 1].end
                        require(range.start > previousEnd) { "overlapping ranges at ${range.start}" }
                        if (previousEnd + BigInteger.ONE < range.start) starts += (previousEnd + BigInteger.ONE) to -1
                    }
                    starts += range.start to range.value
                }
                sorted.lastOrNull()?.takeIf { it.end < max }?.let { starts += (it.end + BigInteger.ONE) to -1 }
                return starts
            }

            /**
             * IPv6 starts reduced to their /64 network (the upper 64 bits). A /64 takes the
             * value at its first address, or, if that is a gap, the first known value inside
             * it; a value starting inside a /64 that is already taken begins at the next one.
             */
            fun slash64(starts: List<Pair<BigInteger, Int>>): List<Pair<BigInteger, Int>> {
                val keys = ArrayList<BigInteger>(starts.size)
                val values = ArrayList<Int>(starts.size)
                fun put(key: BigInteger, value: Int) {
                    if (keys.lastOrNull() == key) {
                        values[values.size - 1] = value
                    } else {
                        keys += key
                        values += value
                    }
                }
                for ((start, value) in starts) {
                    val network = start.shiftRight(64)
                    if (start == network.shiftLeft(64)) {
                        put(network, value)
                        continue
                    }
                    // Keys never pass network + 1, so the value at the start of this /64 is
                    // the last or second-last one.
                    val i = if (keys.lastOrNull()?.let { it > network } == true) keys.size - 2 else keys.size - 1
                    val atStart = if (i >= 0) values[i] else -1
                    put(if (atStart < 0 && value >= 0) network else network + BigInteger.ONE, value)
                }
                val result = ArrayList<Pair<BigInteger, Int>>(keys.size)
                for (i in keys.indices) {
                    if (result.lastOrNull()?.second != values[i]) result += keys[i] to values[i]
                }
                return result
            }

            fun writeString(out: DataOutputStream, text: String) {
                val bytes = text.toByteArray(Charsets.UTF_8)
                out.writeShort(bytes.size)
                out.write(bytes)
            }
        }
    }

    internal class Range(val start: BigInteger, val end: BigInteger, val value: Int)
}
