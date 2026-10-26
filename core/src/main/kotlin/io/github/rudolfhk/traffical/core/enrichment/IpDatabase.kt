package io.github.rudolfhk.traffical.core.enrichment

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
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
 * BuildEnrichment). [version] says where the data comes from and how old it is.
 */
class IpDatabase internal constructor(
    val version: String,
    private val countries: Array<String>,
    private val networks: Array<Network>,
    private val country4: RangeTable,
    private val country6: RangeTable,
    private val network4: RangeTable,
    private val network6: RangeTable,
) {
    /** ISO 3166 country code ("US"), or null if unknown. */
    fun country(address: InetAddress): String? = table(address, country4, country6)?.let(countries::get)

    fun network(address: InetAddress): Network? = table(address, network4, network6)?.let(networks::get)

    private fun table(address: InetAddress, v4: RangeTable, v6: RangeTable): Int? {
        val bytes = address.address
        val index = when (address) {
            is Inet4Address -> v4.lookup(0, ByteBuffer.wrap(bytes).int.toLong() and 0xffffffffL)
            is Inet6Address -> ByteBuffer.wrap(bytes).let { v6.lookup(it.long, it.long) }
            else -> -1
        }
        return index.takeIf { it >= 0 }
    }

    companion object {
        private const val MAGIC = "TALIPDB1"

        /** Reads the format written by [Builder.write] (uncompressed). */
        fun read(input: InputStream): IpDatabase {
            val data = DataInputStream(input.buffered())
            val magic = ByteArray(MAGIC.length).also(data::readFully)
            if (String(magic, Charsets.US_ASCII) != MAGIC) throw IOException("not an IP database")
            val version = data.readUTF()
            val countries = Array(readVarint(data).toInt()) { data.readUTF() }
            val networks = Array(readVarint(data).toInt()) { Network(readVarint(data).toInt(), data.readUTF()) }
            return IpDatabase(version, countries, networks, RangeTable.read(data), RangeTable.read(data), RangeTable.read(data), RangeTable.read(data))
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

        /** Writes the database (uncompressed; the app stores it gzipped). */
        fun write(output: OutputStream) {
            val data = DataOutputStream(output)
            data.write(MAGIC.toByteArray(Charsets.US_ASCII))
            data.writeUTF(version)
            writeVarint(data, countryIds.size.toLong())
            countryIds.keys.forEach(data::writeUTF)
            writeVarint(data, networkIds.size.toLong())
            for (network in networkIds.keys) {
                writeVarint(data, network.asn.toLong())
                data.writeUTF(network.organization)
            }
            for (ranges in listOf(country4, country6, network4, network6)) RangeTable.write(data, ranges)
            data.flush()
        }

        private fun number(address: InetAddress) = BigInteger(1, address.address)
    }

    internal class Range(val start: BigInteger, val end: BigInteger, val value: Int)
}

/**
 * Sorted range starts with values; an address belongs to the last range starting at or
 * below it. Starts are 128-bit numbers kept as two longs (IPv4 in [lo]); value -1 marks a
 * gap between ranges.
 */
internal class RangeTable(private val hi: LongArray, private val lo: LongArray, private val values: IntArray) {

    fun lookup(addressHi: Long, addressLo: Long): Int {
        var low = 0
        var high = hi.size - 1
        var found = -1
        while (low <= high) {
            val mid = (low + high) ushr 1
            if (compare(hi[mid], lo[mid], addressHi, addressLo) <= 0) {
                found = mid
                low = mid + 1
            } else {
                high = mid - 1
            }
        }
        return if (found < 0) -1 else values[found]
    }

    companion object {
        private fun compare(aHi: Long, aLo: Long, bHi: Long, bLo: Long): Int {
            val byHi = java.lang.Long.compareUnsigned(aHi, bHi)
            return if (byHi != 0) byHi else java.lang.Long.compareUnsigned(aLo, bLo)
        }

        private val LONG_MASK = BigInteger.ONE.shiftLeft(64) - BigInteger.ONE
        private val MAX_ADDRESS = BigInteger.ONE.shiftLeft(128) - BigInteger.ONE

        /** Entry count, then per entry: hi delta, lo (both varints), value + 1 (varint). */
        fun write(data: DataOutputStream, ranges: List<IpDatabase.Range>) {
            val sorted = ranges.sortedBy { it.start }
            val starts = ArrayList<Pair<BigInteger, Int>>(sorted.size * 2)
            for ((i, range) in sorted.withIndex()) {
                if (i > 0) {
                    val previousEnd = sorted[i - 1].end
                    require(range.start > previousEnd) { "overlapping ranges at ${range.start}" }
                    // A gap after the previous range: addresses in it are unknown.
                    if (previousEnd + BigInteger.ONE < range.start) starts += (previousEnd + BigInteger.ONE) to -1
                }
                starts += range.start to range.value
            }
            sorted.lastOrNull()?.takeIf { it.end < MAX_ADDRESS }?.let { last -> starts += (last.end + BigInteger.ONE) to -1 }

            writeVarint(data, starts.size.toLong())
            var previousHi = 0L
            for ((start, value) in starts) {
                val hi = start.shiftRight(64).toLong()
                val lo = start.and(LONG_MASK).toLong()
                writeVarint(data, hi - previousHi)
                writeVarint(data, lo)
                writeVarint(data, (value + 1).toLong())
                previousHi = hi
            }
        }

        fun read(data: DataInputStream): RangeTable {
            val count = readVarint(data).toInt()
            val hi = LongArray(count)
            val lo = LongArray(count)
            val values = IntArray(count)
            var previousHi = 0L
            for (i in 0 until count) {
                previousHi += readVarint(data)
                hi[i] = previousHi
                lo[i] = readVarint(data)
                values[i] = readVarint(data).toInt() - 1
            }
            return RangeTable(hi, lo, values)
        }
    }
}

/** Unsigned LEB128. */
internal fun writeVarint(out: DataOutputStream, value: Long) {
    var v = value
    while (v and 0x7fL.inv() != 0L) {
        out.writeByte(((v and 0x7f) or 0x80).toInt())
        v = v ushr 7
    }
    out.writeByte(v.toInt())
}

internal fun readVarint(input: DataInputStream): Long {
    var result = 0L
    var shift = 0
    while (true) {
        val b = input.read()
        if (b < 0) throw EOFException()
        result = result or ((b and 0x7f).toLong() shl shift)
        if (b and 0x80 == 0) return result
        shift += 7
        if (shift > 63) throw IOException("varint too long")
    }
}
