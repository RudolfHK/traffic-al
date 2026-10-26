package io.github.rudolfhk.traffical.core.analysis

import java.util.Locale

/** Human-readable numbers for the UI (SI units, like Android's Formatter). */
object Format {

    private val UNITS = listOf("kB", "MB", "GB", "TB")

    fun bytes(bytes: Long, locale: Locale = Locale.getDefault()): String {
        if (bytes < 1000) return "$bytes B"
        var value = bytes / 1000.0
        var unit = 0
        while (value >= 999.5 && unit < UNITS.lastIndex) {
            value /= 1000
            unit++
        }
        val number = if (value < 9.95) String.format(locale, "%.1f", value) else String.format(locale, "%.0f", value)
        return "$number ${UNITS[unit]}"
    }

    fun rate(bytesPerSecond: Long, locale: Locale = Locale.getDefault()): String = bytes(bytesPerSecond, locale) + "/s"

    fun duration(micros: Long, locale: Locale = Locale.getDefault()): String {
        val millis = micros / 1000
        return when {
            millis < 1 -> "<1 ms"
            millis < 1000 -> "$millis ms"
            millis < 60_000 -> String.format(locale, "%.1f s", millis / 1000.0)
            millis < 3_600_000 -> String.format(locale, "%d min %02d s", millis / 60_000, millis / 1000 % 60)
            else -> String.format(locale, "%d h %02d min", millis / 3_600_000, millis / 60_000 % 60)
        }
    }
}

/** Classic hex dump: offset, 16 bytes in hex, printable ASCII. */
object HexDump {
    fun lines(data: ByteArray, offset: Int = 0, length: Int = data.size - offset, width: Int = 16): List<String> {
        val lines = ArrayList<String>((length + width - 1) / width)
        var lineStart = 0
        while (lineStart < length) {
            val count = minOf(width, length - lineStart)
            val line = StringBuilder(width * 4 + 8)
            line.append(String.format(Locale.ROOT, "%04x  ", lineStart))
            for (i in 0 until width) {
                if (i < count) {
                    line.append(String.format(Locale.ROOT, "%02x ", data[offset + lineStart + i].toInt() and 0xff))
                } else {
                    line.append("   ")
                }
                if (i == width / 2 - 1) line.append(' ')
            }
            line.append(' ')
            for (i in 0 until count) {
                val c = data[offset + lineStart + i].toInt() and 0xff
                line.append(if (c in 0x20..0x7e) c.toChar() else '.')
            }
            lines += line.toString().trimEnd()
            lineStart += count
        }
        return lines
    }
}
