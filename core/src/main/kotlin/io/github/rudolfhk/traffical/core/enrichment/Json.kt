package io.github.rudolfhk.traffical.core.enrichment

/**
 * A small JSON parser for the few documents the app reads (RDAP answers, tracker data):
 * objects become `Map<String, Any?>`, arrays `List<Any?>`, numbers `Long` or `Double`.
 */
object Json {
    class ParseException(message: String) : IllegalArgumentException(message)

    fun parse(text: String): Any? {
        val parser = Parser(text)
        val value = parser.value()
        parser.skipWhitespace()
        if (!parser.atEnd()) throw parser.error("trailing characters")
        return value
    }

    private class Parser(private val text: String) {
        private var pos = 0

        fun atEnd() = pos >= text.length

        fun error(message: String) = ParseException("$message at $pos")

        fun skipWhitespace() {
            while (pos < text.length && text[pos].isWhitespace()) pos++
        }

        fun value(): Any? {
            skipWhitespace()
            if (atEnd()) throw error("unexpected end")
            return when (val c = text[pos]) {
                '{' -> obj()
                '[' -> array()
                '"' -> string()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c in '0'..'9') number() else throw error("unexpected '$c'")
            }
        }

        private fun obj(): Map<String, Any?> {
            pos++ // {
            val result = LinkedHashMap<String, Any?>()
            skipWhitespace()
            if (peek('}')) return result
            while (true) {
                skipWhitespace()
                if (atEnd() || text[pos] != '"') throw error("expected a key")
                val key = string()
                skipWhitespace()
                expect(':')
                result[key] = value()
                skipWhitespace()
                if (peek('}')) return result
                expect(',')
            }
        }

        private fun array(): List<Any?> {
            pos++ // [
            val result = ArrayList<Any?>()
            skipWhitespace()
            if (peek(']')) return result
            while (true) {
                result += value()
                skipWhitespace()
                if (peek(']')) return result
                expect(',')
            }
        }

        private fun string(): String {
            pos++ // "
            val out = StringBuilder()
            while (true) {
                if (atEnd()) throw error("unterminated string")
                when (val c = text[pos++]) {
                    '"' -> return out.toString()
                    '\\' -> {
                        if (atEnd()) throw error("unterminated escape")
                        when (val e = text[pos++]) {
                            '"', '\\', '/' -> out.append(e)
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000c')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'u' -> {
                                if (pos + 4 > text.length) throw error("short unicode escape")
                                out.append(text.substring(pos, pos + 4).toIntOrNull(16)?.toChar() ?: throw error("bad unicode escape"))
                                pos += 4
                            }
                            else -> throw error("bad escape '\\$e'")
                        }
                    }
                    else -> out.append(c)
                }
            }
        }

        private fun number(): Any {
            val start = pos
            if (text[pos] == '-') pos++
            while (pos < text.length && (text[pos].isDigit() || text[pos] in ".eE+-")) pos++
            val token = text.substring(start, pos)
            return token.toLongOrNull() ?: token.toDoubleOrNull() ?: throw error("bad number '$token'")
        }

        private fun literal(word: String, value: Any?): Any? {
            if (!text.startsWith(word, pos)) throw error("expected $word")
            pos += word.length
            return value
        }

        private fun peek(c: Char): Boolean {
            if (pos < text.length && text[pos] == c) {
                pos++
                return true
            }
            return false
        }

        private fun expect(c: Char) {
            if (!peek(c)) throw error("expected '$c'")
        }
    }
}

/** Convenience accessors for parsed JSON. */
internal fun Any?.obj(key: String): Map<*, *>? = (this as? Map<*, *>)?.get(key) as? Map<*, *>
internal fun Any?.list(key: String): List<*> = ((this as? Map<*, *>)?.get(key) as? List<*>).orEmpty()
internal fun Any?.str(key: String): String? = (this as? Map<*, *>)?.get(key) as? String
