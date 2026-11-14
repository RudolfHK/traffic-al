package io.github.rudolfhk.traffical.core.analysis

/** A kind of personal or sensitive data a request may carry. */
enum class ExposureType(val label: String) {
    EMAIL("Email address"),
    PHONE("Phone number"),
    LOCATION("Precise location"),
    DEVICE_ID("Device identifier"),
    ADVERTISING_ID("Advertising ID"),
    AUTH("Credential / token"),
    COOKIE("Cookie"),
    CARD("Payment card number"),
}

/**
 * One piece of sensitive data found in a decrypted message. [where] says where it was (e.g.
 * "query:email", "header:Cookie", "body"); [sample] is a short, truncated proof — never the
 * full secret.
 */
data class Exposure(val type: ExposureType, val where: String, val sample: String)

/**
 * Deterministic scan of a decrypted [HttpMessage] for personal/sensitive data an app is
 * sending, so a security audit can answer "what of mine is going out, and to whom" (phase
 * 12). It is rule-based (field names + value patterns), not heuristic, so the same input
 * always gives the same findings and nothing is inferred or sent anywhere.
 *
 * Findings are evidence, not accusations: an app sending your email or an auth token to its
 * own backend is normal. The value of the audit is seeing *which* app sends *what* to *which*
 * destination — the destination is added by [DataFlowAudit], not here.
 */
object SensitiveData {
    private val EMAIL = Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")
    private val JWT = Regex("eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]{4,}")
    private val E164 = Regex("\\+[1-9]\\d{9,14}")
    private val DECIMAL = Regex("-?\\d{1,3}\\.\\d{3,}")
    private val CARD_CANDIDATE = Regex("(?:\\d[ -]?){13,19}")

    private val AD_KEYS = setOf("adid", "gaid", "idfa", "idfv", "aaid", "ad_id", "advertising_id", "advertisingid", "advertising-id")
    private val ID_KEYS = setOf("android_id", "androidid", "device_id", "deviceid", "imei", "meid", "serial", "serialno", "udid", "installation_id", "install_id", "hardware_id")
    private val LOC_KEYS = setOf("lat", "latitude", "lon", "lng", "long", "longitude", "geo", "gps", "coords", "coordinates")
    private val TOKEN_KEYS = setOf("token", "access_token", "accesstoken", "refresh_token", "id_token", "auth", "apikey", "api_key", "password", "passwd", "pwd", "secret", "session", "sessionid", "session_id", "sid")
    private val PHONE_KEYS = setOf("phone", "phonenumber", "phone_number", "msisdn", "mobile", "tel")

    private const val MAX_EXPOSURES = 64

    /** Every distinct exposure in [message] (deduplicated by type and location). */
    fun scan(message: HttpMessage): List<Exposure> {
        val out = ArrayList<Exposure>()

        message.path?.substringAfter('?', "")?.takeIf { it.isNotEmpty() }?.let { query ->
            scanParams(query, "query", out)
        }
        for (h in message.headers) scanHeader(h, out)
        if (message.bodyPreview.isNotEmpty()) {
            val ct = message.contentType?.lowercase().orEmpty()
            when {
                ct.contains("x-www-form-urlencoded") -> scanParams(message.bodyPreview, "body", out)
                ct.contains("json") -> { scanJson(message.bodyPreview, out); scanText(message.bodyPreview, "body", out) }
                else -> scanText(message.bodyPreview, "body", out)
            }
        }
        return dedup(out)
    }

    private fun scanParams(params: String, where: String, out: MutableList<Exposure>) {
        for (pair in params.split('&')) {
            if (pair.isEmpty()) continue
            val key = pair.substringBefore('=')
            val value = urlDecode(pair.substringAfter('=', ""))
            classify(key, value, where, out)
        }
    }

    private fun scanJson(body: String, out: MutableList<Exposure>) {
        for (m in Regex("\"([A-Za-z0-9_]+)\"\\s*:\\s*\"([^\"]*)\"").findAll(body)) {
            classify(m.groupValues[1], m.groupValues[2], "body", out)
        }
    }

    private fun scanHeader(h: HttpHeader, out: MutableList<Exposure>) {
        when (h.name.lowercase()) {
            "authorization", "proxy-authorization" -> {
                val scheme = h.value.substringBefore(' ', h.value).take(12)
                out += Exposure(ExposureType.AUTH, "header:${h.name}", "$scheme …")
            }
            "cookie" -> out += Exposure(ExposureType.COOKIE, "header:Cookie", cookieNames(h.value))
            "set-cookie" -> out += Exposure(ExposureType.COOKIE, "header:Set-Cookie", h.value.substringBefore('=').take(32))
            else -> classify(h.name, h.value, "header", out)
        }
    }

    /** Key-name rules first, then value-pattern rules, for one key/value pair. */
    private fun classify(key: String, value: String, whereBase: String, out: MutableList<Exposure>) {
        if (value.isEmpty()) return
        val k = key.lowercase()
        val where = "$whereBase:$key"
        when {
            k in AD_KEYS -> out += Exposure(ExposureType.ADVERTISING_ID, where, sample(value))
            k in ID_KEYS -> out += Exposure(ExposureType.DEVICE_ID, where, sample(value))
            k in TOKEN_KEYS -> out += Exposure(ExposureType.AUTH, where, sample(value))
            k in PHONE_KEYS -> out += Exposure(ExposureType.PHONE, where, sample(value))
            k in LOC_KEYS && DECIMAL.matches(value.trim()) -> out += Exposure(ExposureType.LOCATION, where, value.trim())
        }
        valuePatterns(value, where, out)
    }

    /** Value-only patterns that hold regardless of the field name. */
    private fun valuePatterns(value: String, where: String, out: MutableList<Exposure>) {
        EMAIL.find(value)?.let { out += Exposure(ExposureType.EMAIL, where, sample(it.value)) }
        JWT.find(value)?.let { out += Exposure(ExposureType.AUTH, where, it.value.take(10) + "…") }
        E164.find(value)?.let { out += Exposure(ExposureType.PHONE, where, it.value) }
        for (m in CARD_CANDIDATE.findAll(value)) {
            val digits = m.value.filter { it.isDigit() }
            if (luhn(digits)) { out += Exposure(ExposureType.CARD, where, mask(digits)); break }
        }
    }

    private fun scanText(text: String, where: String, out: MutableList<Exposure>) {
        valuePatterns(text, where, out)
    }

    private fun dedup(list: List<Exposure>): List<Exposure> {
        val seen = LinkedHashMap<Pair<ExposureType, String>, Exposure>()
        for (e in list) seen.putIfAbsent(e.type to e.where, e)
        return seen.values.take(MAX_EXPOSURES)
    }

    private fun cookieNames(cookie: String): String {
        val names = cookie.split(';').mapNotNull { it.substringBefore('=').trim().ifEmpty { null } }
        return names.take(6).joinToString(", ") + if (names.size > 6) ", …" else ""
    }

    private fun sample(value: String): String {
        val t = value.trim()
        return if (t.length <= 8) t else t.take(6) + "…(${t.length})"
    }

    private fun mask(digits: String): String =
        if (digits.length <= 4) "•".repeat(digits.length) else "•••• ${digits.takeLast(4)}"

    private fun luhn(digits: String): Boolean {
        if (digits.length !in 13..19) return false
        var sum = 0
        var alt = false
        for (i in digits.indices.reversed()) {
            var d = digits[i] - '0'
            if (alt) { d *= 2; if (d > 9) d -= 9 }
            sum += d
            alt = !alt
        }
        return sum % 10 == 0
    }

    private fun urlDecode(s: String): String = try {
        java.net.URLDecoder.decode(s, "UTF-8")
    } catch (_: Exception) {
        s
    }
}
