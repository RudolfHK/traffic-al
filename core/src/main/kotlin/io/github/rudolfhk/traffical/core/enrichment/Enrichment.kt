package io.github.rudolfhk.traffical.core.enrichment

import io.github.rudolfhk.traffical.core.capture.FlowInfo
import java.net.InetAddress
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/** What is known offline about where a connection goes. */
data class Destination(
    /** ISO 3166 country code of the server's IP address. */
    val country: String?,
    val network: Network?,
    /** The tracker or service the server name belongs to. */
    val tracker: Tracker?,
) {
    /** Words a connection search should find, e.g. "Google LLC", "AS15169", "US", "Germany". */
    val searchTerms: List<String>
        get() = listOfNotNull(
            country,
            country?.let(::countryName),
            network?.organization,
            network?.let { "AS${it.asn}" },
            tracker?.name,
            tracker?.company,
            tracker?.categoryLabel,
        )
}

private val countryNames = ConcurrentHashMap<String, String>()

/** "DE" -> "Germany". Cached: searching the connection list asks for it per connection. */
fun countryName(code: String): String =
    countryNames.getOrPut(code) { Locale("", code).getDisplayCountry(Locale.ENGLISH).ifEmpty { code } }

/** The bundled offline data; either part may be missing. */
class Enrichment(val ips: IpDatabase?, val trackers: TrackerList?) {

    fun destination(flow: FlowInfo): Destination = destination(flow.remoteAddress, flow.domain)

    fun destination(address: InetAddress, host: String?): Destination = Destination(
        country = ips?.country(address),
        network = ips?.network(address),
        tracker = host?.let { trackers?.match(it) },
    )
}

/** The registration of an IP address range, from an RDAP answer (RFC 9083). */
data class RdapInfo(
    /** Network name, e.g. "GOGL". */
    val name: String?,
    val handle: String?,
    val country: String?,
    /** "8.8.8.0 - 8.8.8.255" */
    val range: String?,
    /** The registrant's (or another entity's) name, e.g. "Google LLC". */
    val organization: String?,
    /** The registry that answered, from the port43 WHOIS host, e.g. "whois.arin.net". */
    val registry: String?,
)

object Rdap {
    /** Query URL; rdap.org redirects to the regional registry responsible for [address]. */
    fun url(address: InetAddress): String = "https://rdap.org/ip/${address.hostAddress?.substringBefore('%')}"

    fun parse(json: String): RdapInfo {
        val root = Json.parse(json) as? Map<*, *> ?: throw Json.ParseException("not an RDAP object")
        val start = root.str("startAddress")
        val end = root.str("endAddress")
        return RdapInfo(
            name = root.str("name"),
            handle = root.str("handle"),
            country = root.str("country"),
            range = if (start != null && end != null) "$start - $end" else null,
            organization = organizationOf(root),
            registry = root.str("port43"),
        )
    }

    /** Prefers the registrant, then any entity with a vCard name, searching nested entities too. */
    private fun organizationOf(root: Map<*, *>): String? {
        val entities = ArrayList<Map<*, *>>()
        fun collect(node: Any?) {
            for (entity in node.list("entities")) {
                if (entity is Map<*, *>) {
                    entities += entity
                    collect(entity)
                }
            }
        }
        collect(root)
        val named = entities.mapNotNull { entity -> vcardName(entity)?.let { entity to it } }
        val registrant = named.firstOrNull { (entity, _) -> "registrant" in entity.list("roles") }
        return (registrant ?: named.firstOrNull())?.second
    }

    /** "fn" of a jCard: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"], ...]] */
    private fun vcardName(entity: Map<*, *>): String? {
        val vcard = entity["vcardArray"] as? List<*> ?: return null
        val properties = vcard.getOrNull(1) as? List<*> ?: return null
        for (property in properties) {
            val fields = property as? List<*> ?: continue
            if (fields.firstOrNull() == "fn") return (fields.getOrNull(3) as? String)?.takeIf { it.isNotBlank() }
        }
        return null
    }
}
