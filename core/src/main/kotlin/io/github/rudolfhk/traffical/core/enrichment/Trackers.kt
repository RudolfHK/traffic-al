package io.github.rudolfhk.traffical.core.enrichment

import java.io.BufferedReader
import java.io.InputStream
import java.io.OutputStream
import java.io.Writer

/**
 * A known tracker or service domain (AdGuard companiesdb, based on WhoTracks.me), e.g.
 * "Google Analytics" by "Google", category "site_analytics".
 */
data class Tracker(val name: String, val company: String, val category: String) {
    /** Collects data about people (advertising, analytics, telemetry) rather than serving content. */
    val tracking: Boolean get() = category in TRACKING_CATEGORIES

    /** "site_analytics" -> "Site analytics". */
    val categoryLabel: String get() = categoryLabel(category)

    companion object {
        val TRACKING_CATEGORIES = setOf("advertising", "pornvertising", "site_analytics", "mobile_analytics", "telemetry")

        private val LABELS = mapOf(
            "cdn" to "CDN",
            "misc" to "Other",
            "pornvertising" to "Adult advertising",
            "audio_video_player" to "Audio/video player",
        )

        fun categoryLabel(category: String): String =
            LABELS[category] ?: category.replace('_', ' ').replaceFirstChar { it.uppercaseChar() }
    }
}

/** Tracker domains; a host matches its own entry or the closest parent domain's. */
class TrackerList(val version: String, private val byDomain: Map<String, Tracker>) {

    val size: Int get() = byDomain.size

    fun match(host: String): Tracker? {
        var name = host.lowercase().trimEnd('.')
        while (true) {
            byDomain[name]?.let { return it }
            val dot = name.indexOf('.')
            // Stop before the top-level domain: "com" alone is never a tracker.
            if (dot < 0 || name.indexOf('.', dot + 1) < 0) return null
            name = name.substring(dot + 1)
        }
    }

    /** Writes "# version", then one "domain<TAB>name<TAB>company<TAB>category" line per domain. */
    fun write(output: OutputStream) {
        val writer: Writer = output.bufferedWriter(Charsets.UTF_8)
        writer.write("# $version\n")
        for ((domain, tracker) in byDomain.toSortedMap()) {
            writer.write(listOf(domain, tracker.name, tracker.company, tracker.category).joinToString("\t") { it.replace('\t', ' ') })
            writer.write("\n")
        }
        writer.flush()
    }

    companion object {
        fun read(input: InputStream): TrackerList {
            val reader: BufferedReader = input.bufferedReader(Charsets.UTF_8)
            var version = ""
            val trackers = HashMap<String, Tracker>()
            reader.forEachLine { line ->
                when {
                    line.startsWith("# ") -> if (version.isEmpty()) version = line.substring(2)
                    line.isBlank() -> Unit
                    else -> {
                        val fields = line.split('\t')
                        if (fields.size == 4) trackers[fields[0]] = Tracker(fields[1], fields[2], fields[3])
                    }
                }
            }
            return TrackerList(version, trackers)
        }

        /**
         * Builds the list from AdGuard companiesdb's dist/trackers.json and
         * dist/companies.json (parsed with [Json]).
         */
        fun fromCompaniesDb(trackersJson: Any?, companiesJson: Any?, version: String): TrackerList {
            val categories = trackersJson.obj("categories").orEmpty()
            val trackers = trackersJson.obj("trackers").orEmpty()
            val companies = companiesJson.obj("companies").orEmpty()
            val byDomain = HashMap<String, Tracker>()
            for ((domain, trackerId) in trackersJson.obj("trackerDomains").orEmpty()) {
                val info = trackers[trackerId] as? Map<*, *> ?: continue
                val name = info["name"] as? String ?: continue
                val companyId = info["companyId"] as? String
                val company = (companies[companyId] as? Map<*, *>)?.get("name") as? String ?: name
                val category = categories[info["categoryId"]?.toString()] as? String ?: "unknown"
                byDomain[(domain as String).lowercase()] = Tracker(name, company, category)
            }
            return TrackerList(version, byDomain)
        }
    }
}
