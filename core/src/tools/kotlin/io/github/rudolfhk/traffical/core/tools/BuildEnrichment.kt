package io.github.rudolfhk.traffical.core.tools

import io.github.rudolfhk.traffical.core.enrichment.IpDatabase
import io.github.rudolfhk.traffical.core.enrichment.Json
import io.github.rudolfhk.traffical.core.enrichment.Network
import io.github.rudolfhk.traffical.core.enrichment.TrackerList
import java.io.File
import java.net.InetAddress
import java.util.zip.GZIPOutputStream
import kotlin.system.exitProcess

/**
 * Builds the app's offline enrichment data (app/src/main/assets/enrichment) from the
 * files tools/enrichment/update.sh downloads:
 * - dbip-country-ipv4.csv, dbip-country-ipv6.csv, dbip-asn-ipv4.csv, dbip-asn-ipv6.csv
 *   (DB-IP Lite, CC BY 4.0) -> ip.bin.gz
 * - trackers.json, companies.json (AdGuard companiesdb, CC BY-SA 4.0) -> trackers.tsv.gz
 * - fetched.txt: the download date, part of the version strings.
 *
 * Usage: buildEnrichment <source dir> <output dir>
 */
fun main(args: Array<String>) {
    if (args.size != 2) {
        System.err.println("Usage: buildEnrichment <source dir> <output dir>")
        exitProcess(2)
    }
    val source = File(args[0])
    val output = File(args[1]).apply { mkdirs() }
    val fetched = File(source, "fetched.txt").readText().trim()

    val ips = IpDatabase.Builder("DB-IP Lite, $fetched")
    var countryRanges = 0
    var networkRanges = 0
    for (family in listOf("ipv4", "ipv6")) {
        File(source, "dbip-country-$family.csv").forEachLine { line ->
            val (start, end, country) = csvFields(line)
            ips.addCountry(InetAddress.getByName(start), InetAddress.getByName(end), country)
            countryRanges++
        }
        File(source, "dbip-asn-$family.csv").forEachLine { line ->
            val fields = csvFields(line)
            ips.addNetwork(InetAddress.getByName(fields[0]), InetAddress.getByName(fields[1]), Network(fields[2].toInt(), fields[3]))
            networkRanges++
        }
    }
    GZIPOutputStream(File(output, "ip.bin.gz").outputStream().buffered()).use(ips::write)

    val trackersJson = Json.parse(File(source, "trackers.json").readText())
    val updated = (trackersJson as Map<*, *>)["timeUpdated"]?.toString()?.substringBefore('T') ?: fetched
    val trackers = TrackerList.fromCompaniesDb(trackersJson, Json.parse(File(source, "companies.json").readText()), "AdGuard companiesdb, $updated")
    GZIPOutputStream(File(output, "trackers.tsv.gz").outputStream().buffered()).use(trackers::write)

    println(
        "$countryRanges country ranges, $networkRanges network ranges -> ip.bin.gz " +
            "(${File(output, "ip.bin.gz").length() / 1024} KiB); ${trackers.size} tracker domains -> trackers.tsv.gz " +
            "(${File(output, "trackers.tsv.gz").length() / 1024} KiB)",
    )
}

/** Splits one CSV line; fields may be quoted ("Cloudflare, Inc.") with "" for a quote. */
internal fun csvFields(line: String): List<String> {
    val fields = ArrayList<String>()
    val field = StringBuilder()
    var quoted = false
    var i = 0
    while (i < line.length) {
        val c = line[i]
        when {
            quoted && c == '"' && i + 1 < line.length && line[i + 1] == '"' -> {
                field.append('"')
                i++
            }
            c == '"' -> quoted = !quoted
            c == ',' && !quoted -> {
                fields += field.toString()
                field.setLength(0)
            }
            else -> field.append(c)
        }
        i++
    }
    fields += field.toString()
    return fields
}
