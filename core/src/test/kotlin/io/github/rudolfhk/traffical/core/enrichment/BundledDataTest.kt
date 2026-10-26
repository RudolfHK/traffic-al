package io.github.rudolfhk.traffical.core.enrichment

import java.io.File
import java.net.InetAddress
import java.util.zip.GZIPInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Checks the data bundled with the app (tools/enrichment/update.sh) on well-known addresses. */
class BundledDataTest {
    private val assets = File("../app/src/main/assets/enrichment")

    @Test
    fun `ip database knows big networks`() {
        val started = System.nanoTime()
        val db = GZIPInputStream(File(assets, "ip.bin.gz").inputStream()).use { IpDatabase.read(it) }
        println("loaded ${db.version} in ${(System.nanoTime() - started) / 1_000_000} ms")
        assertTrue(db.version.startsWith("DB-IP Lite"))

        fun network(ip: String) = db.network(InetAddress.getByName(ip))
        assertEquals(Network(15169, "Google LLC"), network("8.8.8.8"))
        assertEquals("US", db.country(InetAddress.getByName("8.8.8.8")))
        assertEquals(15169, network("2001:4860:4860::8888")?.asn)
        assertEquals(13335, network("1.1.1.1")?.asn)
        assertEquals(13335, network("2606:4700:4700::1111")?.asn)
        assertEquals(19281, network("9.9.9.9")?.asn)
        assertEquals("DE", db.country(InetAddress.getByName("193.99.144.85"))) // heise.de
    }

    @Test
    fun `tracker list knows common trackers`() {
        val trackers = GZIPInputStream(File(assets, "trackers.tsv.gz").inputStream()).use { TrackerList.read(it) }
        assertTrue(trackers.version.startsWith("AdGuard companiesdb"))
        assertTrue(trackers.size > 1000)
        val doubleclick = trackers.match("googleads.g.doubleclick.net")!!
        assertEquals("Google", doubleclick.company)
        assertTrue(doubleclick.tracking)
        assertEquals("Google", trackers.match("app-measurement.com")?.company)
        assertEquals("Meta Platforms, Inc.", trackers.match("graph.facebook.com")?.company)
    }
}
