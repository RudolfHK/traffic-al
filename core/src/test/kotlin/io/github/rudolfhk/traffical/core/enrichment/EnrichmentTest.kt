package io.github.rudolfhk.traffical.core.enrichment

import io.github.rudolfhk.traffical.core.analysis.ConnectionFilter
import io.github.rudolfhk.traffical.core.analysis.FlowFlag
import io.github.rudolfhk.traffical.core.analysis.TimeRange
import io.github.rudolfhk.traffical.core.analysis.TrafficTimeline
import io.github.rudolfhk.traffical.core.analysis.dashboard
import io.github.rudolfhk.traffical.core.analysis.flags
import io.github.rudolfhk.traffical.core.capture.FlowInfo
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EnrichmentTest {

    @Test
    fun `json parses objects, arrays, escapes and numbers`() {
        val value = Json.parse("""{"a": [1, -2.5e1, true, false, null], "b": "x\"\\\/\né😀", "c": {}}""")
        val map = value as Map<*, *>
        assertEquals(listOf(1L, -25.0, true, false, null), map["a"])
        assertEquals("x\"\\/\né😀", map["b"])
        assertEquals(emptyMap<String, Any?>(), map["c"])
        assertFailsWith<Json.ParseException> { Json.parse("""{"a": 1""") }
        assertFailsWith<Json.ParseException> { Json.parse("""[1] 2""") }
        assertFailsWith<Json.ParseException> { Json.parse("""{a: 1}""") }
    }

    @Test
    fun `ip ranges with gaps, boundaries and IPv6`() {
        val google = Network(15169, "Google LLC")
        val builder = IpDatabase.Builder("test")
        builder.addCountry(ip("1.0.0.0"), ip("1.0.0.255"), "AU")
        builder.addCountry(ip("8.8.8.0"), ip("8.8.8.255"), "US")
        builder.addCountry(ip("2001:4860::"), ip("2001:4860:ffff:ffff:ffff:ffff:ffff:ffff"), "US")
        builder.addCountry(ip("fd00::"), ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), "ZZ")
        builder.addNetwork(ip("8.8.8.0"), ip("8.8.8.255"), google)
        builder.addNetwork(ip("8.8.9.0"), ip("8.8.9.127"), google)
        builder.addNetwork(ip("2001:4860::"), ip("2001:4860::ffff"), google) // not /64 aligned
        builder.addNetwork(ip("255.255.255.0"), ip("255.255.255.255"), Network(1, "Last"))
        val bytes = ByteArrayOutputStream().also(builder::write).toByteArray()
        val db = IpDatabase.read(ByteArrayInputStream(bytes))

        assertEquals("test", db.version)
        assertEquals("AU", db.country(ip("1.0.0.0")))
        assertEquals("AU", db.country(ip("1.0.0.255")))
        assertNull(db.country(ip("1.0.1.0")), "gap after a range")
        assertNull(db.country(ip("0.255.255.255")), "before the first range")
        assertEquals("US", db.country(ip("8.8.8.8")))
        assertNull(db.country(ip("8.8.9.0")))
        assertEquals(google, db.network(ip("8.8.8.8")))
        assertEquals(google, db.network(ip("8.8.9.127")))
        assertNull(db.network(ip("8.8.9.128")))
        assertEquals("Last", db.network(ip("255.255.255.255"))?.organization)
        assertEquals("US", db.country(ip("2001:4860:4860::8888")))
        assertEquals(google, db.network(ip("2001:4860::8888")))
        assertNull(db.network(ip("2001:4860::1:0")), "past a range that ends inside a /64")
        assertEquals("ZZ", db.country(ip("ffff::1")), "addresses above 2^127 compare unsigned")
        assertNull(db.country(ip("2001:4861::")))
    }

    @Test
    fun `tracker list matches the closest parent domain`() {
        val list = TrackerList(
            "test",
            mapOf(
                "doubleclick.net" to Tracker("DoubleClick", "Google", "advertising"),
                "google.com" to Tracker("Google", "Google", "essential"),
                "analytics.google.com" to Tracker("Google Analytics", "Google", "site_analytics"),
            ),
        )
        assertEquals("DoubleClick", list.match("googleads.g.doubleclick.net")?.name)
        assertEquals("DoubleClick", list.match("DoubleClick.NET.")?.name)
        assertEquals("Google Analytics", list.match("region1.analytics.google.com")?.name)
        assertEquals("Google", list.match("www.google.com")?.name)
        assertNull(list.match("example.net"))
        assertNull(list.match("net"))
        assertTrue(list.match("ad.doubleclick.net")!!.tracking)
        assertFalse(list.match("www.google.com")!!.tracking)
        assertEquals("Site analytics", list.match("analytics.google.com")!!.categoryLabel)

        val copy = TrackerList.read(ByteArrayInputStream(ByteArrayOutputStream().also(list::write).toByteArray()))
        assertEquals("test", copy.version)
        assertEquals(3, copy.size)
        assertEquals(list.match("ad.doubleclick.net"), copy.match("ad.doubleclick.net"))
    }

    @Test
    fun `tracker list from AdGuard companiesdb`() {
        val trackers = Json.parse(
            """{"timeUpdated": "2026-10-26", "categories": {"4": "advertising", "6": "site_analytics"},
               "trackers": {"doubleclick": {"name": "DoubleClick", "categoryId": 4, "companyId": "google"},
                            "matomo": {"name": "Matomo", "categoryId": 6, "companyId": null}},
               "trackerDomains": {"doubleclick.net": "doubleclick", "2mdn.net": "doubleclick", "matomo.cloud": "matomo"}}""",
        )
        val companies = Json.parse("""{"companies": {"google": {"name": "Google", "websiteUrl": "https://google.com"}}}""")
        val list = TrackerList.fromCompaniesDb(trackers, companies, "v")
        assertEquals(Tracker("DoubleClick", "Google", "advertising"), list.match("s0.2mdn.net"))
        assertEquals(Tracker("Matomo", "Matomo", "site_analytics"), list.match("x.matomo.cloud"))
    }

    @Test
    fun `rdap answer gives network, registrant and range`() {
        val info = Rdap.parse(ARIN_8_8_8_8)
        assertEquals("GOGL", info.name)
        assertEquals("NET-8-8-8-0-2", info.handle)
        assertEquals("8.8.8.0 - 8.8.8.255", info.range)
        assertEquals("Google LLC", info.organization)
        assertEquals("whois.arin.net", info.registry)
        assertNull(info.country)

        val ripe = Rdap.parse(RIPE_EXAMPLE)
        assertEquals("DE", ripe.country)
        assertEquals("Example GmbH", ripe.organization, "nested entity without registrant role")
        assertEquals("https://rdap.org/ip/2001:db8:0:0:0:0:0:1", Rdap.url(ip("2001:db8::1")))
    }

    @Test
    fun `trackers raise the tracker flag, are searchable and summarized`() {
        val doubleclick = Tracker("DoubleClick", "Google", "advertising")
        val cdn = Tracker("Akamai", "Akamai", "cdn")
        val tracked = flow(1, uid = 10001, sni = "ad.doubleclick.net")
        val plain = flow(2, uid = 10002, sni = "cdn.example.com")
        assertEquals(setOf(FlowFlag.TRACKER), tracked.flags(doubleclick))
        assertEquals(emptySet(), plain.flags(cdn))

        val destination = Destination("US", Network(15169, "Google LLC"), doubleclick)
        val filter = ConnectionFilter(text = "google as15169 united")
        assertTrue(filter.matches(tracked, "App", null, 0, destination))
        assertFalse(filter.matches(tracked, "App", null, 0, null))
        assertTrue(ConnectionFilter(attentionOnly = true).matches(tracked, "App", null, 0, destination))

        val destinations = mapOf(1L to destination, 2L to Destination(null, null, cdn), 3L to destination)
        val data = dashboard(
            listOf(tracked, plain, flow(3, uid = 10002, sni = "x.doubleclick.net")),
            TrafficTimeline(),
            TimeRange.ALL,
            2_000_000,
        ) { destinations[it.id] }
        assertEquals(2, data.attention)
        val google = data.trackers.single()
        assertEquals("Google", google.company)
        assertEquals(listOf("Advertising"), google.categories)
        assertEquals(2, google.connections)
        assertEquals(2, google.apps)
    }

    private fun ip(text: String) = InetAddress.getByName(text)

    private fun flow(id: Long, uid: Int, sni: String) = FlowInfo(
        id = id, uid = uid, ipVersion = 4, protocol = 6,
        localAddress = ip("10.215.173.1"), localPort = 40000 + id.toInt(),
        remoteAddress = ip("142.250.186.34"), remotePort = 443,
        sni = sni, dnsName = null, bytesOut = 100, bytesIn = 1000, packetsOut = 1, packetsIn = 1,
        firstSeenMicros = 1_000_000, lastSeenMicros = 1_500_000, blocked = false, closed = false,
        encryptedDns = false,
    )

    private companion object {
        // Shortened from ARIN's answer for 8.8.8.8.
        const val ARIN_8_8_8_8 = """{
          "rdapConformance": ["nro_rdap_profile_0", "rdap_level_0", "cidr0", "arin_originas0"],
          "objectClassName": "ip network", "handle": "NET-8-8-8-0-2",
          "startAddress": "8.8.8.0", "endAddress": "8.8.8.255", "ipVersion": "v4",
          "name": "GOGL", "type": "DIRECT ALLOCATION", "parentHandle": "NET-8-0-0-0-0",
          "port43": "whois.arin.net",
          "entities": [{
            "objectClassName": "entity", "handle": "GOGL", "roles": ["registrant"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"],
              ["adr", {"label": "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States"}, "text", ["", "", "", "", "", "", ""]],
              ["kind", {}, "text", "org"]]],
            "entities": [{"objectClassName": "entity", "handle": "ABUSE5250-ARIN", "roles": ["abuse"],
              "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Abuse"]]]}]
          }]
        }"""

        const val RIPE_EXAMPLE = """{
          "objectClassName": "ip network", "handle": "2001:db8::/32", "name": "EXAMPLE-NET",
          "startAddress": "2001:db8::/32", "endAddress": "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
          "country": "DE", "port43": "whois.ripe.net",
          "entities": [{"objectClassName": "entity", "handle": "EX1-RIPE", "roles": ["administrative"],
            "entities": [{"objectClassName": "entity", "handle": "ORG-EX1-RIPE", "roles": ["owner"],
              "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example GmbH"]]]}]}]
        }"""
    }
}
