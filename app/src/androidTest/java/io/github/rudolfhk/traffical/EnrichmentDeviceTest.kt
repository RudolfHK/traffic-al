package io.github.rudolfhk.traffical

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.rudolfhk.traffical.enrichment.EnrichmentStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress

/** The bundled offline data loads from the APK's assets and answers lookups on Android. */
@RunWith(AndroidJUnit4::class)
class EnrichmentDeviceTest {

    @Test
    fun bundledDataLoadsAndAnswers() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        EnrichmentStore.load(context)
        val enrichment = runBlocking { withTimeout(60_000) { EnrichmentStore.enrichment.first { it != null } } }!!
        assertNotNull("IP database: ${EnrichmentStore.errors.value}", enrichment.ips)
        assertNotNull("tracker list: ${EnrichmentStore.errors.value}", enrichment.trackers)
        val google = enrichment.destination(InetAddress.getByName("8.8.8.8"), "googleads.g.doubleclick.net")
        assertEquals(15169, google.network?.asn)
        assertEquals("US", google.country)
        assertEquals("Google", google.tracker?.company)
        assertTrue(google.tracker!!.tracking)
        assertNotNull(enrichment.destination(InetAddress.getByName("2606:4700:4700::1111"), null).network)
    }
}
