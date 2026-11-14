package io.github.rudolfhk.traffical.core.analysis

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SensitiveDataTest {

    @Test
    fun `finds the data a tracking request leaks`() {
        val message = HttpMessage(
            kind = HttpKind.REQUEST,
            method = "POST",
            authority = "collect.example.test",
            path = "/track?email=user%40example.test&adid=1234-5678-ABCD-EF90",
            headers = listOf(
                HttpHeader("Authorization", "Bearer secrettoken123456"),
                HttpHeader("Cookie", "sid=abc123; theme=dark"),
            ),
            contentType = "application/x-www-form-urlencoded",
            bodyPreview = "lat=52.5200&lon=13.4050&card=4111111111111111",
        )
        val types = SensitiveData.scan(message).map { it.type }.toSet()
        assertTrue(ExposureType.EMAIL in types, "email")
        assertTrue(ExposureType.ADVERTISING_ID in types, "advertising id")
        assertTrue(ExposureType.AUTH in types, "authorization")
        assertTrue(ExposureType.COOKIE in types, "cookie")
        assertTrue(ExposureType.LOCATION in types, "location")
        assertTrue(ExposureType.CARD in types, "card")
    }

    @Test
    fun `flags a JWT in a custom header`() {
        val message = HttpMessage(
            kind = HttpKind.REQUEST,
            method = "GET",
            path = "/me",
            headers = listOf(HttpHeader("X-Auth", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcDEF123456")),
        )
        val found = SensitiveData.scan(message)
        assertTrue(found.any { it.type == ExposureType.AUTH })
    }

    @Test
    fun `a benign request has no exposures`() {
        val message = HttpMessage(
            kind = HttpKind.REQUEST,
            method = "GET",
            authority = "example.test",
            path = "/index.html",
            headers = listOf(HttpHeader("Accept", "text/html"), HttpHeader("User-Agent", "App/1.0")),
        )
        assertEquals(emptyList(), SensitiveData.scan(message))
    }

    @Test
    fun `the card sample does not reveal the full number`() {
        val message = HttpMessage(
            kind = HttpKind.REQUEST,
            path = "/pay?pan=4111111111111111",
        )
        val card = SensitiveData.scan(message).first { it.type == ExposureType.CARD }
        assertTrue(card.sample.endsWith("1111"))
        assertFalse(card.sample.contains("4111111111111111"))
    }

    private fun assertFalse(condition: Boolean) = assertTrue(!condition)
}
