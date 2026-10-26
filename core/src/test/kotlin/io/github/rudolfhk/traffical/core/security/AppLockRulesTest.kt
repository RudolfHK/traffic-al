package io.github.rudolfhk.traffical.core.security

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AppLockRulesTest {

    @Test
    fun `PIN record matches only its PIN and survives encoding`() {
        val record = PinRecord.create("2468".toCharArray())
        val decoded = PinRecord.decode(record.encode())
        assertTrue(decoded.matches("2468".toCharArray()))
        assertFalse(decoded.matches("2469".toCharArray()))
        assertFalse(decoded.matches("24680".toCharArray()))
        // Same PIN, different salt: different hash.
        assertFalse(PinRecord.create("2468".toCharArray()).hash.contentEquals(record.hash))
    }

    @Test
    fun `only 4 to 12 digits are valid`() {
        assertTrue(PinRecord.isValid("0000"))
        assertTrue(PinRecord.isValid("123456789012"))
        assertFalse(PinRecord.isValid("123"))
        assertFalse(PinRecord.isValid("1234567890123"))
        assertFalse(PinRecord.isValid("12a4"))
    }

    @Test
    fun `locks again only after the grace period`() {
        var now = 0L
        val rules = LockRules({ now }, graceMillis = 60_000)
        assertFalse(rules.onForeground(), "never in the background")
        rules.onBackground()
        now += 59_000
        assertFalse(rules.onForeground())
        rules.onBackground()
        now += 60_000
        assertTrue(rules.onForeground())
    }

    @Test
    fun `wrong PINs lead to growing waits`() {
        var now = 0L
        val rules = LockRules({ now })
        repeat(4) { rules.onWrongPin() }
        assertEquals(0, rules.waitMillis())
        rules.onWrongPin()
        assertEquals(30_000, rules.waitMillis())
        now += 30_000
        assertEquals(0, rules.waitMillis())
        rules.onWrongPin()
        assertEquals(60_000, rules.waitMillis())
        repeat(20) { rules.onWrongPin() }
        assertEquals(30_000L shl 5, rules.waitMillis())
        rules.onUnlocked()
        assertEquals(0, rules.waitMillis())
    }
}
