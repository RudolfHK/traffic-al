package io.github.rudolfhk.traffical.core.security

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * A PIN stored as salted PBKDF2-HMAC-SHA256. The app keeps this record encrypted with a
 * key in the Android Keystore, so the short PIN can't be brute-forced from a copy of the
 * app's files.
 */
class PinRecord(val salt: ByteArray, val iterations: Int, val hash: ByteArray) {

    fun matches(pin: CharArray): Boolean = MessageDigest.isEqual(hash(pin, salt, iterations), hash)

    fun encode(): ByteArray = ByteBuffer.allocate(8 + salt.size + hash.size)
        .putInt(iterations)
        .putInt(salt.size)
        .put(salt)
        .put(hash)
        .array()

    companion object {
        const val MIN_LENGTH = 4
        const val MAX_LENGTH = 12
        private const val ITERATIONS = 100_000
        private const val SALT_BYTES = 16
        private const val HASH_BITS = 256

        fun isValid(pin: CharSequence): Boolean = pin.length in MIN_LENGTH..MAX_LENGTH && pin.all { it in '0'..'9' }

        fun create(pin: CharArray, random: SecureRandom = SecureRandom()): PinRecord {
            require(isValid(String(pin))) { "PIN must be $MIN_LENGTH to $MAX_LENGTH digits" }
            val salt = ByteArray(SALT_BYTES).also(random::nextBytes)
            return PinRecord(salt, ITERATIONS, hash(pin, salt, ITERATIONS))
        }

        fun decode(bytes: ByteArray): PinRecord {
            val buffer = ByteBuffer.wrap(bytes)
            val iterations = buffer.getInt()
            val salt = ByteArray(buffer.getInt()).also { buffer.get(it) }
            val hash = ByteArray(buffer.remaining()).also { buffer.get(it) }
            return PinRecord(salt, iterations, hash)
        }

        private fun hash(pin: CharArray, salt: ByteArray, iterations: Int): ByteArray {
            val spec = PBEKeySpec(pin, salt, iterations, HASH_BITS)
            try {
                return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
            } finally {
                spec.clearPassword()
            }
        }
    }
}

/**
 * When the app lock asks for the PIN again and how long it refuses after wrong ones.
 * Times are milliseconds from [clock].
 */
class LockRules(
    private val clock: () -> Long,
    /** Leaving the app for less than this keeps it unlocked (e.g. for the export file picker). */
    private val graceMillis: Long = 60_000,
) {
    private var backgroundSince: Long? = null
    private var failures = 0
    private var lockedOutUntil = 0L

    fun onBackground() {
        backgroundSince = clock()
    }

    /** True if the app was away long enough to lock again. */
    fun onForeground(): Boolean {
        val since = backgroundSince ?: return false
        backgroundSince = null
        return clock() - since >= graceMillis
    }

    /** Milliseconds until the next PIN may be tried; 0 if now. */
    fun waitMillis(): Long = maxOf(0L, lockedOutUntil - clock())

    fun onWrongPin() {
        failures++
        if (failures >= FREE_ATTEMPTS) {
            val doublings = minOf(failures - FREE_ATTEMPTS, MAX_DOUBLINGS)
            lockedOutUntil = clock() + (FIRST_LOCKOUT_MILLIS shl doublings)
        }
    }

    fun onUnlocked() {
        failures = 0
        lockedOutUntil = 0
    }

    private companion object {
        const val FREE_ATTEMPTS = 5
        const val FIRST_LOCKOUT_MILLIS = 30_000L
        const val MAX_DOUBLINGS = 5 // up to 16 minutes
    }
}
