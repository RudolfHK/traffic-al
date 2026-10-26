package io.github.rudolfhk.traffical.security

import android.content.Context
import android.content.SharedPreferences
import android.os.SystemClock
import android.util.Log
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import io.github.rudolfhk.traffical.core.security.LockRules
import io.github.rudolfhk.traffical.core.security.PinRecord
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.security.GeneralSecurityException

data class LockState(
    /** A PIN is set: the app asks for it at start and after a minute in the background. */
    val enabled: Boolean = false,
    val locked: Boolean = false,
    /** Fingerprint (or another biometric) may unlock instead of the PIN. */
    val biometric: Boolean = false,
)

/**
 * The app lock: protects the app's screens with a PIN (stored as a salted PBKDF2 hash,
 * itself encrypted with a Keystore key) and optionally the fingerprint. The capture keeps
 * running while the app is locked.
 */
object AppLock {
    private const val PREFS = "app_lock"
    private const val BIOMETRIC = "biometric"
    private const val PIN_SECRET = "pin"

    private lateinit var prefs: SharedPreferences
    private val rules = LockRules(SystemClock::elapsedRealtime)
    private val _state = MutableStateFlow(LockState())
    val state: StateFlow<LockState> = _state.asStateFlow()

    sealed interface Attempt {
        data object Unlocked : Attempt
        data object WrongPin : Attempt

        /** Too many wrong PINs: wait before the next try. */
        data class Wait(val millis: Long) : Attempt
    }

    fun init(context: Context) {
        prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val enabled = Keys.hasSecret(PIN_SECRET)
        _state.value = LockState(enabled = enabled, locked = enabled, biometric = enabled && prefs.getBoolean(BIOMETRIC, false))
        ProcessLifecycleOwner.get().lifecycle.addObserver(
            object : DefaultLifecycleObserver {
                override fun onStop(owner: LifecycleOwner) = rules.onBackground()
                override fun onStart(owner: LifecycleOwner) {
                    if (rules.onForeground() && _state.value.enabled) _state.update { it.copy(locked = true) }
                }
            },
        )
    }

    /** Sets or changes the PIN and turns the lock on. Slow (key derivation): not on the main thread. */
    fun setPin(pin: CharArray) {
        Keys.storeSecret(PIN_SECRET, PinRecord.create(pin).encode())
        _state.update { it.copy(enabled = true, locked = false) }
    }

    fun disable() {
        Keys.storeSecret(PIN_SECRET, null)
        prefs.edit().putBoolean(BIOMETRIC, false).apply()
        _state.value = LockState()
    }

    fun setBiometric(enabled: Boolean) {
        prefs.edit().putBoolean(BIOMETRIC, enabled).apply()
        _state.update { it.copy(biometric = it.enabled && enabled) }
    }

    /** Checks [pin]. Slow (key derivation): not on the main thread. */
    fun unlock(pin: CharArray): Attempt {
        rules.waitMillis().takeIf { it > 0 }?.let { return Attempt.Wait(it) }
        val record = try {
            Keys.loadSecret(PIN_SECRET)?.let(PinRecord::decode)
        } catch (e: GeneralSecurityException) {
            // The Keystore key is gone: the PIN can't be checked; erasing all data is the way out.
            Log.e("AppLock", "PIN record unreadable", e)
            return Attempt.WrongPin
        }
        if (record == null || record.matches(pin)) {
            unlocked()
            return Attempt.Unlocked
        }
        rules.onWrongPin()
        return rules.waitMillis().takeIf { it > 0 }?.let { Attempt.Wait(it) } ?: Attempt.WrongPin
    }

    /** The fingerprint was accepted by the system's biometric prompt. */
    fun unlockWithBiometric() = unlocked()

    private fun unlocked() {
        rules.onUnlocked()
        _state.update { it.copy(locked = false) }
    }
}
