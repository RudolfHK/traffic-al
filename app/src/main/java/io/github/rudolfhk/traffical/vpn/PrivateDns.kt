package io.github.rudolfhk.traffical.vpn

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.os.Build
import android.provider.Settings
import android.util.Log
import java.util.concurrent.TimeUnit

/**
 * Android's Private DNS (DNS-over-TLS). In "automatic" mode the capture engine blocks
 * port 853 and Android falls back to plain DNS, which the app can read. In "strict" mode
 * (a provider hostname is set) there is no fallback, so lookups stay encrypted unless
 * the mode is switched to automatic for the duration of the capture. Changing the
 * setting needs WRITE_SECURE_SETTINGS (granted once via adb) or root.
 */
class PrivateDns(context: Context) {

    sealed interface Mode {
        data object Off : Mode
        data object Automatic : Mode
        data class Strict(val hostname: String) : Mode
    }

    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Mode of the underlying network (this app is excluded from its own VPN). */
    fun currentMode(): Mode {
        val connectivity = appContext.getSystemService(ConnectivityManager::class.java)
        return modeOf(connectivity.getLinkProperties(connectivity.activeNetwork))
    }

    fun modeOf(link: LinkProperties?): Mode {
        if (link == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return Mode.Off
        val hostname = link.privateDnsServerName
        return when {
            hostname != null -> Mode.Strict(hostname)
            link.isPrivateDnsActive -> Mode.Automatic
            else -> Mode.Off
        }
    }

    /** True while this app has switched strict mode off and still has to restore it. */
    val isOverridden: Boolean get() = prefs.contains(KEY_SAVED_HOSTNAME)

    /**
     * Switches strict Private DNS to automatic and remembers the hostname for [restore].
     * Blocking (may wait for a root prompt); call off the main thread.
     */
    fun switchToAutomatic(strict: Mode.Strict): Boolean {
        if (!isOverridden) prefs.edit().putString(KEY_SAVED_HOSTNAME, strict.hostname).commit()
        val switched = putGlobal(SETTING_MODE, MODE_OPPORTUNISTIC)
        if (!switched) prefs.edit().remove(KEY_SAVED_HOSTNAME).commit()
        return switched
    }

    /** Restores the strict mode saved by [switchToAutomatic], also after a crash. Blocking. */
    fun restore(): Boolean {
        val hostname = prefs.getString(KEY_SAVED_HOSTNAME, null) ?: return true
        val restored = putGlobal(SETTING_SPECIFIER, hostname) && putGlobal(SETTING_MODE, MODE_HOSTNAME)
        if (restored) prefs.edit().remove(KEY_SAVED_HOSTNAME).commit()
        return restored
    }

    private fun putGlobal(key: String, value: String): Boolean {
        val granted = appContext.checkSelfPermission(Manifest.permission.WRITE_SECURE_SETTINGS) ==
            PackageManager.PERMISSION_GRANTED
        if (granted) {
            try {
                return Settings.Global.putString(appContext.contentResolver, key, value)
            } catch (e: SecurityException) {
                Log.w(TAG, "WRITE_SECURE_SETTINGS rejected", e)
            }
        }
        return putGlobalAsRoot(key, value)
    }

    private fun putGlobalAsRoot(key: String, value: String): Boolean = try {
        // key and value are fixed constants or a hostname reported by Android itself.
        require(value.all { it.isLetterOrDigit() || it in ".-" }) { "unexpected value" }
        val process = ProcessBuilder("su", "-c", "settings put global $key $value")
            .redirectErrorStream(true)
            .start()
        val finished = process.waitFor(ROOT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        if (!finished) process.destroy()
        finished && process.exitValue() == 0
    } catch (e: Exception) {
        Log.i(TAG, "root not available: ${e.message}")
        false
    }

    private companion object {
        const val TAG = "PrivateDns"
        const val PREFS = "private_dns"
        const val KEY_SAVED_HOSTNAME = "saved_hostname"
        const val SETTING_MODE = "private_dns_mode"
        const val SETTING_SPECIFIER = "private_dns_specifier"
        const val MODE_OPPORTUNISTIC = "opportunistic"
        const val MODE_HOSTNAME = "hostname"
        const val ROOT_TIMEOUT_SECONDS = 30L
    }
}
