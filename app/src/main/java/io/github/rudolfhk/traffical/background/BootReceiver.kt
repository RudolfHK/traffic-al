package io.github.rudolfhk.traffical.background

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.core.content.ContextCompat
import io.github.rudolfhk.traffical.settings.SettingsStore
import io.github.rudolfhk.traffical.vpn.CaptureVpnService

/**
 * Starts the capture after boot (if enabled), and again after an app update killed a
 * running capture. Needs the VPN permission granted once; the consent dialog can't be
 * shown from the background.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val start = when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED -> SettingsStore.settings.value.startOnBoot
            Intent.ACTION_MY_PACKAGE_REPLACED -> SettingsStore.captureWanted
            else -> false
        }
        if (!start || VpnService.prepare(context) != null) return
        try {
            ContextCompat.startForegroundService(
                context,
                Intent(context, CaptureVpnService::class.java).setAction(CaptureVpnService.ACTION_START),
            )
        } catch (e: IllegalStateException) {
            Log.w("BootReceiver", "could not start the capture", e)
        }
    }
}
