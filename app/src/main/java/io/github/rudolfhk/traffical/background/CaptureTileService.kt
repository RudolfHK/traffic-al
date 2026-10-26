package io.github.rudolfhk.traffical.background

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import io.github.rudolfhk.traffical.MainActivity
import io.github.rudolfhk.traffical.capture.CaptureRepository
import io.github.rudolfhk.traffical.vpn.CaptureVpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/** Quick Settings tile that starts and stops the capture without opening the app. */
class CaptureTileService : TileService() {
    private var scope: CoroutineScope? = null

    override fun onStartListening() {
        scope = MainScope().apply {
            launch { CaptureRepository.status.collect { showState(it.running) } }
        }
    }

    override fun onStopListening() {
        scope?.cancel()
        scope = null
    }

    override fun onClick() {
        val service = Intent(this, CaptureVpnService::class.java)
        try {
            when {
                CaptureRepository.status.value.running -> startService(service.setAction(CaptureVpnService.ACTION_STOP))
                VpnService.prepare(this) == null ->
                    ContextCompat.startForegroundService(this, service.setAction(CaptureVpnService.ACTION_START))
                else -> openApp() // the VPN consent dialog needs an activity
            }
        } catch (e: IllegalStateException) {
            openApp() // starting a service from the background was refused
        }
    }

    private fun showState(running: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.updateTile()
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            .putExtra(MainActivity.EXTRA_START_CAPTURE, true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }
}
