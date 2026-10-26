package io.github.rudolfhk.traffical

import android.Manifest
import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.text.format.Formatter
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import io.github.rudolfhk.traffical.capture.CaptureRepository
import io.github.rudolfhk.traffical.model.BackgroundInfo
import io.github.rudolfhk.traffical.model.ThemeMode
import io.github.rudolfhk.traffical.settings.SettingsStore
import io.github.rudolfhk.traffical.ui.MainActions
import io.github.rudolfhk.traffical.ui.MainScreen
import io.github.rudolfhk.traffical.ui.TrafficAlTheme
import io.github.rudolfhk.traffical.vpn.CaptureVpnService
import io.github.rudolfhk.traffical.vpn.PrivateDns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter

class MainActivity : ComponentActivity() {

    /** The recording whose export waits for the file picker; null exports the packets in memory. */
    private var pendingExport: String? = null

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { requestVpnConsent() }

    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                startCaptureService()
            } else {
                CaptureRepository.onStopped(R.string.error_vpn_consent_denied)
            }
        }

    private val exportPcapng =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
            if (uri != null) export(uri, pendingExport)
            pendingExport = null
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pendingExport = savedInstanceState?.getString(STATE_PENDING_EXPORT)
        restorePrivateDnsAfterCrash()
        val actions = MainActions(
            start = ::requestStart,
            stop = ::stopCapture,
            clear = CaptureRepository::clear,
            switchPrivateDns = ::switchPrivateDns,
            exportBuffer = { launchExport(null) },
            exportRecording = { launchExport(it) },
            requestBatteryExemption = ::requestBatteryExemption,
            openVpnSettings = ::openVpnSettings,
            backgroundInfo = ::backgroundInfo,
        )
        setContent {
            val settings by SettingsStore.settings.collectAsStateWithLifecycle()
            val dark = when (settings.theme) {
                ThemeMode.SYSTEM -> isSystemInDarkTheme()
                ThemeMode.LIGHT -> false
                ThemeMode.DARK -> true
            }
            // Status and navigation bar icons follow the app's theme, not only the system's.
            DisposableEffect(dark) {
                enableEdgeToEdge(
                    statusBarStyle = SystemBarStyle.auto(Color.TRANSPARENT, Color.TRANSPARENT) { dark },
                    navigationBarStyle = SystemBarStyle.auto(LIGHT_SCRIM, DARK_SCRIM) { dark },
                )
                onDispose {}
            }
            TrafficAlTheme(dark) { MainScreen(actions) }
        }
        if (savedInstanceState == null) handleStartRequest(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleStartRequest(intent)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(STATE_PENDING_EXPORT, pendingExport)
    }

    /** The Quick Settings tile opens the app when the VPN consent dialog is needed. */
    private fun handleStartRequest(intent: Intent?) {
        if (intent?.getBooleanExtra(EXTRA_START_CAPTURE, false) == true && !CaptureRepository.status.value.running) {
            requestStart()
        }
    }

    /** A capture that ended without stopping cleanly may have left strict Private DNS switched off. */
    private fun restorePrivateDnsAfterCrash() {
        val privateDns = PrivateDns(this)
        if (CaptureRepository.status.value.running || !privateDns.isOverridden) return
        lifecycleScope.launch(Dispatchers.IO) { privateDns.restore() }
    }

    private fun switchPrivateDns() {
        startService(Intent(this, CaptureVpnService::class.java).setAction(CaptureVpnService.ACTION_SWITCH_PRIVATE_DNS))
    }

    private fun requestStart() {
        val needsNotificationPermission = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        if (needsNotificationPermission) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            requestVpnConsent()
        }
    }

    private fun requestVpnConsent() {
        val consent = VpnService.prepare(this)
        if (consent != null) vpnConsent.launch(consent) else startCaptureService()
    }

    private fun startCaptureService() {
        ContextCompat.startForegroundService(
            this,
            Intent(this, CaptureVpnService::class.java).setAction(CaptureVpnService.ACTION_START),
        )
    }

    private fun stopCapture() {
        startService(Intent(this, CaptureVpnService::class.java).setAction(CaptureVpnService.ACTION_STOP))
    }

    private fun launchExport(recording: String?) {
        pendingExport = recording
        val time = recording?.toLongOrNull()?.let { LocalDateTime.ofInstant(Instant.ofEpochMilli(it), ZoneId.systemDefault()) }
            ?: LocalDateTime.now()
        exportPcapng.launch("traffic-al-" + time.format(FILE_TIME) + ".pcapng")
    }

    private fun export(uri: Uri, recording: String?) {
        lifecycleScope.launch {
            val message = withContext(Dispatchers.IO) {
                runCatching {
                    contentResolver.openOutputStream(uri)?.let { out ->
                        if (recording == null) {
                            getString(R.string.export_done, CaptureRepository.exportPcapng(out))
                        } else {
                            CaptureRepository.exportRecording(recording, out)?.let { bytes ->
                                getString(R.string.export_recording_done, Formatter.formatShortFileSize(this@MainActivity, bytes))
                            }
                        }
                    }
                }.getOrNull()
            } ?: getString(R.string.export_failed)
            Toast.makeText(this@MainActivity, message, Toast.LENGTH_LONG).show()
        }
    }

    /** Asks to exempt the app from battery optimization, which stops background work. */
    @SuppressLint("BatteryLife") // the user asked for it in the settings
    private fun requestBatteryExemption() {
        val request = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName"))
        if (!tryStart(request)) tryStart(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
    }

    private fun openVpnSettings() {
        if (!tryStart(Intent(Settings.ACTION_VPN_SETTINGS))) tryStart(Intent(Settings.ACTION_WIRELESS_SETTINGS))
    }

    private fun tryStart(intent: Intent): Boolean = try {
        startActivity(intent)
        true
    } catch (_: ActivityNotFoundException) {
        false
    }

    private fun backgroundInfo() = BackgroundInfo(
        batteryOptimized = !getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(packageName),
        alwaysOn = CaptureRepository.status.value.alwaysOn,
        appVersion = BuildConfig.VERSION_NAME,
    )

    companion object {
        /** Start the capture when opened (used by the Quick Settings tile). */
        const val EXTRA_START_CAPTURE = "io.github.rudolfhk.traffical.START_CAPTURE"

        private const val STATE_PENDING_EXPORT = "pending_export"
        private val FILE_TIME = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")

        // The scrims enableEdgeToEdge uses by default for the navigation bar.
        private val LIGHT_SCRIM = Color.argb(0xe6, 0xFF, 0xFF, 0xFF)
        private val DARK_SCRIM = Color.argb(0x80, 0x1b, 0x1b, 0x1b)
    }
}
