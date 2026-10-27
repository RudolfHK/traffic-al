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
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricPrompt
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import io.github.rudolfhk.traffical.capture.CaptureRepository
import io.github.rudolfhk.traffical.capture.TlsKeyStore
import io.github.rudolfhk.traffical.enrichment.EnrichmentStore
import io.github.rudolfhk.traffical.model.BackgroundInfo
import io.github.rudolfhk.traffical.model.ThemeMode
import io.github.rudolfhk.traffical.security.AppLock
import io.github.rudolfhk.traffical.settings.SettingsStore
import io.github.rudolfhk.traffical.ui.LockGate
import io.github.rudolfhk.traffical.ui.MainActions
import io.github.rudolfhk.traffical.ui.MainScreen
import io.github.rudolfhk.traffical.ui.TrafficAlTheme
import io.github.rudolfhk.traffical.ui.common.LocalUiText
import io.github.rudolfhk.traffical.ui.rememberUiText
import io.github.rudolfhk.traffical.vpn.CaptureVpnService
import io.github.rudolfhk.traffical.vpn.PrivateDns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/** A FragmentActivity because the fingerprint prompt (BiometricPrompt) needs one. */
class MainActivity : FragmentActivity() {

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

    private lateinit var biometricPrompt: BiometricPrompt

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pendingExport = savedInstanceState?.getString(STATE_PENDING_EXPORT)
        restorePrivateDnsAfterCrash()
        EnrichmentStore.load(this)
        biometricPrompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    AppLock.unlockWithBiometric()
                }
            },
        )
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
            biometricAvailable = ::biometricAvailable,
            authenticateBiometric = ::authenticateBiometric,
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
            // While the app lock is on, the app's content stays out of screenshots and the
            // recent apps overview.
            val lock by AppLock.state.collectAsStateWithLifecycle()
            LaunchedEffect(lock.enabled) {
                if (lock.enabled) {
                    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
                } else {
                    window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                }
            }
            TrafficAlTheme(dark) {
                CompositionLocalProvider(LocalUiText provides rememberUiText()) {
                    if (lock.locked) LockGate(lock, actions) else MainScreen(actions)
                }
            }
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
                            CaptureRepository.exportRecording(recording, out)?.let { result ->
                                val size = Formatter.formatShortFileSize(this@MainActivity, result.bytes)
                                if (result.damagedSegments == 0) {
                                    getString(R.string.export_recording_done, result.packets, size)
                                } else {
                                    getString(R.string.export_recording_damaged, result.packets, size, result.damagedSegments)
                                }
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

    private fun biometricAvailable(): Boolean =
        BiometricManager.from(this).canAuthenticate(BIOMETRIC_WEAK) == BiometricManager.BIOMETRIC_SUCCESS

    private fun authenticateBiometric() {
        if (!biometricAvailable()) return
        biometricPrompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(getString(R.string.biometric_title))
                .setNegativeButtonText(getString(R.string.biometric_use_pin))
                .setAllowedAuthenticators(BIOMETRIC_WEAK)
                .build(),
        )
    }

    private fun backgroundInfo() = BackgroundInfo(
        batteryOptimized = !getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(packageName),
        alwaysOn = CaptureRepository.status.value.alwaysOn,
        appVersion = BuildConfig.VERSION_NAME,
        ipData = EnrichmentStore.current?.ips?.version,
        trackerData = EnrichmentStore.current?.trackers?.version,
        tlsKeyLogPath = TlsKeyStore.path,
        tlsKeySessions = TlsKeyStore.sessionCount(),
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
