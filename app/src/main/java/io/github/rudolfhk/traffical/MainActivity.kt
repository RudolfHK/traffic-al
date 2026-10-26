package io.github.rudolfhk.traffical

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import io.github.rudolfhk.traffical.capture.CaptureRepository
import io.github.rudolfhk.traffical.ui.MainScreen
import io.github.rudolfhk.traffical.ui.TrafficAlTheme
import io.github.rudolfhk.traffical.vpn.CaptureVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

class MainActivity : ComponentActivity() {

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
            if (uri != null) export(uri)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            TrafficAlTheme {
                MainScreen(
                    onStart = ::requestStart,
                    onStop = ::stopCapture,
                    onExport = { exportPcapng.launch(exportFileName()) },
                    onClear = CaptureRepository::clear,
                )
            }
        }
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

    private fun export(uri: Uri) {
        lifecycleScope.launch {
            val count = withContext(Dispatchers.IO) {
                runCatching { contentResolver.openOutputStream(uri)?.use(CaptureRepository::exportPcapng) }.getOrNull()
            }
            val message = if (count != null) getString(R.string.export_done, count) else getString(R.string.export_failed)
            Toast.makeText(this@MainActivity, message, Toast.LENGTH_LONG).show()
        }
    }

    private fun exportFileName(): String =
        "traffic-al-" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + ".pcapng"
}
