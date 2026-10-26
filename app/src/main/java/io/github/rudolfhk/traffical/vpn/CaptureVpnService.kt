package io.github.rudolfhk.traffical.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.util.Log
import androidx.annotation.StringRes
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import io.github.rudolfhk.traffical.MainActivity
import io.github.rudolfhk.traffical.R
import io.github.rudolfhk.traffical.capture.AppResolver
import io.github.rudolfhk.traffical.capture.CaptureRepository
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import io.github.rudolfhk.traffical.core.packet.PacketParser
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * Local VPN (no remote server). Phase 2a: only the virtual DNS server address is routed
 * into the TUN interface, so every app's DNS lookups are captured and attributed while all
 * other traffic keeps flowing over the normal network untouched.
 */
class CaptureVpnService : VpnService() {

    private val vpnDnsAddress: InetAddress = InetAddress.getByName(VPN_DNS)

    private var tun: TunInterface? = null
    private var executor: ExecutorService? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopCapture()
        } else {
            startCapture()
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        // Another VPN took over or the user revoked the permission.
        stopCapture()
    }

    override fun onDestroy() {
        stopCapture()
        super.onDestroy()
    }

    private fun startCapture() {
        if (tun != null) return
        showForegroundNotification()

        val pfd = try {
            Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(MTU)
                .addAddress(VPN_ADDRESS, 30)
                .addDnsServer(VPN_DNS)
                .addRoute(VPN_DNS, 32)
                // Our own sockets (upstream DNS) must bypass the VPN.
                .addDisallowedApplication(packageName)
                .setConfigureIntent(openAppIntent())
                .apply { if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) setMetered(false) }
                .establish()
        } catch (e: Exception) {
            Log.e(TAG, "establish() failed", e)
            null
        }
        if (pfd == null) {
            fail(R.string.error_vpn_establish)
            return
        }

        val dnsExecutor = Executors.newFixedThreadPool(DNS_THREADS)
        val tunInterface = TunInterface(pfd, MTU)
        val forwarder = DnsForwarder(this, AppResolver(this), ::upstreamDnsServers, tunInterface::write)
        executor = dnsExecutor
        tun = tunInterface

        tunInterface.start { packet, timestampMicros ->
            val parsed = PacketParser.parse(packet)
            if (parsed != null && parsed.protocol == IpProtocol.UDP &&
                parsed.destinationPort == 53 && parsed.destination == vpnDnsAddress
            ) {
                try {
                    dnsExecutor.execute { forwarder.forward(packet, parsed, timestampMicros) }
                } catch (_: RejectedExecutionException) {
                    // Capture is stopping.
                }
            } else {
                // Anything else routed to us (e.g. DNS over TCP) is recorded but not answered yet.
                CaptureRepository.recordPacket(packet, timestampMicros, null)
            }
        }
        CaptureRepository.onStarted()
    }

    private fun stopCapture() {
        tun?.close()
        tun = null
        executor?.shutdownNow()
        executor = null
        CaptureRepository.onStopped()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun fail(@StringRes message: Int) {
        CaptureRepository.onStopped(message)
        stopCapture()
    }

    /** Resolvers of the underlying network; this app is excluded from the VPN, so its default network is the real one. */
    private fun upstreamDnsServers(): List<InetAddress> {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        val servers = connectivity.getLinkProperties(connectivity.activeNetwork)
            ?.dnsServers
            .orEmpty()
            .filter { it != vpnDnsAddress }
        return servers.ifEmpty { FALLBACK_DNS.map(InetAddress::getByName) }
    }

    private fun showForegroundNotification() {
        val notifications = getSystemService(NotificationManager::class.java)
        notifications.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW),
        )
        val stopIntent = PendingIntent.getService(
            this,
            0,
            Intent(this, CaptureVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_capture)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setContentIntent(openAppIntent())
            .setOngoing(true)
            .addAction(0, getString(R.string.action_stop), stopIntent)
            .build()
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, type)
    }

    private fun openAppIntent(): PendingIntent = PendingIntent.getActivity(
        this,
        0,
        Intent(this, MainActivity::class.java),
        PendingIntent.FLAG_IMMUTABLE,
    )

    companion object {
        const val ACTION_START = "io.github.rudolfhk.traffical.START"
        const val ACTION_STOP = "io.github.rudolfhk.traffical.STOP"

        private const val TAG = "CaptureVpnService"
        private const val VPN_ADDRESS = "10.215.173.1"
        private const val VPN_DNS = "10.215.173.2"
        private const val MTU = 16_384
        private const val DNS_THREADS = 16

        // Only used if the underlying network reports no DNS servers.
        private val FALLBACK_DNS = listOf("9.9.9.9", "149.112.112.112")

        private const val CHANNEL_ID = "capture"
        private const val NOTIFICATION_ID = 1
    }
}
