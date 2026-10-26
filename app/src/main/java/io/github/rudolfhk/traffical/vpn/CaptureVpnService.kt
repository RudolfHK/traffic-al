package io.github.rudolfhk.traffical.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.Log
import androidx.annotation.StringRes
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import io.github.rudolfhk.traffical.MainActivity
import io.github.rudolfhk.traffical.R
import io.github.rudolfhk.traffical.capture.AppResolver
import io.github.rudolfhk.traffical.capture.CaptureRepository
import io.github.rudolfhk.traffical.core.capture.CaptureBatch
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import io.github.rudolfhk.traffical.settings.SettingsStore
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.Executors

/**
 * Local VPN (no remote server) that routes all traffic of all other apps into a TUN
 * interface. The native engine (zdtun) forwards every connection unchanged over normal
 * sockets and reports each packet, which the repository turns into connections and
 * DNS lookups.
 *
 * The capture runs in the background until the user stops it: with the app closed, after
 * the system killed the process (START_STICKY), as always-on VPN (started by the system)
 * and, if enabled, from boot. Its notification is silent and has no status-bar icon;
 * Android's own VPN key icon stays.
 */
class CaptureVpnService : VpnService() {

    private val mainHandler = Handler(Looper.getMainLooper())
    private val background = Executors.newSingleThreadExecutor()

    private lateinit var apps: AppResolver
    private lateinit var privateDns: PrivateDns

    private var tun: ParcelFileDescriptor? = null
    private var capture: NativeCapture? = null
    private var captureThread: Thread? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    @Volatile
    private var stopping = false

    override fun onCreate() {
        super.onCreate()
        apps = AppResolver(this)
        privateDns = PrivateDns(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                SettingsStore.captureWanted = false
                stopCapture()
            }
            ACTION_SWITCH_PRIVATE_DNS -> switchPrivateDnsToAutomatic()
            // Restarted by the system after it killed the process.
            null -> if (SettingsStore.captureWanted) startCapture() else stopSelf(startId)
            // ACTION_START, or SERVICE_INTERFACE when Android starts the always-on VPN.
            else -> startCapture()
        }
        return START_STICKY
    }

    override fun onRevoke() {
        // Another VPN took over or the user revoked the permission: don't come back.
        SettingsStore.captureWanted = false
        stopCapture()
    }

    override fun onDestroy() {
        stopCapture()
        background.shutdown()
        super.onDestroy()
    }

    private fun startCapture() {
        if (capture != null) return
        showForegroundNotification()

        val connectivity = getSystemService(ConnectivityManager::class.java)
        val link = connectivity.getLinkProperties(connectivity.activeNetwork)
        val pfd = establish(hasGlobalIpv6(link))
        if (pfd == null) {
            fail(R.string.error_vpn_establish)
            return
        }

        val engine = try {
            NativeCapture(engineListener)
        } catch (e: Throwable) {
            Log.e(TAG, "native engine unavailable", e)
            pfd.close()
            fail(R.string.error_capture_failed)
            return
        }
        engine.setDns(VPN_DNS, upstreamDns(link))
        SettingsStore.captureWanted = true
        CaptureRepository.onStarted(alwaysOn = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && isAlwaysOn)
        applyPrivateDnsMode(engine, link)

        tun = pfd
        capture = engine
        captureThread = Thread({ runEngine(engine, pfd) }, "capture").apply { start() }
        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                // The default network of this app is the real one (it is excluded from the VPN).
                engine.setDns(VPN_DNS, upstreamDns(linkProperties))
                applyPrivateDnsMode(engine, linkProperties)
            }
        }.also { connectivity.registerDefaultNetworkCallback(it) }
    }

    private fun establish(ipv6: Boolean): ParcelFileDescriptor? = try {
        Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(MTU)
            .addAddress(VPN_ADDRESS, 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(VPN_DNS)
            .apply {
                if (ipv6) {
                    addAddress(VPN_ADDRESS6, 64)
                    addRoute("::", 0)
                }
            }
            // The engine's own sockets must bypass the VPN.
            .addDisallowedApplication(packageName)
            .setBlocking(true)
            .setConfigureIntent(openAppIntent())
            .apply { if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) setMetered(false) }
            .establish()
    } catch (e: Exception) {
        Log.e(TAG, "establish() failed", e)
        null
    }

    private fun runEngine(engine: NativeCapture, pfd: ParcelFileDescriptor) {
        val result = engine.run(pfd.fd, MTU)
        if (result != 0 && !stopping) {
            Log.e(TAG, "capture engine stopped with $result")
            mainHandler.post { fail(R.string.error_capture_failed) }
        }
    }

    private fun stopCapture() {
        if (stopping) return
        stopping = true

        networkCallback?.let { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) }
        networkCallback = null
        capture?.let { engine ->
            engine.stop()
            captureThread?.join(ENGINE_JOIN_TIMEOUT_MS)
            // Freeing the engine while its thread still runs would crash; leak it instead.
            if (captureThread?.isAlive != true) engine.destroy()
        }
        capture = null
        captureThread = null
        tun?.close()
        tun = null

        if (privateDns.isOverridden) background.execute { privateDns.restore() }
        CaptureRepository.onStopped()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
        stopping = false
    }

    private fun fail(@StringRes message: Int) {
        SettingsStore.captureWanted = false
        CaptureRepository.onStopped(message)
        stopCapture()
    }

    private val engineListener = object : NativeCapture.Listener {
        override fun resolveUid(
            ipVersion: Int,
            protocol: Int,
            source: InetAddress,
            sourcePort: Int,
            destination: InetAddress,
            destinationPort: Int,
        ): Int {
            val osProtocol = when (protocol) {
                IpProtocol.TCP -> OsConstants.IPPROTO_TCP
                IpProtocol.UDP -> OsConstants.IPPROTO_UDP
                else -> return CaptureBatch.UID_UNKNOWN // getConnectionOwnerUid only knows TCP and UDP
            }
            return apps.ownerUid(
                osProtocol,
                InetSocketAddress(source, sourcePort),
                InetSocketAddress(destination, destinationPort),
            )
        }

        override fun onPackets(batch: ByteArray) {
            try {
                CaptureRepository.onBatch(batch)
            } catch (e: RuntimeException) {
                Log.e(TAG, "dropping malformed batch", e)
            }
        }

        override fun protect(socket: Int): Boolean = this@CaptureVpnService.protect(socket)
    }

    /**
     * Port 853 is blocked so that automatic Private DNS falls back to plain DNS. In strict
     * mode there is no fallback, so blocking would break all lookups: allow it then.
     */
    private fun applyPrivateDnsMode(engine: NativeCapture, link: LinkProperties?) {
        val mode = privateDns.modeOf(link)
        engine.setBlockPrivateDns(mode !is PrivateDns.Mode.Strict)
        CaptureRepository.setPrivateDns(
            strictHost = (mode as? PrivateDns.Mode.Strict)?.hostname,
            overridden = privateDns.isOverridden,
        )
    }

    private fun switchPrivateDnsToAutomatic() {
        val mode = privateDns.currentMode() as? PrivateDns.Mode.Strict ?: return
        background.execute {
            val switched = privateDns.switchToAutomatic(mode)
            mainHandler.post {
                CaptureRepository.setError(if (switched) null else R.string.error_private_dns_switch)
                capture?.let { applyPrivateDnsMode(it, currentLink()) }
            }
        }
    }

    private fun currentLink(): LinkProperties? {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        return connectivity.getLinkProperties(connectivity.activeNetwork)
    }

    /** The real resolver for queries to the virtual DNS server; IPv4 preferred. */
    private fun upstreamDns(link: LinkProperties?): String {
        val servers = link?.dnsServers.orEmpty().filter {
            !it.isLinkLocalAddress && it.hostAddress != VPN_DNS
        }
        val server = servers.firstOrNull { it is Inet4Address } ?: servers.firstOrNull()
        return server?.hostAddress?.substringBefore('%') ?: FALLBACK_DNS
    }

    private fun hasGlobalIpv6(link: LinkProperties?): Boolean = link?.linkAddresses.orEmpty().any {
        val address = it.address
        address is Inet6Address && !address.isLinkLocalAddress && !address.isLoopbackAddress &&
            (address.address[0].toInt() and 0xfe) != 0xfc // not a unique local address
    }

    /**
     * A foreground service keeps the capture alive in the background. Its channel has the
     * lowest importance: no sound, no status-bar icon, folded away in the shade.
     */
    private fun showForegroundNotification() {
        val notifications = getSystemService(NotificationManager::class.java)
        notifications.deleteNotificationChannel(OLD_CHANNEL_ID)
        notifications.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_MIN).apply {
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_SECRET
            },
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
            .setSilent(true)
            .setShowWhen(false)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .addAction(0, getString(R.string.action_stop), stopIntent)
            .build()
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        try {
            ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, type)
        } catch (e: IllegalStateException) {
            // Android 12+ may refuse a foreground start from the background (e.g. a sticky
            // restart). The VPN still runs: the system keeps a VPN service bound.
            Log.w(TAG, "capture runs without a foreground notification", e)
        }
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
        const val ACTION_SWITCH_PRIVATE_DNS = "io.github.rudolfhk.traffical.SWITCH_PRIVATE_DNS"

        private const val TAG = "CaptureVpnService"
        private const val VPN_ADDRESS = "10.215.173.1"
        private const val VPN_ADDRESS6 = "fd00:7a1:c0de::1"
        private const val VPN_DNS = "10.215.173.2"
        private const val MTU = 10_000
        private const val ENGINE_JOIN_TIMEOUT_MS = 3_000L

        // Only used if the underlying network reports no usable DNS server.
        private const val FALLBACK_DNS = "9.9.9.9"

        private const val CHANNEL_ID = "capture_silent"
        private const val OLD_CHANNEL_ID = "capture"
        private const val NOTIFICATION_ID = 1
    }
}
