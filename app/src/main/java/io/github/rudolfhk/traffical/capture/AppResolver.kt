package io.github.rudolfhk.traffical.capture

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import io.github.rudolfhk.traffical.R
import io.github.rudolfhk.traffical.model.AppInfo
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/** Maps connections seen on the TUN interface to the app (uid) that opened them. */
class AppResolver(context: Context) {
    private val appContext = context.applicationContext
    private val packageManager = appContext.packageManager
    private val connectivity = appContext.getSystemService(ConnectivityManager::class.java)
    private val cache = ConcurrentHashMap<Int, AppInfo>()

    /**
     * Returns the uid owning the connection, or [Process.INVALID_UID]. Only works while this
     * app is the active VPN, and only on Android 10+ (older versions would need /proc/net).
     */
    fun ownerUid(protocol: Int, local: InetSocketAddress, remote: InetSocketAddress): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return Process.INVALID_UID
        return try {
            connectivity.getConnectionOwnerUid(protocol, local, remote)
        } catch (_: SecurityException) {
            Process.INVALID_UID
        } catch (_: IllegalArgumentException) {
            Process.INVALID_UID
        }
    }

    fun appInfo(uid: Int): AppInfo = cache.getOrPut(uid) { resolve(uid) }

    private fun resolve(uid: Int): AppInfo {
        if (uid == Process.INVALID_UID) return AppInfo(uid, null, appContext.getString(R.string.app_unknown))
        val packages = packageManager.getPackagesForUid(uid)?.sorted()
        if (packages.isNullOrEmpty()) {
            return AppInfo(uid, null, packageManager.getNameForUid(uid) ?: "uid $uid")
        }
        val primary = packages.first()
        val label = if (packages.size == 1) {
            loadLabel(primary)
        } else {
            // Shared uid (e.g. android.uid.system): several packages, no single app label.
            packageManager.getNameForUid(uid) ?: primary
        }
        return AppInfo(uid, primary, label)
    }

    private fun loadLabel(packageName: String): String = try {
        packageManager.getApplicationInfo(packageName, 0).loadLabel(packageManager).toString()
    } catch (_: PackageManager.NameNotFoundException) {
        packageName
    }
}
