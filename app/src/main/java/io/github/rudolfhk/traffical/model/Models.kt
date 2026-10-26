package io.github.rudolfhk.traffical.model

import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.enrichment.Destination
import io.github.rudolfhk.traffical.core.enrichment.RdapInfo

// Platform-independent UI models: also compiled by tools/ui-preview (Compose Desktop).

data class AppInfo(val uid: Int, val packageName: String?, val label: String) {
    /** Used as the PCAPNG packet comment so captures stay attributable in Wireshark. */
    fun describe(): String = "uid=$uid app=${packageName ?: label}"
}

data class DnsEvent(
    val id: Long,
    val timestampMillis: Long,
    val app: AppInfo,
    val domain: String,
    val queryType: String,
    val answers: List<String>,
    val rcode: Int,
    val latencyMillis: Long?,
)

/** A connection with its app and, once the offline data is loaded, what is known about the server. */
data class Connection(val flow: FlowInfo, val app: AppInfo, val destination: Destination? = null)

enum class ThemeMode { SYSTEM, LIGHT, DARK }

/** User settings, stored by the app (SettingsStore). */
data class AppSettings(
    val theme: ThemeMode = ThemeMode.SYSTEM,
    val startOnBoot: Boolean = false,
    val recordToStorage: Boolean = true,
    /** Megabytes of 1,000,000 bytes, like the sizes shown everywhere in the app. */
    val storageLimitMb: Int = 1000,
) {
    val storageLimitBytes: Long get() = storageLimitMb * 1_000_000L

    companion object {
        val STORAGE_LIMITS_MB = listOf(250, 1000, 4000)
    }
}

/** What the recorder does while a capture runs. */
data class RecorderStatus(
    /** Name of the recording being written. */
    val recording: String? = null,
    val recordedBytes: Long = 0,
    /** Saving stopped, e.g. because the storage is full. */
    val storageError: String? = null,
    /** Packets not saved because the storage could not keep up. */
    val droppedPackets: Long = 0,
)

data class RecordingItem(
    val name: String,
    val startMillis: Long,
    val endMillis: Long,
    val bytes: Long,
    val segments: Int,
    /** The oldest part was deleted to stay within the storage limit. */
    val truncated: Boolean,
    /** Still being written. */
    val active: Boolean,
)

/** What Android allows for capturing in the background. */
data class BackgroundInfo(
    /** Battery optimization may stop the capture in the background. */
    val batteryOptimized: Boolean,
    /** The capture runs as always-on VPN (known while it runs). */
    val alwaysOn: Boolean,
    val appVersion: String,
    /** Versions of the bundled IP and tracker data, null until loaded. */
    val ipData: String? = null,
    val trackerData: String? = null,
)

/** The app lock as the settings show it. */
data class PrivacyInfo(
    val lockEnabled: Boolean,
    val biometric: Boolean,
    /** A fingerprint (or other biometric) is set up on the phone. */
    val biometricAvailable: Boolean,
)

/** Result of the online owner lookup of a server's IP address. */
data class OwnerInfo(
    val reverseDns: String?,
    val rdap: RdapInfo?,
    /** Why the RDAP lookup failed. */
    val error: String?,
)
