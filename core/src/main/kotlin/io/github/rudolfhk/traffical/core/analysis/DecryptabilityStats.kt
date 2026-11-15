package io.github.rudolfhk.traffical.core.analysis

import io.github.rudolfhk.traffical.core.capture.FlowInfo

/** How much of one app's HTTP-bearing traffic can be read versus stays encrypted (phase 13). */
data class AppReadability(
    val uid: Int,
    val readableConnections: Int,
    val encryptedConnections: Int,
    val readableBytes: Long,
    val encryptedBytes: Long,
) {
    val connections: Int get() = readableConnections + encryptedConnections
    val bytes: Long get() = readableBytes + encryptedBytes

    /** Fraction of this app's HTTP-bearing bytes that are readable (0..1); 0 when it has none. */
    val readableFraction: Double get() = if (bytes == 0L) 0.0 else readableBytes.toDouble() / bytes

    /** Everything this app sends is readable (nothing opaque). */
    val fullyReadable: Boolean get() = encryptedConnections == 0 && readableConnections > 0

    /** Nothing this app sends can be read — entirely opaque (pinned or no keys). */
    val fullyEncrypted: Boolean get() = readableConnections == 0 && encryptedConnections > 0
}

/**
 * The readable-versus-undecryptable breakdown of the captured traffic (phase 13): how much is
 * decrypted or in the clear, and how much stays encrypted because there are no keys or the app
 * pins. It answers "what of mine can I actually read, and what is impossible to decrypt", and
 * makes the MITM measurable — apps routed through mitmproxy move from encrypted to readable.
 */
data class DecryptabilityStats(
    val readableConnections: Int,
    val encryptedConnections: Int,
    val readableBytes: Long,
    val encryptedBytes: Long,
    /** Apps with HTTP-bearing traffic, most-encrypted (most opaque by bytes) first. */
    val apps: List<AppReadability>,
) {
    val connections: Int get() = readableConnections + encryptedConnections
    val bytes: Long get() = readableBytes + encryptedBytes

    /** Fraction of all HTTP-bearing bytes that are readable (0..1). */
    val readableFraction: Double get() = if (bytes == 0L) 0.0 else readableBytes.toDouble() / bytes

    /** Apps whose traffic is entirely readable. */
    val fullyReadableApps: Int get() = apps.count { it.fullyReadable }

    /** Apps whose traffic is entirely opaque (pinned or no keys). */
    val fullyEncryptedApps: Int get() = apps.count { it.fullyEncrypted }

    companion object {
        val EMPTY = DecryptabilityStats(0, 0, 0, 0, emptyList())
    }
}

/**
 * Builds the decryptability breakdown of [flows]. [read] classifies each connection (the app
 * runs decryption with the owner's keys plus [PlaintextDissector]; pure callers can stub it).
 * NOT_APPLICABLE flows (DNS and other non-HTTP) are left out so the ratio reflects the app's
 * actual web traffic, not its name lookups. Pure and deterministic.
 */
fun decryptabilityStats(
    flows: List<FlowInfo>,
    read: (FlowInfo) -> FlowReadResult = { FlowReadResult.NOT_APPLICABLE },
): DecryptabilityStats {
    val apps = ArrayList<AppReadability>()
    var readableConnections = 0
    var encryptedConnections = 0
    var readableBytes = 0L
    var encryptedBytes = 0L

    for ((uid, appFlows) in flows.groupBy { it.uid }) {
        var rc = 0
        var ec = 0
        var rb = 0L
        var eb = 0L
        for (flow in appFlows) {
            val bytes = flow.bytesOut + flow.bytesIn
            when (read(flow).state) {
                ReadState.READABLE -> { rc++; rb += bytes }
                ReadState.ENCRYPTED -> { ec++; eb += bytes }
                ReadState.NOT_APPLICABLE -> {}
            }
        }
        if (rc == 0 && ec == 0) continue
        apps += AppReadability(uid, rc, ec, rb, eb)
        readableConnections += rc
        encryptedConnections += ec
        readableBytes += rb
        encryptedBytes += eb
    }

    apps.sortWith(compareByDescending<AppReadability> { it.encryptedBytes }.thenByDescending { it.bytes })
    return DecryptabilityStats(readableConnections, encryptedConnections, readableBytes, encryptedBytes, apps)
}
