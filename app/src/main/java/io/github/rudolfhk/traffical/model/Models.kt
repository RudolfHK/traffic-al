package io.github.rudolfhk.traffical.model

import io.github.rudolfhk.traffical.core.capture.FlowInfo

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

data class Connection(val flow: FlowInfo, val app: AppInfo)
