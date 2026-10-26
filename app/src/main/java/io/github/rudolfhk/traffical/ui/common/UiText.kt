package io.github.rudolfhk.traffical.ui.common

import androidx.compose.runtime.staticCompositionLocalOf

/**
 * The strings of the shared screens. The app fills it from its string resources
 * (English/German); tools/ui-preview from values/strings.xml, mapping each property to
 * the resource of the same name in snake_case (tabDashboard -> tab_dashboard). Values
 * with %1$d etc. are format strings.
 */
data class UiText(
    val appName: String,
    val tabDashboard: String,
    val tabConnections: String,
    val tabDns: String,
    val actionBack: String,
    val rangeMinute: String,
    val rangeFiveMinutes: String,
    val rangeFifteenMinutes: String,
    val rangeHour: String,
    val rangeAll: String,
    val statSent: String,
    val statReceived: String,
    val statConnections: String,
    val statAttention: String,
    val chartThroughput: String,
    val appsByTraffic: String,
    val sortByData: String,
    val sortByConnections: String,
    val appSummary: String,
    val appAttention: String,
    val emptyList: String,
    val filterHint: String,
    val filterAttention: String,
    val filterClear: String,
    val filterApp: String,
    val filterCount: String,
    val flagTracker: String,
    val flagRisky: String,
    val flagUnnamed: String,
    val badgeEncryptedDns: String,
    val badgeBlocked: String,
    val detailApp: String,
    val detailDomain: String,
    val detailSni: String,
    val detailServerName: String,
    val detailDnsName: String,
    val detailProtocol: String,
    val detailCategory: String,
    val detailRating: String,
    val detailRemote: String,
    val detailLocal: String,
    val detailStarted: String,
    val detailDuration: String,
    val detailSent: String,
    val detailReceived: String,
    val detailRate: String,
    val detailState: String,
    val detailStateOpen: String,
    val detailStateClosed: String,
    val detailPackets: String,
    val detailNoPackets: String,
    val detailPayload: String,
    val detailEncryptedHint: String,
    val dnsEmpty: String,
)

val LocalUiText = staticCompositionLocalOf<UiText> { error("No UiText provided") }
