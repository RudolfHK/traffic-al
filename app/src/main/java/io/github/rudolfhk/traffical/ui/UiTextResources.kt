package io.github.rudolfhk.traffical.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import io.github.rudolfhk.traffical.R
import io.github.rudolfhk.traffical.ui.common.UiText

/** The shared screens' strings from the app's resources, reloaded when the locale changes. */
@Composable
fun rememberUiText(): UiText {
    val res = LocalContext.current.resources
    val configuration = LocalConfiguration.current
    return remember(res, configuration) {
        UiText(
            appName = res.getString(R.string.app_name),
            tabDashboard = res.getString(R.string.tab_dashboard),
            tabConnections = res.getString(R.string.tab_connections),
            tabDns = res.getString(R.string.tab_dns),
            actionBack = res.getString(R.string.action_back),
            rangeMinute = res.getString(R.string.range_minute),
            rangeFiveMinutes = res.getString(R.string.range_five_minutes),
            rangeFifteenMinutes = res.getString(R.string.range_fifteen_minutes),
            rangeHour = res.getString(R.string.range_hour),
            rangeAll = res.getString(R.string.range_all),
            statSent = res.getString(R.string.stat_sent),
            statReceived = res.getString(R.string.stat_received),
            statConnections = res.getString(R.string.stat_connections),
            statAttention = res.getString(R.string.stat_attention),
            chartThroughput = res.getString(R.string.chart_throughput),
            appsByTraffic = res.getString(R.string.apps_by_traffic),
            sortByData = res.getString(R.string.sort_by_data),
            sortByConnections = res.getString(R.string.sort_by_connections),
            appSummary = res.getString(R.string.app_summary),
            appAttention = res.getString(R.string.app_attention),
            emptyList = res.getString(R.string.empty_list),
            filterHint = res.getString(R.string.filter_hint),
            filterAttention = res.getString(R.string.filter_attention),
            filterClear = res.getString(R.string.filter_clear),
            filterApp = res.getString(R.string.filter_app),
            filterCount = res.getString(R.string.filter_count),
            flagTracker = res.getString(R.string.flag_tracker),
            flagRisky = res.getString(R.string.flag_risky),
            flagUnnamed = res.getString(R.string.flag_unnamed),
            badgeEncryptedDns = res.getString(R.string.badge_encrypted_dns),
            badgeBlocked = res.getString(R.string.badge_blocked),
            detailApp = res.getString(R.string.detail_app),
            detailDomain = res.getString(R.string.detail_domain),
            detailSni = res.getString(R.string.detail_sni),
            detailServerName = res.getString(R.string.detail_server_name),
            detailDnsName = res.getString(R.string.detail_dns_name),
            detailProtocol = res.getString(R.string.detail_protocol),
            detailCategory = res.getString(R.string.detail_category),
            detailRating = res.getString(R.string.detail_rating),
            detailRemote = res.getString(R.string.detail_remote),
            detailLocal = res.getString(R.string.detail_local),
            detailStarted = res.getString(R.string.detail_started),
            detailDuration = res.getString(R.string.detail_duration),
            detailSent = res.getString(R.string.detail_sent),
            detailReceived = res.getString(R.string.detail_received),
            detailRate = res.getString(R.string.detail_rate),
            detailState = res.getString(R.string.detail_state),
            detailStateOpen = res.getString(R.string.detail_state_open),
            detailStateClosed = res.getString(R.string.detail_state_closed),
            detailPackets = res.getString(R.string.detail_packets),
            detailNoPackets = res.getString(R.string.detail_no_packets),
            detailPayload = res.getString(R.string.detail_payload),
            detailEncryptedHint = res.getString(R.string.detail_encrypted_hint),
            dnsEmpty = res.getString(R.string.dns_empty),
        )
    }
}
