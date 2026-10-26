package io.github.rudolfhk.traffical.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import io.github.rudolfhk.traffical.R
import io.github.rudolfhk.traffical.capture.CaptureRepository
import io.github.rudolfhk.traffical.capture.CaptureStatus
import io.github.rudolfhk.traffical.core.analysis.ConnectionFilter
import io.github.rudolfhk.traffical.core.analysis.DashboardData
import io.github.rudolfhk.traffical.core.analysis.FlowPacket
import io.github.rudolfhk.traffical.core.analysis.TimeRange
import io.github.rudolfhk.traffical.model.Connection
import io.github.rudolfhk.traffical.ui.common.ConnectionDetailScreen
import io.github.rudolfhk.traffical.ui.common.ConnectionsScreen
import io.github.rudolfhk.traffical.ui.common.DashboardScreen
import io.github.rudolfhk.traffical.ui.common.DnsScreen
import io.github.rudolfhk.traffical.ui.common.LocalUiText
import io.github.rudolfhk.traffical.ui.common.Tab
import io.github.rudolfhk.traffical.ui.common.TrafficAlScaffold
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/** How often the dashboard is recomputed while visible. */
private const val DASHBOARD_REFRESH_MILLIS = 1_000L

private val filterSaver: Saver<ConnectionFilter, Any> = listSaver<ConnectionFilter, Any?>(
    save = { listOf(it.text, it.timeRange.name, it.protocol, it.port, it.uid, it.attentionOnly) },
    restore = {
        ConnectionFilter(
            text = it[0] as String,
            timeRange = TimeRange.valueOf(it[1] as String),
            protocol = it[2] as String?,
            port = it[3] as Int?,
            uid = it[4] as Int?,
            attentionOnly = it[5] as Boolean,
        )
    },
)

@Composable
fun MainScreen(
    onStart: () -> Unit,
    onStop: () -> Unit,
    onExport: () -> Unit,
    onClear: () -> Unit,
    onSwitchPrivateDns: () -> Unit,
) {
    val status by CaptureRepository.status.collectAsStateWithLifecycle()
    val connections by CaptureRepository.connections.collectAsStateWithLifecycle()
    val dnsEvents by CaptureRepository.dnsEvents.collectAsStateWithLifecycle()
    val packetCount by CaptureRepository.packetCount.collectAsStateWithLifecycle()

    var tab by rememberSaveable { mutableStateOf(Tab.DASHBOARD) }
    var range by rememberSaveable { mutableStateOf(TimeRange.FIVE_MINUTES) }
    var filter by rememberSaveable(stateSaver = filterSaver) { mutableStateOf(ConnectionFilter()) }
    var dnsQuery by rememberSaveable { mutableStateOf("") }

    // The open connection detail. The connection list only holds the most recent
    // connections, so the last known state is kept in case it drops out.
    var detailId by rememberSaveable { mutableStateOf<Long?>(null) }
    var detailLast by remember { mutableStateOf<Connection?>(null) }
    val detail = detailId?.let { id ->
        connections.firstOrNull { it.flow.id == id } ?: detailLast?.takeIf { it.flow.id == id }
    }
    LaunchedEffect(detail) {
        if (detail != null) {
            detailLast = detail
        } else {
            detailId = null
        }
    }

    BackHandler(enabled = detail != null) { detailId = null }
    BackHandler(enabled = detail == null && tab != Tab.DASHBOARD) { tab = Tab.DASHBOARD }

    val text = rememberUiText()
    CompositionLocalProvider(LocalUiText provides text) {
        TrafficAlScaffold(
            tab = tab,
            onTabSelected = {
                tab = it
                detailId = null
            },
            title = when {
                detail != null -> detail.app.label
                tab == Tab.CONNECTIONS -> text.tabConnections
                tab == Tab.DNS -> text.tabDns
                else -> text.appName
            },
            onBack = if (detail != null) ({ detailId = null }) else null,
        ) { padding ->
            val modifier = Modifier.padding(padding)
            when {
                detail != null -> {
                    var packets by remember(detail.flow.id, detail.flow.closed) {
                        mutableStateOf<List<FlowPacket>?>(null)
                    }
                    LaunchedEffect(detail.flow.id, detail.flow.closed) {
                        packets = withContext(Dispatchers.Default) { CaptureRepository.packetsOf(detail) }
                    }
                    ConnectionDetailScreen(detail, packets, modifier)
                }
                tab == Tab.DASHBOARD -> {
                    val data = rememberDashboard(range)
                    DashboardScreen(
                        data = data,
                        appInfo = CaptureRepository::appInfo,
                        onRangeChange = { range = it },
                        onAppClick = { uid ->
                            filter = ConnectionFilter(uid = uid, timeRange = range)
                            tab = Tab.CONNECTIONS
                        },
                        header = {
                            StatusCard(
                                status = status,
                                connectionCount = connections.size,
                                lookupCount = dnsEvents.size,
                                packetCount = packetCount,
                                onStart = onStart,
                                onStop = onStop,
                                onExport = onExport,
                                onClear = onClear,
                                onSwitchPrivateDns = onSwitchPrivateDns,
                            )
                        },
                        modifier = modifier,
                    )
                }
                tab == Tab.CONNECTIONS -> {
                    val nowMicros = remember(connections, filter.timeRange) { CaptureRepository.referenceMicros() }
                    ConnectionsScreen(
                        connections = connections,
                        filter = filter,
                        onFilterChange = { filter = it },
                        onConnectionClick = { detailId = it.flow.id },
                        nowMicros = nowMicros,
                        modifier = modifier,
                    )
                }
                else -> DnsScreen(dnsEvents, dnsQuery, { dnsQuery = it }, modifier)
            }
        }
    }
}

/**
 * The dashboard over [range], recomputed every second while the screen is visible. The
 * previous data stays on screen while a new range is computed.
 */
@Composable
private fun rememberDashboard(range: TimeRange): DashboardData {
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val data = remember { mutableStateOf(CaptureRepository.dashboard(range)) }
    LaunchedEffect(range, lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                data.value = withContext(Dispatchers.Default) { CaptureRepository.dashboard(range) }
                delay(DASHBOARD_REFRESH_MILLIS)
            }
        }
    }
    return data.value
}

@Composable
private fun StatusCard(
    status: CaptureStatus,
    connectionCount: Int,
    lookupCount: Int,
    packetCount: Int,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onExport: () -> Unit,
    onClear: () -> Unit,
    onSwitchPrivateDns: () -> Unit,
) {
    Card(Modifier.padding(horizontal = 16.dp).fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(if (status.running) R.string.status_running else R.string.status_stopped),
                style = MaterialTheme.typography.titleMedium,
            )
            status.errorRes?.let {
                Text(stringResource(it), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
            }
            Text(
                text = stringResource(R.string.status_counts, connectionCount, lookupCount, packetCount),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            when {
                status.privateDnsOverridden -> Text(
                    text = stringResource(R.string.private_dns_overridden),
                    style = MaterialTheme.typography.bodySmall,
                )
                status.running && status.privateDnsStrictHost != null -> {
                    Text(
                        text = stringResource(R.string.private_dns_strict, status.privateDnsStrictHost),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                    TextButton(onClick = onSwitchPrivateDns) { Text(stringResource(R.string.action_private_dns_switch)) }
                }
                !status.running -> Text(
                    text = stringResource(R.string.status_mode_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Row(Modifier.padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (status.running) {
                    Button(onClick = onStop) { Text(stringResource(R.string.action_stop)) }
                } else {
                    Button(onClick = onStart) { Text(stringResource(R.string.action_start)) }
                }
                OutlinedButton(onClick = onExport, enabled = packetCount > 0) {
                    Text(stringResource(R.string.action_export))
                }
                TextButton(onClick = onClear, enabled = connectionCount > 0 || packetCount > 0) {
                    Text(stringResource(R.string.action_clear))
                }
            }
        }
    }
}
