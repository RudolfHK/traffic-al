package io.github.rudolfhk.traffical.ui

import android.text.format.Formatter
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.rudolfhk.traffical.R
import io.github.rudolfhk.traffical.capture.AppInfo
import io.github.rudolfhk.traffical.capture.CaptureRepository
import io.github.rudolfhk.traffical.capture.CaptureStatus
import io.github.rudolfhk.traffical.capture.Connection
import io.github.rudolfhk.traffical.capture.DnsEvent
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault())

private data class AppSummary(
    val app: AppInfo,
    val bytesOut: Long,
    val bytesIn: Long,
    val connections: Int,
    val domains: Int,
)

private const val TAB_CONNECTIONS = 0
private const val TAB_DNS = 1
private const val TAB_APPS = 2

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
    var filter by rememberSaveable { mutableStateOf("") }
    var tab by rememberSaveable { mutableIntStateOf(TAB_CONNECTIONS) }

    val query = filter.trim()
    val shownConnections = remember(connections, query) {
        if (query.isEmpty()) connections else connections.filter { it.matches(query) }
    }
    val shownDnsEvents = remember(dnsEvents, query) {
        if (query.isEmpty()) dnsEvents else dnsEvents.filter { it.matches(query) }
    }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(horizontal = 16.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.app_name),
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.padding(top = 16.dp),
            )
            StatusCard(status, connections.size, dnsEvents.size, packetCount, onSwitchPrivateDns)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (status.running) {
                    Button(onClick = onStop) { Text(stringResource(R.string.action_stop)) }
                } else {
                    Button(onClick = onStart) { Text(stringResource(R.string.action_start)) }
                }
                OutlinedButton(onClick = onExport, enabled = packetCount > 0) {
                    Text(stringResource(R.string.action_export))
                }
                TextButton(onClick = onClear, enabled = connections.isNotEmpty() || packetCount > 0) {
                    Text(stringResource(R.string.action_clear))
                }
            }
            OutlinedTextField(
                value = filter,
                onValueChange = { filter = it },
                label = { Text(stringResource(R.string.filter_hint)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            TabRow(selectedTabIndex = tab) {
                Tab(
                    selected = tab == TAB_CONNECTIONS,
                    onClick = { tab = TAB_CONNECTIONS },
                    text = { Text(stringResource(R.string.tab_connections)) },
                )
                Tab(selected = tab == TAB_DNS, onClick = { tab = TAB_DNS }, text = { Text(stringResource(R.string.tab_dns)) })
                Tab(selected = tab == TAB_APPS, onClick = { tab = TAB_APPS }, text = { Text(stringResource(R.string.tab_apps)) })
            }
            val empty = when (tab) {
                TAB_DNS -> shownDnsEvents.isEmpty()
                else -> shownConnections.isEmpty()
            }
            if (empty) {
                Text(
                    text = stringResource(R.string.empty_list),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 16.dp),
                )
            } else {
                when (tab) {
                    TAB_CONNECTIONS -> ConnectionList(shownConnections)
                    TAB_DNS -> DnsList(shownDnsEvents)
                    else -> AppList(shownConnections) { selected ->
                        filter = selected
                        tab = TAB_CONNECTIONS
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusCard(
    status: CaptureStatus,
    connectionCount: Int,
    lookupCount: Int,
    packetCount: Int,
    onSwitchPrivateDns: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(if (status.running) R.string.status_running else R.string.status_stopped),
                style = MaterialTheme.typography.titleMedium,
            )
            status.errorRes?.let {
                Text(stringResource(it), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
            }
            Text(
                text = stringResource(R.string.status_counts, connectionCount, lookupCount, packetCount),
                style = MaterialTheme.typography.bodyMedium,
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
                else -> Text(
                    text = stringResource(R.string.status_mode_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun ConnectionList(connections: List<Connection>) {
    val context = LocalContext.current
    LazyColumn(modifier = Modifier.fillMaxSize()) {
        items(connections, key = { it.flow.id }) { connection ->
            val flow = connection.flow
            val badges = buildList {
                if (flow.blocked) add(stringResource(R.string.badge_blocked))
                if (flow.encryptedDns) add(stringResource(R.string.badge_encrypted_dns))
            }
            Column(modifier = Modifier.padding(vertical = 6.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = timeFormat.format(Instant.ofEpochMilli(flow.lastSeenMicros / 1000)),
                        style = MaterialTheme.typography.labelMedium,
                        fontFamily = FontFamily.Monospace,
                    )
                    Text(
                        text = connection.app.label,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    if (badges.isNotEmpty()) {
                        Text(
                            text = badges.joinToString(" · "),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
                Text(
                    text = flow.domain ?: flow.remoteAddress.hostAddress.orEmpty(),
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = "${IpProtocol.name(flow.protocol)} ${endpoint(flow.remoteAddress.hostAddress.orEmpty(), flow.remotePort)}" +
                        " · ↑ ${Formatter.formatShortFileSize(context, flow.bytesOut)}" +
                        " ↓ ${Formatter.formatShortFileSize(context, flow.bytesIn)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            HorizontalDivider()
        }
    }
}

@Composable
private fun DnsList(events: List<DnsEvent>) {
    LazyColumn(modifier = Modifier.fillMaxSize()) {
        items(events, key = { it.id }) { event ->
            Column(modifier = Modifier.padding(vertical = 6.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = timeFormat.format(Instant.ofEpochMilli(event.timestampMillis)),
                        style = MaterialTheme.typography.labelMedium,
                        fontFamily = FontFamily.Monospace,
                    )
                    Text(
                        text = event.app.label,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Text(text = event.domain, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
                Text(
                    text = "${event.queryType} → ${resultText(event)}" + (event.latencyMillis?.let { " · $it ms" } ?: ""),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            HorizontalDivider()
        }
    }
}

@Composable
private fun AppList(connections: List<Connection>, onSelect: (String) -> Unit) {
    val context = LocalContext.current
    val summaries = remember(connections) {
        connections.groupBy { it.app.uid }
            .map { (_, appConnections) ->
                AppSummary(
                    app = appConnections.first().app,
                    bytesOut = appConnections.sumOf { it.flow.bytesOut },
                    bytesIn = appConnections.sumOf { it.flow.bytesIn },
                    connections = appConnections.size,
                    domains = appConnections.mapNotNull { it.flow.domain }.distinct().size,
                )
            }
            .sortedByDescending { it.bytesOut + it.bytesIn }
    }
    LazyColumn(modifier = Modifier.fillMaxSize()) {
        items(summaries, key = { it.app.uid }) { summary ->
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onSelect(summary.app.packageName ?: summary.app.label) }
                    .padding(vertical = 8.dp),
            ) {
                Text(summary.app.label, style = MaterialTheme.typography.titleSmall)
                Text(
                    text = "↑ ${Formatter.formatShortFileSize(context, summary.bytesOut)}" +
                        " ↓ ${Formatter.formatShortFileSize(context, summary.bytesIn)} · " +
                        stringResource(R.string.app_summary, summary.connections, summary.domains),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = summary.app.packageName ?: "uid ${summary.app.uid}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            HorizontalDivider()
        }
    }
}

@Composable
private fun resultText(event: DnsEvent): String = when (event.rcode) {
    0 -> event.answers.joinToString(", ").ifEmpty { stringResource(R.string.dns_empty) }
    1 -> "FORMERR"
    2 -> "SERVFAIL"
    3 -> "NXDOMAIN"
    5 -> "REFUSED"
    else -> "RCODE ${event.rcode}"
}

private fun endpoint(host: String, port: Int) = if (':' in host) "[$host]:$port" else "$host:$port"

private fun AppInfo.matches(query: String): Boolean =
    label.contains(query, ignoreCase = true) || packageName?.contains(query, ignoreCase = true) == true

private fun Connection.matches(query: String): Boolean =
    app.matches(query) ||
        flow.domain?.contains(query, ignoreCase = true) == true ||
        flow.remoteAddress.hostAddress?.contains(query, ignoreCase = true) == true

private fun DnsEvent.matches(query: String): Boolean =
    app.matches(query) ||
        domain.contains(query, ignoreCase = true) ||
        answers.any { it.contains(query, ignoreCase = true) }
