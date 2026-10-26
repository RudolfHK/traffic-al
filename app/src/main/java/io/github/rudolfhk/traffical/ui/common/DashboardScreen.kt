package io.github.rudolfhk.traffical.ui.common

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.rudolfhk.traffical.core.analysis.AppTraffic
import io.github.rudolfhk.traffical.core.analysis.DashboardData
import io.github.rudolfhk.traffical.core.analysis.Format
import io.github.rudolfhk.traffical.core.analysis.TimeRange
import io.github.rudolfhk.traffical.model.AppInfo

/**
 * Overview: totals and live throughput of the selected time range and all apps ranked by
 * traffic (or connections). [header] shows the capture status and controls.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    data: DashboardData,
    appInfo: (Int) -> AppInfo,
    onRangeChange: (TimeRange) -> Unit,
    onAppClick: (Int) -> Unit,
    header: @Composable () -> Unit,
    modifier: Modifier = Modifier,
) {
    val text = LocalUiText.current
    var byConnections by rememberSaveable { mutableStateOf(false) }
    val apps = remember(data.apps, byConnections) {
        if (byConnections) data.apps.sortedByDescending { it.connections } else data.apps
    }
    val maxBytes = data.apps.maxOfOrNull { it.bytes } ?: 0L

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { header() }
        item { RangeChips(data.range, onRangeChange, Modifier.padding(horizontal = 16.dp)) }
        item {
            Row(Modifier.padding(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatTile(
                    label = text.statSent,
                    value = Format.bytes(data.totals.bytesOut),
                    detail = Format.rate(data.rate.bytesOut),
                    modifier = Modifier.weight(1f),
                )
                StatTile(
                    label = text.statReceived,
                    value = Format.bytes(data.totals.bytesIn),
                    detail = Format.rate(data.rate.bytesIn),
                    modifier = Modifier.weight(1f),
                )
            }
        }
        item {
            Row(Modifier.padding(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatTile(
                    label = text.statConnections,
                    value = data.connections.toString(),
                    detail = null,
                    modifier = Modifier.weight(1f),
                )
                StatTile(
                    label = text.statAttention,
                    value = data.attention.toString(),
                    detail = null,
                    modifier = Modifier.weight(1f),
                    highlight = data.attention > 0,
                )
            }
        }
        item {
            Card(Modifier.padding(horizontal = 16.dp).fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(text.chartThroughput, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                        Text(text.statSent, style = MaterialTheme.typography.labelSmall, color = sentColor())
                        Text(
                            text = text.statReceived,
                            style = MaterialTheme.typography.labelSmall,
                            color = receivedColor(),
                            modifier = Modifier.padding(start = 8.dp),
                        )
                    }
                    ThroughputChart(data.series, Modifier.padding(top = 8.dp).fillMaxWidth().height(120.dp))
                }
            }
        }
        item {
            Row(
                Modifier.padding(horizontal = 16.dp).fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(text.appsByTraffic, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                FilterChip(selected = !byConnections, onClick = { byConnections = false }, label = { Text(text.sortByData) })
                FilterChip(selected = byConnections, onClick = { byConnections = true }, label = { Text(text.sortByConnections) })
            }
        }
        if (apps.isEmpty()) {
            item {
                Text(
                    text = text.emptyList,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
            }
        }
        items(apps, key = { it.uid }) { traffic ->
            AppRow(traffic, appInfo(traffic.uid), maxBytes, onClick = { onAppClick(traffic.uid) })
        }
    }
}

@Composable
private fun AppRow(traffic: AppTraffic, app: AppInfo, maxBytes: Long, onClick: () -> Unit) {
    val text = LocalUiText.current
    Column(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 6.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = app.label,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            Text(Format.bytes(traffic.bytes), style = MaterialTheme.typography.titleSmall)
        }
        TrafficBar(traffic.bytesOut, traffic.bytesIn, maxBytes, Modifier.padding(vertical = 4.dp))
        Row {
            Text(
                text = "↑ ${Format.bytes(traffic.bytesOut)}  ↓ ${Format.bytes(traffic.bytesIn)} · " +
                    text.appSummary.format(traffic.connections, traffic.domains),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            if (traffic.rate > 0) {
                Text(
                    text = Format.rate(traffic.rate),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }
        if (traffic.attention > 0) {
            Text(
                text = text.appAttention.format(traffic.attention),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
    }
}
