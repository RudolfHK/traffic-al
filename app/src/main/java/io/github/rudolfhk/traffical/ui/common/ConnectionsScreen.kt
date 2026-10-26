package io.github.rudolfhk.traffical.ui.common

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.rudolfhk.traffical.core.analysis.ATTENTION_FLAGS
import io.github.rudolfhk.traffical.core.analysis.ConnectionFilter
import io.github.rudolfhk.traffical.core.analysis.FlowFlag
import io.github.rudolfhk.traffical.core.analysis.Format
import io.github.rudolfhk.traffical.core.analysis.flags
import io.github.rudolfhk.traffical.core.analysis.protocolLabel
import io.github.rudolfhk.traffical.model.Connection
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

internal val timeFormat: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault())

/** nDPI's category name for "no category". */
private const val UNSPECIFIED_CATEGORY = "Unspecified"

/** All connections with search, quick filters and highlighting of the ones that need attention. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectionsScreen(
    connections: List<Connection>,
    filter: ConnectionFilter,
    onFilterChange: (ConnectionFilter) -> Unit,
    onConnectionClick: (Connection) -> Unit,
    nowMicros: Long,
    modifier: Modifier = Modifier,
) {
    val text = LocalUiText.current
    val shown = remember(connections, filter, nowMicros) {
        connections.filter { filter.matches(it.flow, it.app.label, it.app.packageName, nowMicros) }
    }
    // The most frequent protocols become quick filters.
    val protocols = remember(connections) {
        connections.groupingBy { it.flow.protocolLabel }.eachCount().entries
            .sortedByDescending { it.value }.take(6).map { it.key }
    }
    val filteredApp = filter.uid?.let { uid -> connections.firstOrNull { it.app.uid == uid }?.app }

    Column(modifier.fillMaxSize()) {
        OutlinedTextField(
            value = filter.text,
            onValueChange = { onFilterChange(filter.copy(text = it)) },
            label = { Text(text.filterHint) },
            singleLine = true,
            modifier = Modifier.padding(horizontal = 16.dp).fillMaxWidth(),
        )
        LazyRow(
            modifier = Modifier.padding(top = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            contentPadding = PaddingValues(horizontal = 16.dp),
        ) {
            if (filteredApp != null) {
                item {
                    FilterChip(
                        selected = true,
                        onClick = { onFilterChange(filter.copy(uid = null)) },
                        label = { Text(text.filterApp.format(filteredApp.label) + "  ✕") },
                    )
                }
            }
            item {
                FilterChip(
                    selected = filter.attentionOnly,
                    onClick = { onFilterChange(filter.copy(attentionOnly = !filter.attentionOnly)) },
                    label = { Text(text.filterAttention) },
                )
            }
            items(protocols) { protocol ->
                FilterChip(
                    selected = filter.protocol == protocol,
                    onClick = { onFilterChange(filter.copy(protocol = if (filter.protocol == protocol) null else protocol)) },
                    label = { Text(protocol) },
                )
            }
        }
        RangeChips(
            selected = filter.timeRange,
            onSelect = { onFilterChange(filter.copy(timeRange = it)) },
            modifier = Modifier.padding(top = 4.dp, start = 16.dp, end = 16.dp),
        )
        Row(
            Modifier.padding(horizontal = 16.dp).fillMaxWidth().heightIn(min = 48.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = text.filterCount.format(shown.size, connections.size),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
            if (filter != ConnectionFilter()) {
                TextButton(onClick = { onFilterChange(ConnectionFilter()) }) { Text(text.filterClear) }
            }
        }
        if (shown.isEmpty()) {
            Text(
                text = text.emptyList,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(16.dp),
            )
        }
        LazyColumn(Modifier.fillMaxSize()) {
            items(shown, key = { it.flow.id }) { connection ->
                ConnectionRow(connection, onClick = { onConnectionClick(connection) })
                Divider()
            }
        }
    }
}

@Composable
private fun ConnectionRow(connection: Connection, onClick: () -> Unit) {
    val flow = connection.flow
    val flags = flow.flags()
    val attention = flags.firstOrNull { it in ATTENTION_FLAGS }
    val stripe = if (attention != null) flagColor(attention) else Color.Transparent
    val domain = flow.domain

    Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min).clickable(onClick = onClick)) {
        Box(Modifier.width(4.dp).fillMaxHeight().background(stripe))
        Column(Modifier.padding(start = 12.dp, end = 16.dp, top = 6.dp, bottom = 6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier.weight(1f),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
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
                    FlagBadges(flags)
                }
                Text(
                    text = "↑ ${Format.bytes(flow.bytesOut)}  ↓ ${Format.bytes(flow.bytesIn)}",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                )
            }
            Text(
                text = domain ?: flow.remoteAddress.hostAddress.orEmpty(),
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                fontWeight = if (attention != null) FontWeight.SemiBold else FontWeight.Normal,
                color = if (attention == FlowFlag.TRACKER || attention == FlowFlag.RISKY) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurface
                },
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = listOfNotNull(
                    flow.appProtocol ?: flow.protocolLabel,
                    flow.category?.takeUnless { it == UNSPECIFIED_CATEGORY },
                    endpoint(flow.remoteAddress.hostAddress.orEmpty(), flow.remotePort),
                ).joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

internal fun endpoint(host: String, port: Int) = if (':' in host) "[$host]:$port" else "$host:$port"
