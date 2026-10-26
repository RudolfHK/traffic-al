package io.github.rudolfhk.traffical.ui

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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.rudolfhk.traffical.R
import io.github.rudolfhk.traffical.capture.AppInfo
import io.github.rudolfhk.traffical.capture.CaptureRepository
import io.github.rudolfhk.traffical.capture.CaptureStatus
import io.github.rudolfhk.traffical.capture.DnsEvent
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault())

private data class AppSummary(val app: AppInfo, val queries: Int, val domains: Int)

@Composable
fun MainScreen(
    onStart: () -> Unit,
    onStop: () -> Unit,
    onExport: () -> Unit,
    onClear: () -> Unit,
) {
    val status by CaptureRepository.status.collectAsStateWithLifecycle()
    val events by CaptureRepository.events.collectAsStateWithLifecycle()
    val packetCount by CaptureRepository.packetCount.collectAsStateWithLifecycle()
    var filter by rememberSaveable { mutableStateOf("") }
    var tab by rememberSaveable { mutableIntStateOf(0) }

    val filtered = remember(events, filter) {
        val query = filter.trim()
        if (query.isEmpty()) events else events.filter { it.matches(query) }
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
            StatusCard(status, events.size, packetCount)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (status.running) {
                    Button(onClick = onStop) { Text(stringResource(R.string.action_stop)) }
                } else {
                    Button(onClick = onStart) { Text(stringResource(R.string.action_start)) }
                }
                OutlinedButton(onClick = onExport, enabled = packetCount > 0) {
                    Text(stringResource(R.string.action_export))
                }
                TextButton(onClick = onClear, enabled = events.isNotEmpty() || packetCount > 0) {
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
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text(stringResource(R.string.tab_queries)) })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text(stringResource(R.string.tab_apps)) })
            }
            if (filtered.isEmpty()) {
                Text(
                    text = stringResource(R.string.empty_list),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 16.dp),
                )
            } else if (tab == 0) {
                QueryList(filtered)
            } else {
                AppList(filtered) { selected ->
                    filter = selected
                    tab = 0
                }
            }
        }
    }
}

@Composable
private fun StatusCard(status: CaptureStatus, eventCount: Int, packetCount: Int) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(if (status.running) R.string.status_running else R.string.status_stopped),
                style = MaterialTheme.typography.titleMedium,
            )
            status.errorRes?.let {
                Text(stringResource(it), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
            }
            Text(stringResource(R.string.status_counts, eventCount, packetCount), style = MaterialTheme.typography.bodyMedium)
            Text(
                text = stringResource(R.string.status_mode_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun QueryList(events: List<DnsEvent>) {
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
                    text = "${event.queryType} → ${resultText(event)} · ${event.latencyMillis} ms",
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
private fun AppList(events: List<DnsEvent>, onSelect: (String) -> Unit) {
    val summaries = remember(events) {
        events.groupBy { it.app.uid }
            .map { (_, appEvents) ->
                AppSummary(appEvents.first().app, appEvents.size, appEvents.distinctBy { it.domain }.size)
            }
            .sortedByDescending { it.queries }
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
                    text = (summary.app.packageName ?: "uid ${summary.app.uid}") + " · " +
                        stringResource(R.string.app_summary, summary.queries, summary.domains),
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
    null -> stringResource(R.string.dns_no_response)
    0 -> event.answers.joinToString(", ").ifEmpty { stringResource(R.string.dns_empty) }
    1 -> "FORMERR"
    2 -> "SERVFAIL"
    3 -> "NXDOMAIN"
    5 -> "REFUSED"
    else -> "RCODE ${event.rcode}"
}

private fun DnsEvent.matches(query: String): Boolean =
    app.label.contains(query, ignoreCase = true) ||
        app.packageName?.contains(query, ignoreCase = true) == true ||
        domain.contains(query, ignoreCase = true) ||
        answers.any { it.contains(query, ignoreCase = true) }
