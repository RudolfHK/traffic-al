package io.github.rudolfhk.traffical.ui.common

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.fillMaxWidth
import io.github.rudolfhk.traffical.model.DnsEvent
import java.time.Instant

/** DNS lookups of all apps, newest first, with a text filter. */
@Composable
fun DnsScreen(events: List<DnsEvent>, query: String, onQueryChange: (String) -> Unit, modifier: Modifier = Modifier) {
    val text = LocalUiText.current
    val words = query.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
    val shown = remember(events, query) {
        if (words.isEmpty()) {
            events
        } else {
            events.filter { event ->
                val fields = listOfNotNull(event.app.label, event.app.packageName, event.domain) + event.answers
                words.all { word -> fields.any { it.contains(word, ignoreCase = true) } }
            }
        }
    }

    Column(modifier.fillMaxSize()) {
        OutlinedTextField(
            value = query,
            onValueChange = onQueryChange,
            label = { Text(text.filterHint) },
            singleLine = true,
            modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 8.dp).fillMaxWidth(),
        )
        if (shown.isEmpty()) {
            Text(
                text = text.emptyList,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(16.dp),
            )
        }
        LazyColumn(Modifier.fillMaxSize()) {
            items(shown, key = { it.id }) { event ->
                Column(Modifier.padding(horizontal = 16.dp, vertical = 6.dp)) {
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
                    Text(event.domain, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
                    Text(
                        text = "${event.queryType} → ${resultText(event)}" +
                            (event.latencyMillis?.let { " · $it ms" } ?: ""),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Divider()
            }
        }
    }
}

@Composable
private fun resultText(event: DnsEvent): String = when (event.rcode) {
    0 -> event.answers.joinToString(", ").ifEmpty { LocalUiText.current.dnsEmpty }
    1 -> "FORMERR"
    2 -> "SERVFAIL"
    3 -> "NXDOMAIN"
    5 -> "REFUSED"
    else -> "RCODE ${event.rcode}"
}
