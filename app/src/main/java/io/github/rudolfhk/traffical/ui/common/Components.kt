package io.github.rudolfhk.traffical.ui.common

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.github.rudolfhk.traffical.core.analysis.Format
import io.github.rudolfhk.traffical.core.analysis.FlowFlag
import io.github.rudolfhk.traffical.core.analysis.TimeRange
import io.github.rudolfhk.traffical.core.analysis.TrafficPoint

enum class Tab { DASHBOARD, CONNECTIONS, DNS, SETTINGS }

/** App frame: top bar (with back navigation for detail screens) and bottom navigation. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrafficAlScaffold(
    tab: Tab,
    onTabSelected: (Tab) -> Unit,
    title: String,
    onBack: (() -> Unit)?,
    content: @Composable (PaddingValues) -> Unit,
) {
    val text = LocalUiText.current
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    if (onBack != null) {
                        IconButton(onClick = onBack) {
                            Icon(Icons.Filled.ArrowBack, contentDescription = text.actionBack)
                        }
                    }
                },
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = tab == Tab.DASHBOARD,
                    onClick = { onTabSelected(Tab.DASHBOARD) },
                    icon = { Icon(Icons.Filled.Home, contentDescription = null) },
                    label = { Text(text.tabDashboard) },
                )
                NavigationBarItem(
                    selected = tab == Tab.CONNECTIONS,
                    onClick = { onTabSelected(Tab.CONNECTIONS) },
                    icon = { Icon(Icons.Filled.List, contentDescription = null) },
                    label = { Text(text.tabConnections) },
                )
                NavigationBarItem(
                    selected = tab == Tab.DNS,
                    onClick = { onTabSelected(Tab.DNS) },
                    icon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    label = { Text(text.tabDns) },
                )
                NavigationBarItem(
                    selected = tab == Tab.SETTINGS,
                    onClick = { onTabSelected(Tab.SETTINGS) },
                    icon = { Icon(Icons.Filled.Settings, contentDescription = null) },
                    label = { Text(text.tabSettings) },
                )
            }
        },
        content = content,
    )
}

@Composable
fun rangeLabel(range: TimeRange): String {
    val text = LocalUiText.current
    return when (range) {
        TimeRange.MINUTE -> text.rangeMinute
        TimeRange.FIVE_MINUTES -> text.rangeFiveMinutes
        TimeRange.FIFTEEN_MINUTES -> text.rangeFifteenMinutes
        TimeRange.HOUR -> text.rangeHour
        TimeRange.ALL -> text.rangeAll
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RangeChips(selected: TimeRange, onSelect: (TimeRange) -> Unit, modifier: Modifier = Modifier) {
    LazyRow(modifier = modifier, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        items(TimeRange.values().toList()) { range ->
            FilterChip(
                selected = range == selected,
                onClick = { onSelect(range) },
                label = { Text(rangeLabel(range)) },
            )
        }
    }
}

@Composable
fun StatTile(label: String, value: String, detail: String?, modifier: Modifier = Modifier, highlight: Boolean = false) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(
            containerColor = if (highlight) {
                MaterialTheme.colorScheme.errorContainer
            } else {
                MaterialTheme.colorScheme.surfaceVariant
            },
        ),
    ) {
        Column(Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
            Text(label, style = MaterialTheme.typography.labelMedium, maxLines = 1)
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, maxLines = 1)
            if (detail != null) Text(detail, style = MaterialTheme.typography.bodySmall, maxLines = 1)
        }
    }
}

/** Colors of the two traffic directions in charts and bars. */
@Composable
fun sentColor(): Color = MaterialTheme.colorScheme.primary

@Composable
fun receivedColor(): Color = MaterialTheme.colorScheme.tertiary

/** Area chart of sent and received bytes per interval. */
@Composable
fun ThroughputChart(series: List<TrafficPoint>, modifier: Modifier = Modifier) {
    val out = sentColor()
    val incoming = receivedColor()
    val grid = MaterialTheme.colorScheme.outlineVariant
    val peak = series.maxOfOrNull { maxOf(it.bytesOut, it.bytesIn) } ?: 0L
    val stepSeconds = if (series.size >= 2) (series[1].startMillis - series[0].startMillis) / 1000 else 1L

    // The peak rate labels the top grid line; the plot is scaled so the peak touches it.
    Column(modifier) {
        Text(
            text = Format.rate(peak / maxOf(1L, stepSeconds)),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.align(Alignment.End),
        )
        Canvas(Modifier.fillMaxWidth().weight(1f)) {
            val inset = 2.dp.toPx()
            val plotHeight = size.height - inset
            for (i in 0..3) {
                val y = inset + plotHeight * i / 4
                drawLine(grid, Offset(0f, y), Offset(size.width, y), strokeWidth = 1f)
            }
            if (series.size < 2 || peak == 0L) return@Canvas
            fun area(values: List<Long>, color: Color) {
                val dx = size.width / (values.size - 1)
                val line = Path()
                values.forEachIndexed { i, v ->
                    val x = i * dx
                    val y = size.height - plotHeight * v / peak.toFloat()
                    if (i == 0) line.moveTo(x, y) else line.lineTo(x, y)
                }
                val fill = Path().apply {
                    addPath(line)
                    lineTo(size.width, size.height)
                    lineTo(0f, size.height)
                    close()
                }
                drawPath(fill, color.copy(alpha = 0.18f))
                drawPath(line, color, style = Stroke(width = 2.dp.toPx()))
            }
            area(series.map { it.bytesIn }, incoming)
            area(series.map { it.bytesOut }, out)
        }
    }
}

/** Horizontal share bar: sent and received parts of [total] relative to [max]. */
@Composable
fun TrafficBar(bytesOut: Long, bytesIn: Long, max: Long, modifier: Modifier = Modifier) {
    val out = sentColor()
    val incoming = receivedColor()
    val track = MaterialTheme.colorScheme.surfaceVariant
    Canvas(modifier.height(6.dp).fillMaxWidth().clip(RoundedCornerShape(3.dp)).background(track)) {
        if (max <= 0) return@Canvas
        val outWidth = size.width * bytesOut / max.toFloat()
        val inWidth = size.width * bytesIn / max.toFloat()
        drawRect(out, size = size.copy(width = outWidth))
        drawRect(incoming, topLeft = Offset(outWidth, 0f), size = size.copy(width = inWidth))
    }
}

@Composable
fun flagLabel(flag: FlowFlag): String {
    val text = LocalUiText.current
    return when (flag) {
        FlowFlag.TRACKER -> text.flagTracker
        FlowFlag.RISKY -> text.flagRisky
        FlowFlag.UNNAMED -> text.flagUnnamed
        FlowFlag.ENCRYPTED_DNS -> text.badgeEncryptedDns
        FlowFlag.BLOCKED -> text.badgeBlocked
    }
}

@Composable
fun flagColor(flag: FlowFlag): Color = when (flag) {
    FlowFlag.TRACKER, FlowFlag.RISKY -> MaterialTheme.colorScheme.error
    FlowFlag.UNNAMED -> MaterialTheme.colorScheme.tertiary
    FlowFlag.ENCRYPTED_DNS, FlowFlag.BLOCKED -> MaterialTheme.colorScheme.outline
}

@Composable
fun FlagBadges(flags: Set<FlowFlag>, modifier: Modifier = Modifier) {
    Row(modifier, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        for (flag in FlowFlag.values()) {
            if (flag in flags) LabelBadge(flagLabel(flag), flagColor(flag))
        }
    }
}

/** Small tinted label, e.g. "tracker" or "recording". */
@Composable
fun LabelBadge(label: String, color: Color) {
    Surface(color = color.copy(alpha = 0.14f), contentColor = color, shape = RoundedCornerShape(4.dp)) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 1.dp),
            maxLines = 1,
        )
    }
}

/** "1 app", "3 apps": [one] and [other] are format strings with the count as %1$d. */
internal fun count(n: Int, one: String, other: String): String = (if (n == 1) one else other).format(n)
