package io.github.rudolfhk.traffical.ui.common

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.github.rudolfhk.traffical.core.analysis.Format
import io.github.rudolfhk.traffical.core.analysis.OTHER_SHARE_LABEL
import io.github.rudolfhk.traffical.core.analysis.TrafficShare
import kotlin.math.roundToInt

/**
 * The chart series palette: blue first, dark orange second (phase 14). These are the data-viz
 * reference ramps, with their own steps for the light and dark surfaces — not an automatic flip —
 * so the eight categorical slots stay distinguishable for colour-blind readers on each surface.
 * Validated against the app's surfaces with the data-viz validator (see docs/VISUALIZATION.md);
 * a chart never needs more than the leading few slots because the aggregates fold their tail into
 * a single muted "Other" slice.
 */
object VizPalette {
    private val light = listOf(
        Color(0xFF2A78D6), // blue
        Color(0xFFEB6834), // orange
        Color(0xFF1BAF7A), // aqua
        Color(0xFFEDA100), // yellow
        Color(0xFFE87BA4), // magenta
        Color(0xFF008300), // green
        Color(0xFF6250D6), // violet
        Color(0xFFE34948), // red
    )
    private val dark = listOf(
        Color(0xFF3987E5),
        Color(0xFFD95926),
        Color(0xFF199E70),
        Color(0xFFC98500),
        Color(0xFFD55181),
        Color(0xFF0CA30C),
        Color(0xFF9085E9),
        Color(0xFFE66767),
    )

    fun slots(dark: Boolean): List<Color> = if (dark) this.dark else this.light
}

/** True when the current theme is dark, judged from the surface colour (works in app and preview). */
@Composable
fun chartIsDark(): Boolean = MaterialTheme.colorScheme.surface.luminance() < 0.5f

/** Categorical chart colour [index], wrapping around the palette's slots. */
@Composable
fun vizColor(index: Int): Color {
    val slots = VizPalette.slots(chartIsDark())
    return slots[((index % slots.size) + slots.size) % slots.size]
}

/**
 * A chart in its card: a title, a tap-to-reveal "ⓘ" hint toggle, an always-visible one-line
 * [caption] (what it shows / how to read it), the [content], and the [hint] underneath when
 * revealed. Every chart ships through this so none is without its reading instructions (phase 14).
 */
@Composable
fun ChartCard(
    title: String,
    caption: String,
    hint: String,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    var showHint by rememberSaveable(title) { mutableStateOf(false) }
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                Text(
                    text = if (showHint) "ⓘ ${LocalUiText.current.chartHintHide}" else "ⓘ",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier
                        .clip(RoundedCornerShape(4.dp))
                        .clickable { showHint = !showHint }
                        .padding(horizontal = 6.dp, vertical = 2.dp),
                )
            }
            content()
            Text(
                text = caption,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (showHint) {
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.surface,
                ) {
                    Text(
                        text = hint,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(10.dp),
                    )
                }
            }
        }
    }
}

/** A row of colour swatches with labels, in ink tokens (identity is never colour-alone). */
@Composable
fun LegendRow(entries: List<Pair<String, Color>>, modifier: Modifier = Modifier) {
    Row(modifier, horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
        for ((label, color) in entries) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                Box(Modifier.size(10.dp).clip(RoundedCornerShape(3.dp)).background(color))
                Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

/**
 * A 100%-stacked distribution of [shares] (largest first, the "Other" slice last and muted): a
 * segmented bar with 2px surface gaps, and below it a legend that spells out each slice's share,
 * bytes and connection count — the direct value labels that are the relief for the light-surface
 * contrast of some palette slots. Weights the bar by bytes, or by connections when
 * [weightByBytes] is false (falling back to connections when every slice has zero bytes).
 */
@Composable
fun DistributionChart(
    shares: List<TrafficShare>,
    modifier: Modifier = Modifier,
    weightByBytes: Boolean = true,
) {
    if (shares.isEmpty()) return
    val slots = VizPalette.slots(chartIsDark())
    val other = MaterialTheme.colorScheme.outline
    val colors = shares.mapIndexed { i, share ->
        if (share.label == OTHER_SHARE_LABEL) other else slots[i % slots.size]
    }
    val useBytes = weightByBytes && shares.any { it.bytes > 0 }
    val weights = shares.map { (if (useBytes) it.bytes else it.connections.toLong()).coerceAtLeast(0L) }
    val total = weights.sum()

    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Canvas(
            Modifier.fillMaxWidth().height(16.dp).clip(RoundedCornerShape(4.dp))
                .background(MaterialTheme.colorScheme.surface),
        ) {
            if (total <= 0L) return@Canvas
            val gap = 2.dp.toPx()
            var x = 0f
            weights.forEachIndexed { i, w ->
                val segEnd = x + size.width * (w.toFloat() / total)
                // Full width for the last slice so rounding never leaves a sliver of track.
                val right = (if (i == weights.lastIndex) size.width else segEnd - gap).coerceAtMost(size.width)
                if (right > x) drawRect(colors[i], topLeft = Offset(x, 0f), size = Size(right - x, size.height))
                x = segEnd
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
            for ((i, share) in shares.withIndex()) {
                val percent = if (total <= 0L) 0 else (weights[i] * 100.0 / total).roundToInt()
                DistributionLegendRow(share, colors[i], percent)
            }
        }
    }
}

@Composable
private fun DistributionLegendRow(share: TrafficShare, color: Color, percent: Int) {
    val text = LocalUiText.current
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Box(Modifier.size(10.dp).clip(RoundedCornerShape(3.dp)).background(color))
        Text(
            text = share.label,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.weight(1f),
        )
        Text(
            text = "$percent%",
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            text = "${Format.bytes(share.bytes)} · ${count(share.connections, text.countConnection, text.countConnections)}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
