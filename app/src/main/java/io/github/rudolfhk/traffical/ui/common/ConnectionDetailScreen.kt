package io.github.rudolfhk.traffical.ui.common

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.rudolfhk.traffical.core.analysis.FlowPacket
import io.github.rudolfhk.traffical.core.analysis.Format
import io.github.rudolfhk.traffical.core.analysis.HexDump
import io.github.rudolfhk.traffical.core.analysis.flags
import io.github.rudolfhk.traffical.core.analysis.protocolLabel
import io.github.rudolfhk.traffical.core.capture.Direction
import io.github.rudolfhk.traffical.core.packet.TcpFlags
import io.github.rudolfhk.traffical.model.Connection
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val dateTimeFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault())
private val packetTimeFormat = DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault())

/** Bytes per hex dump line: 8 keep the ASCII column on a phone screen. */
private const val DUMP_WIDTH = 8

/** Lines of hex dump shown per packet before it is expanded. */
private const val COLLAPSED_DUMP_LINES = 6

/**
 * Everything known about one connection and its packets from the capture buffer, with a
 * hex dump of each payload. [packets] is null while they are being loaded.
 */
@Composable
fun ConnectionDetailScreen(connection: Connection, packets: List<FlowPacket>?, modifier: Modifier = Modifier) {
    val text = LocalUiText.current
    val flow = connection.flow
    val durationMicros = flow.lastSeenMicros - flow.firstSeenMicros
    val rate = if (durationMicros > 0) (flow.bytesOut + flow.bytesIn) * 1_000_000 / durationMicros else 0L
    val encrypted = flow.protocolLabel == "TLS" || flow.protocolLabel == "QUIC"

    val rows = listOfNotNull(
        text.detailApp to listOfNotNull(connection.app.label, connection.app.packageName).joinToString("\n"),
        flow.domain?.let { text.detailDomain to it },
        flow.sni?.let { text.detailSni to it },
        flow.serverName?.let { text.detailServerName to it },
        flow.dnsName?.let { text.detailDnsName to it },
        text.detailProtocol to (flow.appProtocol ?: flow.protocolLabel),
        flow.category?.let { text.detailCategory to it },
        flow.breed?.let { text.detailRating to it },
        text.detailRemote to endpoint(flow.remoteAddress.hostAddress.orEmpty(), flow.remotePort),
        text.detailLocal to endpoint(flow.localAddress.hostAddress.orEmpty(), flow.localPort),
        text.detailStarted to dateTimeFormat.format(Instant.ofEpochMilli(flow.firstSeenMicros / 1000)),
        text.detailDuration to Format.duration(durationMicros),
        text.detailSent to "${Format.bytes(flow.bytesOut)} · ${flow.packetsOut} ${text.detailPackets.lowercase()}",
        text.detailReceived to "${Format.bytes(flow.bytesIn)} · ${flow.packetsIn} ${text.detailPackets.lowercase()}",
        text.detailRate to Format.rate(rate),
        text.detailState to if (flow.closed) text.detailStateClosed else text.detailStateOpen,
    )

    LazyColumn(modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item {
            Column(Modifier.padding(horizontal = 16.dp)) {
                Text(
                    text = flow.domain ?: flow.remoteAddress.hostAddress.orEmpty(),
                    style = MaterialTheme.typography.titleLarge,
                    fontFamily = FontFamily.Monospace,
                )
                FlagBadges(flow.flags(), Modifier.padding(top = 4.dp))
            }
        }
        item {
            Card(Modifier.padding(horizontal = 16.dp).fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    for ((label, value) in rows) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                text = label,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.weight(0.35f),
                            )
                            Text(value, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(0.65f))
                        }
                    }
                }
            }
        }
        item {
            Text(
                text = "${text.detailPackets} (${packets?.size ?: "…"})",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(horizontal = 16.dp),
            )
            if (encrypted) {
                Text(
                    text = text.detailEncryptedHint,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
            }
        }
        when {
            packets == null -> item { CircularProgressIndicator(Modifier.padding(16.dp)) }
            packets.isEmpty() -> item {
                Text(
                    text = text.detailNoPackets,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
            }
            else -> items(packets) { packet -> PacketCard(packet) }
        }
    }
}

@Composable
private fun PacketCard(packet: FlowPacket) {
    val text = LocalUiText.current
    var expanded by remember { mutableStateOf(false) }
    val dump = remember(packet) { HexDump.lines(packet.payload, width = DUMP_WIDTH) }
    val outgoing = packet.direction == Direction.OUT

    Card(
        modifier = Modifier
            .padding(horizontal = 16.dp)
            .fillMaxWidth()
            .clickable(enabled = dump.size > COLLAPSED_DUMP_LINES) { expanded = !expanded },
        colors = CardDefaults.cardColors(
            containerColor = if (outgoing) {
                MaterialTheme.colorScheme.primaryContainer
            } else {
                MaterialTheme.colorScheme.surfaceVariant
            },
        ),
    ) {
        Column(Modifier.padding(horizontal = 10.dp, vertical = 6.dp)) {
            Text(
                text = listOfNotNull(
                    packetTimeFormat.format(Instant.ofEpochMilli(packet.timestampMicros / 1000)),
                    if (outgoing) "→" else "←",
                    Format.bytes(packet.length.toLong()),
                    tcpFlagNames(packet.tcpFlags).ifEmpty { null },
                    if (packet.payload.isNotEmpty()) text.detailPayload.format(packet.payload.size) else null,
                ).joinToString("  "),
                style = MaterialTheme.typography.labelMedium,
                fontFamily = FontFamily.Monospace,
            )
            val shown = if (expanded) dump else dump.take(COLLAPSED_DUMP_LINES)
            for (line in shown) {
                Text(line, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace, maxLines = 1)
            }
            if (!expanded && dump.size > COLLAPSED_DUMP_LINES) {
                Text("… +${dump.size - COLLAPSED_DUMP_LINES}", style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

private fun tcpFlagNames(flags: Int): String = listOfNotNull(
    "SYN".takeIf { flags and TcpFlags.SYN != 0 },
    "ACK".takeIf { flags and TcpFlags.ACK != 0 },
    "PSH".takeIf { flags and TcpFlags.PSH != 0 },
    "FIN".takeIf { flags and TcpFlags.FIN != 0 },
    "RST".takeIf { flags and TcpFlags.RST != 0 },
).joinToString(" ")
