package io.github.rudolfhk.traffical.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.github.rudolfhk.traffical.capture.RecordingView
import io.github.rudolfhk.traffical.capture.TlsPlaintext
import io.github.rudolfhk.traffical.core.analysis.ConnectionFilter
import io.github.rudolfhk.traffical.core.analysis.FlowPacket
import io.github.rudolfhk.traffical.core.analysis.Format
import io.github.rudolfhk.traffical.core.analysis.TimeRange
import io.github.rudolfhk.traffical.enrichment.OwnerLookup
import io.github.rudolfhk.traffical.ui.common.ConnectionDetailScreen
import io.github.rudolfhk.traffical.ui.common.ConnectionsScreen
import io.github.rudolfhk.traffical.ui.common.DashboardScreen
import io.github.rudolfhk.traffical.ui.common.DnsScreen
import io.github.rudolfhk.traffical.ui.common.LocalUiText
import io.github.rudolfhk.traffical.ui.common.OwnerState
import io.github.rudolfhk.traffical.ui.common.Tab
import io.github.rudolfhk.traffical.ui.common.TrafficAlScaffold
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val startFormat = DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm").withZone(ZoneId.systemDefault())
private val endFormat = DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.systemDefault())

private val recordingFilterSaver: Saver<ConnectionFilter, Any> = listSaver<ConnectionFilter, Any?>(
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

/**
 * Browses a saved recording with the same dashboard, connections, DNS and detail screens
 * as the live capture (see [RecordingView]). It has its own navigation; [onClose] returns
 * to the recordings list.
 */
@Composable
fun RecordingViewer(view: RecordingView, onClose: () -> Unit, modifier: Modifier = Modifier) {
    val text = LocalUiText.current
    var tab by rememberSaveable { mutableStateOf(Tab.DASHBOARD) }
    var range by rememberSaveable { mutableStateOf(TimeRange.ALL) }
    var filter by rememberSaveable(stateSaver = recordingFilterSaver) { mutableStateOf(ConnectionFilter(timeRange = TimeRange.ALL)) }
    var dnsQuery by rememberSaveable { mutableStateOf("") }
    var detailId by rememberSaveable { mutableStateOf<Long?>(null) }

    val connections = view.connections
    val detail = detailId?.let { id -> connections.firstOrNull { it.flow.id == id } }

    BackHandler(enabled = detail != null) { detailId = null }
    BackHandler(enabled = detail == null) { onClose() }

    TrafficAlScaffold(
        tab = tab,
        onTabSelected = { tab = it; detailId = null },
        title = if (detail != null) detail.app.label else period(view),
        onBack = if (detail != null) ({ detailId = null }) else onClose,
        tabs = setOf(Tab.DASHBOARD, Tab.CONNECTIONS, Tab.DNS),
    ) { padding ->
        val screen = modifier.then(Modifier.padding(padding))
        when {
            detail != null -> {
                var packets by remember(detail.flow.id) { mutableStateOf<List<FlowPacket>?>(null) }
                var decrypted by remember(detail.flow.id) { mutableStateOf<TlsPlaintext.Result?>(null) }
                LaunchedEffect(detail.flow.id) {
                    val loaded = withContext(Dispatchers.Default) { view.packetsOf(detail) }
                    packets = loaded
                    decrypted = withContext(Dispatchers.Default) { TlsPlaintext.of(loaded, detail.flow) }
                }
                var owner by remember(detail.flow.id) { mutableStateOf(OwnerState()) }
                val scope = rememberCoroutineScope()
                ConnectionDetailScreen(
                    connection = detail,
                    packets = packets,
                    owner = owner,
                    onLookupOwner = {
                        owner = OwnerState(loading = true)
                        scope.launch {
                            val info = withContext(Dispatchers.IO) { OwnerLookup.lookup(detail.flow.remoteAddress) }
                            owner = OwnerState(info = info)
                        }
                    },
                    modifier = screen,
                    decryptedRequest = decrypted?.toServer,
                    decryptedResponse = decrypted?.toClient,
                )
            }
            tab == Tab.CONNECTIONS -> ConnectionsScreen(
                connections = connections,
                filter = filter,
                onFilterChange = { filter = it },
                onConnectionClick = { detailId = it.flow.id },
                nowMicros = view.referenceMicros(),
                modifier = screen,
            )
            tab == Tab.DNS -> DnsScreen(view.dnsEvents, dnsQuery, { dnsQuery = it }, screen)
            else -> {
                val data = remember(range) { view.dashboard(range) }
                DashboardScreen(
                    data = data,
                    appInfo = view::appInfo,
                    onRangeChange = { range = it },
                    onAppClick = { uid ->
                        filter = ConnectionFilter(uid = uid, timeRange = range)
                        tab = Tab.CONNECTIONS
                    },
                    onTrackerClick = { company ->
                        filter = ConnectionFilter(text = company, timeRange = range, attentionOnly = true)
                        tab = Tab.CONNECTIONS
                    },
                    header = { RecordingInfoCard(view) },
                    modifier = screen,
                )
            }
        }
    }
}

@Composable
private fun RecordingInfoCard(view: RecordingView) {
    val text = LocalUiText.current
    Card(Modifier.padding(horizontal = 16.dp).fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(period(view), style = MaterialTheme.typography.titleMedium)
            Text(
                text = listOf(
                    Format.duration((view.endMillis - view.startMillis) * 1000),
                    text.recordingViewPackets.format(view.packetCount),
                ).joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = text.recordingViewNote,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** Full-screen loading shown while a recording is read; back cancels it. */
@Composable
fun RecordingLoading(onCancel: () -> Unit, modifier: Modifier = Modifier) {
    val text = LocalUiText.current
    BackHandler(onBack = onCancel)
    TrafficAlScaffold(
        tab = Tab.DASHBOARD,
        onTabSelected = {},
        title = text.recordingLoading,
        onBack = onCancel,
        tabs = emptySet(),
    ) { padding ->
        Box(modifier.then(Modifier.padding(padding)).fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
    }
}

private fun period(view: RecordingView): String =
    "${startFormat.format(Instant.ofEpochMilli(view.startMillis))} – ${endFormat.format(Instant.ofEpochMilli(view.endMillis))}"
