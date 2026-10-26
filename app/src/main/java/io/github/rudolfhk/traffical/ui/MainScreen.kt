package io.github.rudolfhk.traffical.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
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
import io.github.rudolfhk.traffical.core.analysis.Format
import io.github.rudolfhk.traffical.core.analysis.TimeRange
import io.github.rudolfhk.traffical.model.BackgroundInfo
import io.github.rudolfhk.traffical.model.Connection
import io.github.rudolfhk.traffical.model.PrivacyInfo
import io.github.rudolfhk.traffical.model.RecorderStatus
import io.github.rudolfhk.traffical.model.RecordingItem
import io.github.rudolfhk.traffical.security.AppLock
import io.github.rudolfhk.traffical.settings.SettingsStore
import io.github.rudolfhk.traffical.ui.common.ConnectionDetailScreen
import io.github.rudolfhk.traffical.ui.common.ConnectionsScreen
import io.github.rudolfhk.traffical.ui.common.DashboardScreen
import io.github.rudolfhk.traffical.ui.common.DnsScreen
import io.github.rudolfhk.traffical.ui.common.LocalUiText
import io.github.rudolfhk.traffical.ui.common.RecordingsScreen
import io.github.rudolfhk.traffical.ui.common.SettingsScreen
import io.github.rudolfhk.traffical.ui.common.Tab
import io.github.rudolfhk.traffical.ui.common.TrafficAlScaffold
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** How often the dashboard is recomputed while visible. */
private const val DASHBOARD_REFRESH_MILLIS = 1_000L

/** How often the recordings list is reread while visible (a running one grows). */
private const val RECORDINGS_REFRESH_MILLIS = 2_000L

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

/** What the screens ask the activity to do: things that need an Activity or Intents. */
class MainActions(
    val start: () -> Unit,
    val stop: () -> Unit,
    val clear: () -> Unit,
    val switchPrivateDns: () -> Unit,
    val exportBuffer: () -> Unit,
    val exportRecording: (String) -> Unit,
    val requestBatteryExemption: () -> Unit,
    val openVpnSettings: () -> Unit,
    val backgroundInfo: () -> BackgroundInfo,
    val biometricAvailable: () -> Boolean,
    val authenticateBiometric: () -> Unit,
)

@Composable
fun MainScreen(actions: MainActions) {
    val status by CaptureRepository.status.collectAsStateWithLifecycle()
    val connections by CaptureRepository.connections.collectAsStateWithLifecycle()
    val dnsEvents by CaptureRepository.dnsEvents.collectAsStateWithLifecycle()
    val packetCount by CaptureRepository.packetCount.collectAsStateWithLifecycle()
    val recorder by CaptureRepository.recorderStatus.collectAsStateWithLifecycle()
    val settings by SettingsStore.settings.collectAsStateWithLifecycle()

    var tab by rememberSaveable { mutableStateOf(Tab.DASHBOARD) }
    var range by rememberSaveable { mutableStateOf(TimeRange.FIVE_MINUTES) }
    var filter by rememberSaveable(stateSaver = filterSaver) { mutableStateOf(ConnectionFilter()) }
    var dnsQuery by rememberSaveable { mutableStateOf("") }
    var showRecordings by rememberSaveable { mutableStateOf(false) }

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
    BackHandler(enabled = detail == null && showRecordings) { showRecordings = false }
    BackHandler(enabled = detail == null && !showRecordings && tab != Tab.DASHBOARD) { tab = Tab.DASHBOARD }

    val text = LocalUiText.current
    TrafficAlScaffold(
        tab = tab,
        onTabSelected = {
            tab = it
            detailId = null
            showRecordings = false
        },
        title = when {
            detail != null -> detail.app.label
            showRecordings -> text.recordingsTitle
            tab == Tab.CONNECTIONS -> text.tabConnections
            tab == Tab.DNS -> text.tabDns
            tab == Tab.SETTINGS -> text.tabSettings
            else -> text.appName
        },
        onBack = when {
            detail != null -> ({ detailId = null })
            showRecordings -> ({ showRecordings = false })
            else -> null
        },
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
            showRecordings -> {
                val scope = rememberCoroutineScope()
                var reload by remember { mutableIntStateOf(0) }
                val recordings = rememberRecordings(reload)
                RecordingsScreen(
                    recordings = recordings,
                    settings = settings,
                    recorder = recorder,
                    bufferPackets = packetCount,
                    onExport = { actions.exportRecording(it.name) },
                    onDelete = { recording ->
                        scope.launch {
                            withContext(Dispatchers.IO) { CaptureRepository.deleteRecording(recording.name) }
                            reload++
                        }
                    },
                    onExportBuffer = actions.exportBuffer,
                    modifier = modifier,
                )
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
                            recorder = recorder,
                            connectionCount = connections.size,
                            lookupCount = dnsEvents.size,
                            packetCount = packetCount,
                            actions = actions,
                            onShowRecordings = { showRecordings = true },
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
            tab == Tab.DNS -> DnsScreen(dnsEvents, dnsQuery, { dnsQuery = it }, modifier)
            else -> {
                // Battery optimization can change in the system settings: reread on resume.
                val lifecycle = LocalLifecycleOwner.current.lifecycle
                val lifecycleState by lifecycle.currentStateFlow.collectAsStateWithLifecycle()
                val background = remember(lifecycleState, status.alwaysOn) { actions.backgroundInfo() }
                val lock by AppLock.state.collectAsStateWithLifecycle()
                val biometricAvailable = remember(lifecycleState) { actions.biometricAvailable() }
                val scope = rememberCoroutineScope()
                SettingsScreen(
                    settings = settings,
                    background = background,
                    privacy = PrivacyInfo(lock.enabled, lock.biometric, biometricAvailable),
                    onChange = SettingsStore::update,
                    onRequestBatteryExemption = actions.requestBatteryExemption,
                    onOpenVpnSettings = actions.openVpnSettings,
                    onSetPin = { pin -> scope.launch(Dispatchers.Default) { AppLock.setPin(pin.toCharArray()) } },
                    onDisableLock = AppLock::disable,
                    onBiometricChange = AppLock::setBiometric,
                    onEraseAll = { scope.launch(Dispatchers.IO) { CaptureRepository.eraseAll() } },
                    modifier = modifier,
                )
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

/** The saved recordings, reread every few seconds while visible and when [reload] changes. */
@Composable
private fun rememberRecordings(reload: Int): List<RecordingItem>? {
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val recordings = remember { mutableStateOf<List<RecordingItem>?>(null) }
    LaunchedEffect(reload, lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                recordings.value = withContext(Dispatchers.IO) { CaptureRepository.recordings() }
                delay(RECORDINGS_REFRESH_MILLIS)
            }
        }
    }
    return recordings.value
}

@Composable
private fun StatusCard(
    status: CaptureStatus,
    recorder: RecorderStatus,
    connectionCount: Int,
    lookupCount: Int,
    packetCount: Int,
    actions: MainActions,
    onShowRecordings: () -> Unit,
) {
    var confirmClear by remember { mutableStateOf(false) }
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
            if (status.running) RecorderLines(status, recorder)
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
                    TextButton(onClick = actions.switchPrivateDns) { Text(stringResource(R.string.action_private_dns_switch)) }
                }
                !status.running -> Text(
                    text = stringResource(R.string.status_mode_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Row(Modifier.padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (status.running) {
                    Button(onClick = actions.stop) { Text(stringResource(R.string.action_stop)) }
                } else {
                    Button(onClick = actions.start) { Text(stringResource(R.string.action_start)) }
                }
                OutlinedButton(onClick = onShowRecordings) { Text(stringResource(R.string.action_recordings)) }
                TextButton(onClick = { confirmClear = true }, enabled = connectionCount > 0 || packetCount > 0) {
                    Text(stringResource(R.string.action_clear))
                }
            }
        }
    }
    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text(stringResource(R.string.clear_confirm_title)) },
            text = { Text(stringResource(R.string.clear_confirm_text)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmClear = false
                        actions.clear()
                    },
                ) { Text(stringResource(R.string.action_clear)) }
            },
            dismissButton = { TextButton(onClick = { confirmClear = false }) { Text(LocalUiText.current.actionCancel) } },
        )
    }
}

/** Where the packets of the running capture go besides memory. */
@Composable
private fun RecorderLines(status: CaptureStatus, recorder: RecorderStatus) {
    val text = LocalUiText.current
    // (line, is an error)
    val lines = listOfNotNull(
        recorder.recording?.let { stringResource(R.string.status_recording, Format.bytes(recorder.recordedBytes)) to false },
        recorder.storageError?.let { text.recorderError.format(it) to true },
        if (status.alwaysOn) stringResource(R.string.status_always_on) to false else null,
    )
    for ((line, error) in lines) {
        Text(
            text = line,
            style = MaterialTheme.typography.bodySmall,
            color = if (error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
        )
    }
}
