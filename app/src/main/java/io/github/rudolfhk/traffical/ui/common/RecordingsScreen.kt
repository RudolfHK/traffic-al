package io.github.rudolfhk.traffical.ui.common

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.github.rudolfhk.traffical.core.analysis.Format
import io.github.rudolfhk.traffical.model.AppSettings
import io.github.rudolfhk.traffical.model.RecorderStatus
import io.github.rudolfhk.traffical.model.RecordingItem
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

private val startFormat = DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm", Locale.ENGLISH).withZone(ZoneId.systemDefault())
private val endFormat = DateTimeFormatter.ofPattern("HH:mm", Locale.ENGLISH).withZone(ZoneId.systemDefault())

/**
 * Saved recordings with export and delete, the storage they take, and the packets in
 * memory. [recordings] is null while they are being read.
 */
@Composable
fun RecordingsScreen(
    recordings: List<RecordingItem>?,
    settings: AppSettings,
    recorder: RecorderStatus,
    bufferPackets: Int,
    onExport: (RecordingItem) -> Unit,
    onDelete: (RecordingItem) -> Unit,
    onExportBuffer: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val text = LocalUiText.current
    var confirmDelete by remember { mutableStateOf<RecordingItem?>(null) }
    val used = recordings?.sumOf { it.bytes } ?: 0L

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        text = text.recordingsStorage.format(Format.bytes(used), Format.bytes(settings.storageLimitBytes)),
                        style = MaterialTheme.typography.titleSmall,
                    )
                    TrafficBar(used, 0, settings.storageLimitBytes)
                    if (!settings.recordToStorage) Note(text.recordingsOff, error = false)
                    recorder.storageError?.let { Note(text.recorderError.format(it), error = true) }
                    if (recorder.droppedPackets > 0) Note(text.recorderDropped.format(recorder.droppedPackets), error = true)
                }
            }
        }
        item {
            Card(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(start = 12.dp, end = 4.dp, top = 4.dp, bottom = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(text.recordingsBuffer, style = MaterialTheme.typography.titleSmall)
                        Text(
                            text = text.recordingsBufferText.format(bufferPackets),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    TextButton(onClick = onExportBuffer, enabled = bufferPackets > 0) { Text(text.actionExport) }
                }
            }
        }
        item {
            Text(text.recordingsSaved, style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 8.dp))
        }
        when {
            recordings == null -> item { CircularProgressIndicator(Modifier.padding(16.dp)) }
            recordings.isEmpty() -> item { Note(text.recordingsEmpty, error = false) }
            else -> items(recordings, key = { it.name }) { recording ->
                RecordingCard(recording, onExport = { onExport(recording) }, onDelete = { confirmDelete = recording })
            }
        }
    }

    confirmDelete?.let { recording ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            title = { Text(text.recordingsDeleteTitle) },
            text = { Text(text.recordingsDeleteText.format(period(recording), Format.bytes(recording.bytes))) },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmDelete = null
                        onDelete(recording)
                    },
                ) { Text(text.actionDelete) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text(text.actionCancel) } },
        )
    }
}

@Composable
private fun RecordingCard(recording: RecordingItem, onExport: () -> Unit, onDelete: () -> Unit) {
    val text = LocalUiText.current
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(start = 12.dp, end = 4.dp, top = 8.dp)) {
            Text(period(recording), style = MaterialTheme.typography.titleSmall)
            Text(
                text = listOfNotNull(
                    Format.duration((recording.endMillis - recording.startMillis) * 1000),
                    Format.bytes(recording.bytes),
                    text.recordingSegments.format(recording.segments).takeIf { recording.segments > 1 },
                ).joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Row(Modifier.weight(1f), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (recording.active) LabelBadge(text.recordingActive, MaterialTheme.colorScheme.primary)
                    if (recording.truncated) LabelBadge(text.recordingTruncated, MaterialTheme.colorScheme.outline)
                }
                TextButton(onClick = onDelete, enabled = !recording.active) { Text(text.actionDelete) }
                TextButton(onClick = onExport) { Text(text.actionExport) }
            }
        }
    }
}

@Composable
private fun Note(note: String, error: Boolean) {
    Text(
        text = note,
        style = MaterialTheme.typography.bodySmall,
        color = if (error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

private fun period(recording: RecordingItem): String {
    val start = Instant.ofEpochMilli(recording.startMillis)
    return "${startFormat.format(start)} – ${endFormat.format(Instant.ofEpochMilli(recording.endMillis))}"
}
