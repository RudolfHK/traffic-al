package io.github.rudolfhk.traffical.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.github.rudolfhk.traffical.R
import io.github.rudolfhk.traffical.core.analysis.AppAudit
import io.github.rudolfhk.traffical.core.analysis.AuditDestination
import io.github.rudolfhk.traffical.core.analysis.DataFlowAudit
import io.github.rudolfhk.traffical.core.analysis.DecryptabilityStats
import io.github.rudolfhk.traffical.core.analysis.Exposure
import io.github.rudolfhk.traffical.core.analysis.Format
import io.github.rudolfhk.traffical.model.AppInfo
import io.github.rudolfhk.traffical.model.AppSettings
import io.github.rudolfhk.traffical.ui.common.LabelBadge
import kotlin.math.roundToInt

/**
 * The phase-12/13 data-flow audit: per app, what data is going where, plus a decryptability
 * breakdown (what can be read vs stays encrypted) and the MITM-via-mitmproxy control. Everything
 * shown here was decrypted on the device with the owner's own keys; nothing leaves the device.
 */
@Composable
fun AuditScreen(
    audit: DataFlowAudit?,
    stats: DecryptabilityStats?,
    settings: AppSettings,
    appInfo: (Int) -> AppInfo,
    keyLogPresent: Boolean,
    onRefresh: () -> Unit,
    onMitmChange: ((AppSettings) -> AppSettings) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier.fillMaxSize()) {
        AuditHeader(audit, keyLogPresent, onRefresh)
        val expanded = remember { mutableStateMapOf<Int, Boolean>() }
        LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item { MitmProxyCard(settings, onMitmChange) }
            if (stats != null && stats.connections > 0) item { DecryptabilityCard(stats, appInfo) }
            when {
                audit == null -> item { CenteredNote(stringResource(R.string.audit_loading)) }
                audit.apps.isEmpty() -> item {
                    CenteredNote(stringResource(if (keyLogPresent) R.string.audit_empty else R.string.audit_no_keys))
                }
                else -> items(audit.apps, key = { it.uid }) { app ->
                    AppAuditCard(
                        app = app,
                        label = appInfo(app.uid).label,
                        expanded = expanded[app.uid] == true,
                        onToggle = { expanded[app.uid] = expanded[app.uid] != true },
                    )
                }
            }
        }
    }
}

@Composable
private fun AuditHeader(audit: DataFlowAudit?, keyLogPresent: Boolean, onRefresh: () -> Unit) {
    Card(Modifier.padding(16.dp).fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(R.string.audit_title), style = MaterialTheme.typography.titleMedium)
            if (audit != null) {
                Text(
                    stringResource(R.string.audit_summary, audit.apps.size, audit.readableConnections, audit.encryptedConnections),
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (audit.totalExposures > 0) {
                    Text(
                        stringResource(R.string.audit_findings, audit.totalExposures, audit.appsWithExposures),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text(
                    stringResource(R.string.audit_auto),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                TextButton(onClick = onRefresh) { Text(stringResource(R.string.audit_refresh)) }
            }
        }
    }
}

/** The MITM-via-mitmproxy control (phase 13): route the capture's apps through the owner's proxy. */
@Composable
private fun MitmProxyCard(settings: AppSettings, onChange: ((AppSettings) -> AppSettings) -> Unit) {
    var host by remember { mutableStateOf(settings.mitmProxyHost) }
    var port by remember { mutableStateOf(settings.mitmProxyPort.toString()) }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.audit_mitm_title), style = MaterialTheme.typography.titleSmall)
                Switch(checked = settings.mitmProxyEnabled, onCheckedChange = { on -> onChange { it.copy(mitmProxyEnabled = on) } })
            }
            Text(
                stringResource(R.string.audit_mitm_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (settings.mitmProxyEnabled) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = host,
                        onValueChange = { value -> host = value.trim(); onChange { it.copy(mitmProxyHost = host) } },
                        label = { Text(stringResource(R.string.audit_mitm_host)) },
                        singleLine = true,
                        modifier = Modifier.weight(2f),
                    )
                    OutlinedTextField(
                        value = port,
                        onValueChange = { value ->
                            port = value.filter(Char::isDigit).take(5)
                            port.toIntOrNull()?.takeIf { it in 1..65535 }?.let { p -> onChange { it.copy(mitmProxyPort = p) } }
                        },
                        label = { Text(stringResource(R.string.audit_mitm_port)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
    }
}

/** The readable-vs-undecryptable breakdown (phase 13). */
@Composable
private fun DecryptabilityCard(stats: DecryptabilityStats, appInfo: (Int) -> AppInfo) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(R.string.audit_stats_title), style = MaterialTheme.typography.titleSmall)
            Text(
                stringResource(R.string.audit_stats_readable_pct, (stats.readableFraction * 100).roundToInt()),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                stringResource(R.string.audit_stats_bytes, Format.bytes(stats.readableBytes), Format.bytes(stats.encryptedBytes)),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                stringResource(R.string.audit_stats_apps, stats.fullyReadableApps, stats.fullyEncryptedApps),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            // The most opaque apps, so it is obvious which traffic can't be read.
            val opaque = stats.apps.filter { it.encryptedBytes > 0 }.take(5)
            if (opaque.isNotEmpty()) {
                HorizontalDivider(Modifier.padding(vertical = 2.dp))
                for (app in opaque) {
                    Text(
                        stringResource(
                            R.string.audit_stats_app_row,
                            appInfo(app.uid).label,
                            (app.readableFraction * 100).roundToInt(),
                            Format.bytes(app.encryptedBytes),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
    }
}

@Composable
private fun AppAuditCard(app: AppAudit, label: String, expanded: Boolean, onToggle: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(
                Modifier.fillMaxWidth().clickable(onClick = onToggle),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text(label, style = MaterialTheme.typography.titleSmall)
                    Text(
                        stringResource(R.string.audit_app_summary, app.destinationCount, app.exposureCount, app.encryptedConnections),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (app.exposureCount > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(if (expanded) "▾" else "▸", style = MaterialTheme.typography.titleMedium)
            }
            if (expanded) {
                for (destination in app.destinations) {
                    HorizontalDivider()
                    DestinationItem(destination)
                }
            }
        }
    }
}

@Composable
private fun DestinationItem(destination: AuditDestination) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(destination.label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            if (destination.tracker) LabelBadge(stringResource(R.string.audit_tracker), MaterialTheme.colorScheme.error)
        }
        val subtitle = listOfNotNull(
            destination.company,
            destination.country,
            if (destination.methods.isNotEmpty()) destination.methods.joinToString(" ") else null,
        ).joinToString(" · ")
        if (subtitle.isNotEmpty()) {
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (!destination.readable && destination.encrypted > 0) {
            Text(
                stringResource(R.string.audit_encrypted_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        for (exposure in destination.exposures) ExposureRow(exposure)
        for (path in destination.paths.take(6)) {
            Text(
                path,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ExposureRow(exposure: Exposure) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        LabelBadge(exposure.type.label, MaterialTheme.colorScheme.error)
        Text(
            "${exposure.where}: ${exposure.sample}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun CenteredNote(text: String) {
    Column(Modifier.fillMaxWidth().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
