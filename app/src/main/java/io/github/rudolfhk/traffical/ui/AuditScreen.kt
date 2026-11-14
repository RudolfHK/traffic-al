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
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.rudolfhk.traffical.R
import io.github.rudolfhk.traffical.core.analysis.AppAudit
import io.github.rudolfhk.traffical.core.analysis.AuditDestination
import io.github.rudolfhk.traffical.core.analysis.DataFlowAudit
import io.github.rudolfhk.traffical.core.analysis.Exposure
import io.github.rudolfhk.traffical.model.AppInfo
import io.github.rudolfhk.traffical.ui.common.LabelBadge

/**
 * The phase-12 data-flow audit: per app, what data is going where. It shows the destinations
 * each app sent HTTP-bearing traffic to, the sensitive data found in the decrypted requests,
 * and a tally of the connections that stayed encrypted (no keys, or pinned). Everything shown
 * here was decrypted on the device with the owner's own key log; nothing leaves the device.
 */
@Composable
fun AuditScreen(
    audit: DataFlowAudit?,
    appInfo: (Int) -> AppInfo,
    keyLogPresent: Boolean,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier.fillMaxSize()) {
        AuditHeader(audit, keyLogPresent, onRefresh)
        when {
            audit == null -> CenteredNote(stringResource(R.string.audit_loading))
            audit.apps.isEmpty() -> CenteredNote(
                stringResource(if (keyLogPresent) R.string.audit_empty else R.string.audit_no_keys),
            )
            else -> {
                val expanded = remember { mutableStateMapOf<Int, Boolean>() }
                LazyColumn(
                    Modifier.fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(audit.apps, key = { it.uid }) { app ->
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
}

@Composable
private fun AuditHeader(audit: DataFlowAudit?, keyLogPresent: Boolean, onRefresh: () -> Unit) {
    Card(Modifier.padding(16.dp).fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(R.string.audit_title), style = MaterialTheme.typography.titleMedium)
            if (audit != null) {
                Text(
                    stringResource(
                        R.string.audit_summary,
                        audit.apps.size,
                        audit.readableConnections,
                        audit.encryptedConnections,
                    ),
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
            if (!keyLogPresent) {
                Text(
                    stringResource(R.string.audit_no_keys),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
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
                        stringResource(
                            R.string.audit_app_summary,
                            app.destinationCount,
                            app.exposureCount,
                            app.encryptedConnections,
                        ),
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
    Column(
        Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
