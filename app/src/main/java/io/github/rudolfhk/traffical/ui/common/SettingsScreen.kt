package io.github.rudolfhk.traffical.ui.common

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import io.github.rudolfhk.traffical.core.analysis.Format
import io.github.rudolfhk.traffical.model.AppSettings
import io.github.rudolfhk.traffical.model.BackgroundInfo
import io.github.rudolfhk.traffical.model.PrivacyInfo
import io.github.rudolfhk.traffical.model.ThemeMode

/** Theme, background capture, recording and privacy (app lock, encryption, erasing). */
@Composable
fun SettingsScreen(
    settings: AppSettings,
    background: BackgroundInfo,
    privacy: PrivacyInfo,
    onChange: ((AppSettings) -> AppSettings) -> Unit,
    onRequestBatteryExemption: () -> Unit,
    onOpenVpnSettings: () -> Unit,
    onSetPin: (String) -> Unit,
    onDisableLock: () -> Unit,
    onBiometricChange: (Boolean) -> Unit,
    onEraseAll: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val text = LocalUiText.current
    var pinDialog by remember { mutableStateOf(false) }
    var confirmErase by remember { mutableStateOf(false) }
    LazyColumn(modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 16.dp)) {
        item { SectionTitle(text.settingsAppearance) }
        item {
            ChoiceRow(
                title = text.settingsTheme,
                options = ThemeMode.values().toList(),
                selected = settings.theme,
                label = {
                    when (it) {
                        ThemeMode.SYSTEM -> text.themeSystem
                        ThemeMode.LIGHT -> text.themeLight
                        ThemeMode.DARK -> text.themeDark
                    }
                },
                onSelect = { theme -> onChange { it.copy(theme = theme) } },
            )
        }

        item { SectionTitle(text.settingsBackground) }
        item {
            SwitchRow(
                title = text.settingsStartOnBoot,
                subtitle = text.settingsStartOnBootHint,
                checked = settings.startOnBoot,
                onCheckedChange = { on -> onChange { it.copy(startOnBoot = on) } },
            )
        }
        item {
            ActionRow(
                title = text.settingsBattery,
                subtitle = if (background.batteryOptimized) text.settingsBatteryOn else text.settingsBatteryOff,
                subtitleColor = if (background.batteryOptimized) MaterialTheme.colorScheme.error else null,
                action = text.settingsBatteryAction.takeIf { background.batteryOptimized },
                onAction = onRequestBatteryExemption,
            )
        }
        item {
            ActionRow(
                title = text.settingsAlwaysOn,
                subtitle = if (background.alwaysOn) text.settingsAlwaysOnActive else text.settingsAlwaysOnHint,
                subtitleColor = null,
                action = text.settingsAlwaysOnAction,
                onAction = onOpenVpnSettings,
            )
        }
        item { Hint(text.settingsHuaweiHint) }

        item { SectionTitle(text.settingsRecording) }
        item {
            SwitchRow(
                title = text.settingsRecordToStorage,
                subtitle = text.settingsRecordToStorageHint,
                checked = settings.recordToStorage,
                onCheckedChange = { on -> onChange { it.copy(recordToStorage = on) } },
            )
        }
        item {
            ChoiceRow(
                title = text.settingsStorageLimit,
                subtitle = text.settingsStorageLimitHint,
                options = AppSettings.STORAGE_LIMITS_MB,
                selected = settings.storageLimitMb,
                label = { Format.bytes(it * 1_000_000L) },
                onSelect = { mb -> onChange { it.copy(storageLimitMb = mb) } },
            )
        }

        item { SectionTitle(text.settingsPrivacy) }
        item {
            SwitchRow(
                title = text.settingsLock,
                subtitle = text.settingsLockHint,
                checked = privacy.lockEnabled,
                onCheckedChange = { on -> if (on) pinDialog = true else onDisableLock() },
            )
        }
        if (privacy.lockEnabled) {
            item {
                SwitchRow(
                    title = text.settingsBiometric,
                    subtitle = text.settingsBiometricUnavailable.takeIf { !privacy.biometricAvailable },
                    checked = privacy.biometric && privacy.biometricAvailable,
                    onCheckedChange = { on -> if (privacy.biometricAvailable) onBiometricChange(on) },
                )
            }
            item {
                ActionRow(
                    title = text.settingsChangePin,
                    subtitle = null,
                    subtitleColor = null,
                    action = text.actionChange,
                    onAction = { pinDialog = true },
                )
            }
        }
        item {
            ActionRow(
                title = text.settingsEncryption,
                subtitle = text.settingsEncryptionHint,
                subtitleColor = null,
                action = null,
                onAction = {},
            )
        }
        item {
            ActionRow(
                title = text.settingsErase,
                subtitle = text.settingsEraseHint,
                subtitleColor = null,
                action = text.actionErase,
                onAction = { confirmErase = true },
            )
        }

        item { SectionTitle(text.settingsAbout) }
        item { Hint(text.settingsVersion.format(background.appVersion)) }
    }
    SettingsDialogs(
        pinDialog = pinDialog,
        confirmErase = confirmErase,
        onSetPin = onSetPin,
        onEraseAll = onEraseAll,
        onDismiss = {
            pinDialog = false
            confirmErase = false
        },
    )
}

@Composable
private fun SettingsDialogs(
    pinDialog: Boolean,
    confirmErase: Boolean,
    onSetPin: (String) -> Unit,
    onEraseAll: () -> Unit,
    onDismiss: () -> Unit,
) {
    val text = LocalUiText.current
    if (pinDialog) {
        PinDialog(
            title = text.pinTitle,
            onSave = { pin ->
                onDismiss()
                onSetPin(pin)
            },
            onDismiss = onDismiss,
        )
    }
    if (confirmErase) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(text.eraseTitle) },
            text = { Text(text.settingsEraseText) },
            confirmButton = {
                TextButton(
                    onClick = {
                        onDismiss()
                        onEraseAll()
                    },
                ) { Text(text.actionErase, color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = onDismiss) { Text(text.actionCancel) } },
        )
    }
}

@Composable
private fun SectionTitle(title: String) {
    Column {
        Divider(Modifier.padding(top = 8.dp))
        Text(
            text = title,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 4.dp),
        )
    }
}

@Composable
private fun SwitchRow(title: String, subtitle: String?, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f).padding(end = 16.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            if (subtitle != null) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun ActionRow(title: String, subtitle: String?, subtitleColor: Color?, action: String?, onAction: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f).padding(end = 8.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            if (subtitle != null) {
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = subtitleColor ?: MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        if (action != null) TextButton(onClick = onAction) { Text(action) }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun <T> ChoiceRow(
    title: String,
    options: List<T>,
    selected: T,
    label: (T) -> String,
    onSelect: (T) -> Unit,
    subtitle: String? = null,
) {
    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        Text(title, style = MaterialTheme.typography.bodyLarge)
        if (subtitle != null) {
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            for (option in options) {
                FilterChip(selected = option == selected, onClick = { onSelect(option) }, label = { Text(label(option)) })
            }
        }
    }
}

@Composable
private fun Hint(hint: String) {
    Text(
        text = hint,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
    )
}
