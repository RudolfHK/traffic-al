package io.github.rudolfhk.traffical.ui.common

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.rudolfhk.traffical.core.security.PinRecord

/** What the lock screen shows besides the PIN field. */
data class LockScreenState(
    /** The PIN is being checked. */
    val busy: Boolean = false,
    val wrongPin: Boolean = false,
    /** Seconds until the next PIN may be tried after too many wrong ones. */
    val waitSeconds: Int = 0,
)

/** Shown instead of the app while it is locked. */
@Composable
fun LockScreen(
    state: LockScreenState,
    biometric: Boolean,
    onUnlock: (String) -> Unit,
    onBiometric: () -> Unit,
    onErase: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val text = LocalUiText.current
    var pin by remember { mutableStateOf("") }
    var confirmErase by remember { mutableStateOf(false) }
    val canUnlock = PinRecord.isValid(pin) && !state.busy && state.waitSeconds == 0
    val submit = {
        if (canUnlock) {
            onUnlock(pin)
            pin = ""
        }
    }

    Surface(modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        ) {
            Icon(Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(48.dp), tint = MaterialTheme.colorScheme.primary)
            Text(text.lockTitle, style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
            OutlinedTextField(
                value = pin,
                onValueChange = { value -> pin = value.filter { it in '0'..'9' }.take(PinRecord.MAX_LENGTH) },
                label = { Text(text.lockPin) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, imeAction = ImeAction.Done),
                keyboardActions = KeyboardActions(onDone = { submit() }),
                isError = state.wrongPin || state.waitSeconds > 0,
                modifier = Modifier.fillMaxWidth(),
            )
            when {
                state.waitSeconds > 0 -> ErrorText(text.lockWait.format(state.waitSeconds))
                state.wrongPin -> ErrorText(text.lockWrong)
            }
            Button(onClick = submit, enabled = canUnlock, modifier = Modifier.fillMaxWidth()) { Text(text.lockUnlock) }
            if (biometric) TextButton(onClick = onBiometric) { Text(text.lockBiometric) }
            TextButton(onClick = { confirmErase = true }) { Text(text.lockForgot) }
        }
    }

    if (confirmErase) {
        AlertDialog(
            onDismissRequest = { confirmErase = false },
            title = { Text(text.eraseTitle) },
            text = { Text(text.lockEraseText) },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmErase = false
                        onErase()
                    },
                ) { Text(text.actionErase, color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmErase = false }) { Text(text.actionCancel) } },
        )
    }
}

/** Asks for a new PIN twice; [onSave] gets a valid one. */
@Composable
fun PinDialog(title: String, onSave: (String) -> Unit, onDismiss: () -> Unit) {
    val text = LocalUiText.current
    var pin by remember { mutableStateOf("") }
    var repeat by remember { mutableStateOf("") }
    val problem = when {
        pin.isNotEmpty() && !PinRecord.isValid(pin) -> text.pinInvalid
        repeat.isNotEmpty() && repeat != pin -> text.pinMismatch
        else -> null
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                PinField(pin, { pin = it }, text.pinNew)
                PinField(repeat, { repeat = it }, text.pinRepeat)
                if (problem != null) ErrorText(problem)
            }
        },
        confirmButton = {
            TextButton(onClick = { onSave(pin) }, enabled = PinRecord.isValid(pin) && repeat == pin) { Text(text.actionSave) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(text.actionCancel) } },
    )
}

@Composable
private fun PinField(value: String, onValueChange: (String) -> Unit, label: String) {
    OutlinedTextField(
        value = value,
        onValueChange = { input -> onValueChange(input.filter { it in '0'..'9' }.take(PinRecord.MAX_LENGTH)) },
        label = { Text(label) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
    )
}

@Composable
private fun ErrorText(message: String) {
    Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
}
