package io.github.rudolfhk.traffical.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import io.github.rudolfhk.traffical.capture.CaptureRepository
import io.github.rudolfhk.traffical.security.AppLock
import io.github.rudolfhk.traffical.security.LockState
import io.github.rudolfhk.traffical.ui.common.LockScreen
import io.github.rudolfhk.traffical.ui.common.LockScreenState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The lock screen while the app is locked; offers the fingerprint right away if enabled. */
@Composable
fun LockGate(lock: LockState, actions: MainActions) {
    var screen by remember { mutableStateOf(LockScreenState()) }
    val scope = rememberCoroutineScope()
    val biometric = remember(lock.biometric) { lock.biometric && actions.biometricAvailable() }

    LaunchedEffect(Unit) {
        if (biometric) actions.authenticateBiometric()
    }
    LaunchedEffect(screen.waitSeconds) {
        if (screen.waitSeconds > 0) {
            delay(1_000)
            screen = screen.copy(waitSeconds = screen.waitSeconds - 1)
        }
    }

    LockScreen(
        state = screen,
        biometric = biometric,
        onUnlock = { pin ->
            screen = screen.copy(busy = true, wrongPin = false)
            scope.launch {
                // Deriving the PIN hash takes a moment.
                val attempt = withContext(Dispatchers.Default) { AppLock.unlock(pin.toCharArray()) }
                screen = when (attempt) {
                    AppLock.Attempt.Unlocked -> LockScreenState()
                    AppLock.Attempt.WrongPin -> LockScreenState(wrongPin = true)
                    is AppLock.Attempt.Wait -> LockScreenState(waitSeconds = ((attempt.millis + 999) / 1000).toInt())
                }
            }
        },
        onBiometric = actions.authenticateBiometric,
        onErase = {
            scope.launch {
                withContext(Dispatchers.IO) {
                    CaptureRepository.eraseAll()
                    AppLock.disable()
                }
            }
        },
    )
}
