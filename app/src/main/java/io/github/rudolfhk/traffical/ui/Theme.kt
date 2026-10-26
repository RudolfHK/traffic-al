package io.github.rudolfhk.traffical.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import io.github.rudolfhk.traffical.ui.common.SurfaceContainers
import io.github.rudolfhk.traffical.ui.common.trafficAlColorScheme

/** The app's light or dark color scheme; [dark] comes from the theme setting. */
@Composable
fun TrafficAlTheme(dark: Boolean, content: @Composable () -> Unit) {
    val colors = remember(dark) {
        val containers = SurfaceContainers.of(dark)
        trafficAlColorScheme(dark).copy(
            surfaceContainerLowest = containers.lowest,
            surfaceContainerLow = containers.low,
            surfaceContainer = containers.container,
            surfaceContainerHigh = containers.high,
            surfaceContainerHighest = containers.highest,
            surfaceDim = containers.dim,
            surfaceBright = containers.bright,
        )
    }
    MaterialTheme(colorScheme = colors, content = content)
}
