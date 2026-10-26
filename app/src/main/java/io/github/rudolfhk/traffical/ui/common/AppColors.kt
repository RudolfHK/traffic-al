package io.github.rudolfhk.traffical.ui.common

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

/**
 * The app's own color schemes (teal-blue like the launcher icon, received traffic in
 * orange), the same on every Android version: Android 10 has no dynamic color.
 * Material 3 versions newer than Compose Desktop's add surface container roles; the app
 * sets those from [SurfaceContainers].
 */
fun trafficAlColorScheme(dark: Boolean): ColorScheme = if (dark) {
    darkColorScheme(
        primary = Color(0xFF8DCFF1),
        onPrimary = Color(0xFF003548),
        primaryContainer = Color(0xFF004D67),
        onPrimaryContainer = Color(0xFFC2E8FF),
        inversePrimary = Color(0xFF1B6684),
        secondary = Color(0xFFB5C9D7),
        onSecondary = Color(0xFF20333E),
        secondaryContainer = Color(0xFF364955),
        onSecondaryContainer = Color(0xFFD1E5F4),
        tertiary = Color(0xFFFFB59B),
        onTertiary = Color(0xFF5B1A00),
        tertiaryContainer = Color(0xFF7B2E0C),
        onTertiaryContainer = Color(0xFFFFDBCF),
        background = Color(0xFF0F1417),
        onBackground = Color(0xFFDFE3E7),
        surface = Color(0xFF0F1417),
        onSurface = Color(0xFFDFE3E7),
        surfaceVariant = Color(0xFF41484D),
        onSurfaceVariant = Color(0xFFC0C7CD),
        surfaceTint = Color(0xFF8DCFF1),
        inverseSurface = Color(0xFFDFE3E7),
        inverseOnSurface = Color(0xFF2C3135),
        error = Color(0xFFFFB4AB),
        onError = Color(0xFF690005),
        errorContainer = Color(0xFF93000A),
        onErrorContainer = Color(0xFFFFDAD6),
        outline = Color(0xFF8B9297),
        outlineVariant = Color(0xFF41484D),
    )
} else {
    lightColorScheme(
        primary = Color(0xFF1B6684),
        onPrimary = Color(0xFFFFFFFF),
        primaryContainer = Color(0xFFC2E8FF),
        onPrimaryContainer = Color(0xFF001E2C),
        inversePrimary = Color(0xFF8DCFF1),
        secondary = Color(0xFF4E616D),
        onSecondary = Color(0xFFFFFFFF),
        secondaryContainer = Color(0xFFD1E5F4),
        onSecondaryContainer = Color(0xFF0A1E28),
        tertiary = Color(0xFF9A4521),
        onTertiary = Color(0xFFFFFFFF),
        tertiaryContainer = Color(0xFFFFDBCF),
        onTertiaryContainer = Color(0xFF380D00),
        background = Color(0xFFF6FAFE),
        onBackground = Color(0xFF171C20),
        surface = Color(0xFFF6FAFE),
        onSurface = Color(0xFF171C20),
        surfaceVariant = Color(0xFFDCE3E9),
        onSurfaceVariant = Color(0xFF41484D),
        surfaceTint = Color(0xFF1B6684),
        inverseSurface = Color(0xFF2C3135),
        inverseOnSurface = Color(0xFFEEF1F5),
        error = Color(0xFFBA1A1A),
        onError = Color(0xFFFFFFFF),
        errorContainer = Color(0xFFFFDAD6),
        onErrorContainer = Color(0xFF410002),
        outline = Color(0xFF71787E),
        outlineVariant = Color(0xFFC0C7CD),
    )
}

/** Surface container roles of Material 3 1.2+, lowest to highest. */
class SurfaceContainers(
    val lowest: Color,
    val low: Color,
    val container: Color,
    val high: Color,
    val highest: Color,
    val dim: Color,
    val bright: Color,
) {
    companion object {
        fun of(dark: Boolean) = if (dark) {
            SurfaceContainers(
                lowest = Color(0xFF0A0F12),
                low = Color(0xFF171C20),
                container = Color(0xFF1B2024),
                high = Color(0xFF262B2E),
                highest = Color(0xFF313539),
                dim = Color(0xFF0F1417),
                bright = Color(0xFF353A3E),
            )
        } else {
            SurfaceContainers(
                lowest = Color(0xFFFFFFFF),
                low = Color(0xFFF0F4F8),
                container = Color(0xFFEAEEF2),
                high = Color(0xFFE4E9ED),
                highest = Color(0xFFDCE3E9),
                dim = Color(0xFFD6DADE),
                bright = Color(0xFFF6FAFE),
            )
        }
    }
}
