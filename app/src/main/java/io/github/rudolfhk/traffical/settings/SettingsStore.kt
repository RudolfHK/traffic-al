package io.github.rudolfhk.traffical.settings

import android.content.Context
import android.content.SharedPreferences
import io.github.rudolfhk.traffical.model.AppSettings
import io.github.rudolfhk.traffical.model.ThemeMode
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** The user's settings and whether a capture should be running, kept across restarts. */
object SettingsStore {
    private const val PREFS = "settings"
    private const val THEME = "theme"
    private const val START_ON_BOOT = "start_on_boot"
    private const val RECORD = "record_to_storage"
    private const val STORAGE_LIMIT_MB = "storage_limit_mb"
    private const val CAPTURE_WANTED = "capture_wanted"

    private lateinit var prefs: SharedPreferences
    private val _settings = MutableStateFlow(AppSettings())
    val settings: StateFlow<AppSettings> = _settings.asStateFlow()

    fun init(context: Context) {
        synchronized(this) {
            if (::prefs.isInitialized) return
            prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            _settings.value = load()
        }
    }

    fun update(transform: (AppSettings) -> AppSettings) = synchronized(this) {
        val updated = transform(_settings.value)
        prefs.edit()
            .putString(THEME, updated.theme.name)
            .putBoolean(START_ON_BOOT, updated.startOnBoot)
            .putBoolean(RECORD, updated.recordToStorage)
            .putInt(STORAGE_LIMIT_MB, updated.storageLimitMb)
            .apply()
        _settings.value = updated
    }

    /**
     * True from a successful start until the user stops the capture: a capture the system
     * killed is restarted (START_STICKY, app update), a stopped one is not.
     */
    var captureWanted: Boolean
        get() = prefs.getBoolean(CAPTURE_WANTED, false)
        set(value) {
            prefs.edit().putBoolean(CAPTURE_WANTED, value).apply()
        }

    private fun load(): AppSettings {
        val defaults = AppSettings()
        return AppSettings(
            theme = enumOrNull<ThemeMode>(prefs.getString(THEME, null)) ?: defaults.theme,
            startOnBoot = prefs.getBoolean(START_ON_BOOT, defaults.startOnBoot),
            recordToStorage = prefs.getBoolean(RECORD, defaults.recordToStorage),
            storageLimitMb = prefs.getInt(STORAGE_LIMIT_MB, defaults.storageLimitMb),
        )
    }

    private inline fun <reified T : Enum<T>> enumOrNull(name: String?): T? =
        enumValues<T>().firstOrNull { it.name == name }
}
