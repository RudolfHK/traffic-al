package io.github.rudolfhk.traffical

import android.app.Application
import io.github.rudolfhk.traffical.capture.CaptureRepository
import io.github.rudolfhk.traffical.settings.SettingsStore

/** Sets up the shared state before any activity, service, receiver or tile runs. */
class TrafficAlApp : Application() {
    override fun onCreate() {
        super.onCreate()
        SettingsStore.init(this)
        CaptureRepository.init(this)
    }
}
