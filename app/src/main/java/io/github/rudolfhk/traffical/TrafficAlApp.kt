package io.github.rudolfhk.traffical

import android.app.Application
import io.github.rudolfhk.traffical.capture.CaptureRepository
import io.github.rudolfhk.traffical.security.AppLock
import io.github.rudolfhk.traffical.security.Keys
import io.github.rudolfhk.traffical.settings.SettingsStore

/** Sets up the shared state before any activity, service, receiver or tile runs. */
class TrafficAlApp : Application() {
    override fun onCreate() {
        super.onCreate()
        SettingsStore.init(this)
        Keys.init(this)
        AppLock.init(this)
        CaptureRepository.init(this)
    }
}
