package io.github.rudolfhk.traffical.security

import android.content.Context
import android.util.Base64
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.StreamingAead
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.google.crypto.tink.streamingaead.StreamingAeadConfig
import io.github.rudolfhk.traffical.core.recording.SegmentCodec
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom

/**
 * The app's keys. A master key in the Android Keystore (hardware-backed, never leaves it)
 * encrypts Tink keysets stored in the app's preferences: one for recordings (streaming
 * AEAD), one for small secrets (the database key and the app lock's PIN record).
 * The keys need no user authentication, so the capture can write while the phone and the
 * app are locked. Not usable before [init]; the first use is slow (key generation).
 */
object Keys {
    private const val MASTER_KEY_URI = "android-keystore://traffic_al_master_key"
    private const val KEYSET_PREFS = "keysets"
    private const val SECRET_PREFS = "secrets"
    private const val DATABASE_KEY = "database_key"
    private const val DATABASE_KEY_BYTES = 32

    private lateinit var appContext: Context

    fun init(context: Context) {
        appContext = context.applicationContext
    }

    val recordings: StreamingAead by lazy {
        StreamingAeadConfig.register()
        @Suppress("DEPRECATION")
        keyset("recordings", "AES256_GCM_HKDF_4KB").getPrimitive(StreamingAead::class.java)
    }

    private val secrets: Aead by lazy {
        AeadConfig.register()
        @Suppress("DEPRECATION")
        keyset("secrets", "AES256_GCM").getPrimitive(Aead::class.java)
    }

    /** Both keysets share the master key: create them one at a time. */
    private val keysetLock = Any()

    /** Recording segments encrypted with [recordings]. */
    val recordingCodec: SegmentCodec = object : SegmentCodec {
        override val suffix = ".enc"
        override fun encrypting(out: OutputStream, associatedData: ByteArray): OutputStream =
            recordings.newEncryptingStream(out, associatedData)
        override fun decrypting(input: InputStream, associatedData: ByteArray): InputStream =
            recordings.newDecryptingStream(input, associatedData)
    }

    /** The SQLCipher key of the history database: random, stored encrypted. */
    @Synchronized
    fun databaseKey(): ByteArray {
        loadSecret(DATABASE_KEY)?.let { return it }
        val key = ByteArray(DATABASE_KEY_BYTES).also(SecureRandom()::nextBytes)
        storeSecret(DATABASE_KEY, key)
        return key
    }

    /** Stores [value] encrypted under [name]; null deletes it. */
    fun storeSecret(name: String, value: ByteArray?) {
        val prefs = appContext.getSharedPreferences(SECRET_PREFS, Context.MODE_PRIVATE)
        val encoded = value?.let { Base64.encodeToString(secrets.encrypt(it, name.toByteArray()), Base64.NO_WRAP) }
        prefs.edit().putString(name, encoded).commit()
    }

    fun loadSecret(name: String): ByteArray? {
        val prefs = appContext.getSharedPreferences(SECRET_PREFS, Context.MODE_PRIVATE)
        val encoded = prefs.getString(name, null) ?: return null
        return secrets.decrypt(Base64.decode(encoded, Base64.NO_WRAP), name.toByteArray())
    }

    fun hasSecret(name: String): Boolean =
        appContext.getSharedPreferences(SECRET_PREFS, Context.MODE_PRIVATE).getString(name, null) != null

    private fun keyset(name: String, template: String): KeysetHandle = synchronized(keysetLock) {
        AndroidKeysetManager.Builder()
            .withSharedPref(appContext, name, KEYSET_PREFS)
            .withKeyTemplate(KeyTemplates.get(template))
            .withMasterKeyUri(MASTER_KEY_URI)
            .build()
            .keysetHandle
    }
}
