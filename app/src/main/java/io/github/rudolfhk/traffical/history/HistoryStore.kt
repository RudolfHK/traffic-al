package io.github.rudolfhk.traffical.history

import android.content.Context
import android.util.Log
import androidx.room.Room
import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.security.Keys
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import java.net.InetAddress
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.Future

/** A DNS lookup as stored, without the app details (they are looked up by uid). */
class StoredLookup(
    val id: Long,
    val timestampMillis: Long,
    val uid: Int,
    val domain: String,
    val queryType: String,
    val answers: List<String>,
    val rcode: Int,
    val latencyMillis: Long?,
)

class History(val connections: List<FlowInfo>, val lookups: List<StoredLookup>)

/**
 * Connections and DNS lookups that outlive the process, in an SQLCipher database whose
 * key is kept encrypted by [Keys]. All database work runs on one background thread.
 */
class HistoryStore(private val context: Context, private val name: String = "history.db") {
    private val executor = Executors.newSingleThreadExecutor { Thread(it, "history") }
    private var database: HistoryDatabase? = null

    /** Opens the database and reads the most recent entries. */
    fun load(limit: Int): Future<History> = executor.submit(
        Callable {
            val empty = History(emptyList(), emptyList())
            val dao = dao() ?: return@Callable empty
            try {
                dao.trimConnections(MAX_CONNECTIONS)
                dao.trimLookups(MAX_LOOKUPS)
                History(
                    connections = dao.recentConnections(limit).map { it.toFlow() },
                    lookups = dao.recentLookups(limit).map { it.toLookup() },
                )
            } catch (e: RuntimeException) {
                Log.e(TAG, "reading history failed", e)
                empty
            }
        },
    )

    /** Inserts or updates [connections] and adds [lookups], in the background. */
    fun save(connections: List<FlowInfo>, lookups: List<StoredLookup>) {
        if (connections.isEmpty() && lookups.isEmpty()) return
        executor.execute {
            val dao = dao() ?: return@execute
            try {
                database?.runInTransaction(
                    Runnable {
                        if (connections.isNotEmpty()) dao.upsertConnections(connections.map { it.toEntity() })
                        if (lookups.isNotEmpty()) dao.insertLookups(lookups.map { it.toEntity() })
                    },
                )
                saves++
                if (saves % TRIM_EVERY_SAVES == 0) {
                    dao.trimConnections(MAX_CONNECTIONS)
                    dao.trimLookups(MAX_LOOKUPS)
                }
            } catch (e: RuntimeException) {
                Log.e(TAG, "saving history failed", e)
            }
        }
    }

    /** Deletes all stored connections and lookups. */
    fun clear(): Future<*> = executor.submit(
        Runnable {
            dao()?.let {
                it.deleteConnections()
                it.deleteLookups()
            }
        },
    )

    private var saves = 0

    private fun dao(): HistoryDao? {
        database?.let { return it.history() }
        return try {
            System.loadLibrary("sqlcipher")
            Room.databaseBuilder(context.applicationContext, HistoryDatabase::class.java, name)
                .openHelperFactory(SupportOpenHelperFactory(Keys.databaseKey()))
                .build()
                .also { database = it }
                .history()
        } catch (e: Exception) {
            // Without the key (e.g. the Keystore was reset) the history can't be read.
            Log.e(TAG, "history database unavailable", e)
            null
        }
    }

    private companion object {
        const val TAG = "HistoryStore"
        const val MAX_CONNECTIONS = 200_000
        const val MAX_LOOKUPS = 200_000
        const val TRIM_EVERY_SAVES = 60
    }
}

private fun FlowInfo.toEntity() = ConnectionEntity(
    id = id,
    uid = uid,
    ipVersion = ipVersion,
    protocol = protocol,
    localAddress = localAddress.address,
    localPort = localPort,
    remoteAddress = remoteAddress.address,
    remotePort = remotePort,
    sni = sni,
    dnsName = dnsName,
    bytesOut = bytesOut,
    bytesIn = bytesIn,
    packetsOut = packetsOut,
    packetsIn = packetsIn,
    firstSeenMicros = firstSeenMicros,
    lastSeenMicros = lastSeenMicros,
    blocked = blocked,
    closed = closed,
    encryptedDns = encryptedDns,
    appProtocol = appProtocol,
    category = category,
    serverName = serverName,
    breed = breed,
)

private fun ConnectionEntity.toFlow() = FlowInfo(
    id = id,
    uid = uid,
    ipVersion = ipVersion,
    protocol = protocol,
    localAddress = InetAddress.getByAddress(localAddress),
    localPort = localPort,
    remoteAddress = InetAddress.getByAddress(remoteAddress),
    remotePort = remotePort,
    sni = sni,
    dnsName = dnsName,
    bytesOut = bytesOut,
    bytesIn = bytesIn,
    packetsOut = packetsOut,
    packetsIn = packetsIn,
    firstSeenMicros = firstSeenMicros,
    lastSeenMicros = lastSeenMicros,
    blocked = blocked,
    closed = closed,
    encryptedDns = encryptedDns,
    appProtocol = appProtocol,
    category = category,
    serverName = serverName,
    breed = breed,
)

private fun StoredLookup.toEntity() = DnsEntity(
    id = id,
    timestampMillis = timestampMillis,
    uid = uid,
    domain = domain,
    queryType = queryType,
    answers = answers.joinToString("\n"),
    rcode = rcode,
    latencyMillis = latencyMillis,
)

private fun DnsEntity.toLookup() = StoredLookup(
    id = id,
    timestampMillis = timestampMillis,
    uid = uid,
    domain = domain,
    queryType = queryType,
    answers = if (answers.isEmpty()) emptyList() else answers.split('\n'),
    rcode = rcode,
    latencyMillis = latencyMillis,
)
