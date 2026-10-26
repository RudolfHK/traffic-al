package io.github.rudolfhk.traffical.history

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase
import androidx.room.Upsert

/** A connection as stored: [io.github.rudolfhk.traffical.core.capture.FlowInfo] with raw addresses. */
@Entity(tableName = "connections", indices = [Index("lastSeenMicros")])
class ConnectionEntity(
    @PrimaryKey val id: Long,
    val uid: Int,
    val ipVersion: Int,
    val protocol: Int,
    val localAddress: ByteArray,
    val localPort: Int,
    val remoteAddress: ByteArray,
    val remotePort: Int,
    val sni: String?,
    val dnsName: String?,
    val bytesOut: Long,
    val bytesIn: Long,
    val packetsOut: Long,
    val packetsIn: Long,
    val firstSeenMicros: Long,
    val lastSeenMicros: Long,
    val blocked: Boolean,
    val closed: Boolean,
    val encryptedDns: Boolean,
    val appProtocol: String?,
    val category: String?,
    val serverName: String?,
    val breed: String?,
)

/** A DNS lookup; [answers] separated by newlines. */
@Entity(tableName = "dns", indices = [Index("timestampMillis")])
class DnsEntity(
    @PrimaryKey val id: Long,
    val timestampMillis: Long,
    val uid: Int,
    val domain: String,
    val queryType: String,
    val answers: String,
    val rcode: Int,
    val latencyMillis: Long?,
)

@Dao
interface HistoryDao {
    @Upsert
    fun upsertConnections(rows: List<ConnectionEntity>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertLookups(rows: List<DnsEntity>)

    @Query("SELECT * FROM connections ORDER BY lastSeenMicros DESC LIMIT :limit")
    fun recentConnections(limit: Int): List<ConnectionEntity>

    @Query("SELECT * FROM dns ORDER BY timestampMillis DESC LIMIT :limit")
    fun recentLookups(limit: Int): List<DnsEntity>

    @Query("DELETE FROM connections WHERE id NOT IN (SELECT id FROM connections ORDER BY lastSeenMicros DESC LIMIT :keep)")
    fun trimConnections(keep: Int)

    @Query("DELETE FROM dns WHERE id NOT IN (SELECT id FROM dns ORDER BY timestampMillis DESC LIMIT :keep)")
    fun trimLookups(keep: Int)

    @Query("DELETE FROM connections")
    fun deleteConnections()

    @Query("DELETE FROM dns")
    fun deleteLookups()
}

@Database(entities = [ConnectionEntity::class, DnsEntity::class], version = 1, exportSchema = false)
abstract class HistoryDatabase : RoomDatabase() {
    abstract fun history(): HistoryDao
}
