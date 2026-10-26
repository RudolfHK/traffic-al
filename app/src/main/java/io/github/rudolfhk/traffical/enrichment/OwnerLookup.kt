package io.github.rudolfhk.traffical.enrichment

import io.github.rudolfhk.traffical.core.enrichment.Rdap
import io.github.rudolfhk.traffical.core.enrichment.RdapInfo
import io.github.rudolfhk.traffical.model.OwnerInfo
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL

/**
 * Online lookups of who owns an IP address, only when the user asks: reverse DNS and RDAP
 * (rdap.org redirects to the responsible regional internet registry). This app is
 * excluded from its own VPN, so the lookups are not captured. Blocking: call off the main thread.
 */
object OwnerLookup {
    private const val TIMEOUT_MILLIS = 10_000
    private const val MAX_ANSWER_CHARS = 1_000_000

    fun lookup(address: InetAddress): OwnerInfo {
        val reverseDns = try {
            InetAddress.getByAddress(address.address).canonicalHostName.takeUnless { it == address.hostAddress }
        } catch (e: SecurityException) {
            null
        }
        return try {
            OwnerInfo(reverseDns, rdap(address), error = null)
        } catch (e: IOException) {
            OwnerInfo(reverseDns, rdap = null, error = e.message ?: e.javaClass.simpleName)
        } catch (e: IllegalArgumentException) {
            OwnerInfo(reverseDns, rdap = null, error = e.message ?: "unreadable answer")
        }
    }

    private fun rdap(address: InetAddress): RdapInfo {
        val connection = URL(Rdap.url(address)).openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = TIMEOUT_MILLIS
            connection.readTimeout = TIMEOUT_MILLIS
            connection.instanceFollowRedirects = true
            connection.setRequestProperty("Accept", "application/rdap+json, application/json")
            val status = connection.responseCode
            if (status != HttpURLConnection.HTTP_OK) throw IOException("HTTP $status")
            val body = connection.inputStream.bufferedReader().use { reader ->
                val text = StringBuilder()
                val buffer = CharArray(8192)
                while (text.length < MAX_ANSWER_CHARS) {
                    val n = reader.read(buffer)
                    if (n < 0) break
                    text.append(buffer, 0, n)
                }
                text.toString()
            }
            return Rdap.parse(body)
        } finally {
            connection.disconnect()
        }
    }
}
