package io.github.rudolfhk.traffical.preview

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import io.github.rudolfhk.traffical.core.analysis.ConnectionFilter
import io.github.rudolfhk.traffical.core.analysis.FlowPacket
import io.github.rudolfhk.traffical.core.analysis.TimeRange
import io.github.rudolfhk.traffical.core.analysis.TrafficTimeline
import io.github.rudolfhk.traffical.core.analysis.dashboard
import io.github.rudolfhk.traffical.core.capture.Direction
import io.github.rudolfhk.traffical.core.capture.FlowInfo
import io.github.rudolfhk.traffical.core.packet.IpProtocol
import io.github.rudolfhk.traffical.core.packet.TcpFlags
import io.github.rudolfhk.traffical.model.AppInfo
import io.github.rudolfhk.traffical.model.Connection
import io.github.rudolfhk.traffical.model.DnsEvent
import io.github.rudolfhk.traffical.ui.common.ConnectionDetailScreen
import io.github.rudolfhk.traffical.ui.common.ConnectionsScreen
import io.github.rudolfhk.traffical.ui.common.DashboardScreen
import io.github.rudolfhk.traffical.ui.common.DnsScreen
import io.github.rudolfhk.traffical.ui.common.LocalUiText
import io.github.rudolfhk.traffical.ui.common.Tab
import io.github.rudolfhk.traffical.ui.common.TrafficAlScaffold
import io.github.rudolfhk.traffical.ui.common.UiText
import org.jetbrains.skia.EncodedImageFormat
import java.io.File
import java.net.InetAddress
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.random.Random
import kotlin.reflect.full.primaryConstructor

/** Usage: Preview <out dir> <values/strings.xml> */
fun main(args: Array<String>) {
    val outDir = File(args[0]).apply { mkdirs() }
    val text = loadUiText(File(args[1]))
    val sample = Sample()

    fun render(name: String, dark: Boolean = false, content: @Composable () -> Unit) {
        val scene = ImageComposeScene(width = 412 * 2, height = 892 * 2, density = Density(2f)) {
            MaterialTheme(colorScheme = if (dark) darkColorScheme() else lightColorScheme()) {
                CompositionLocalProvider(LocalUiText provides text) {
                    Surface { content() }
                }
            }
        }
        val png = scene.render().encodeToData(EncodedImageFormat.PNG)!!.bytes
        scene.close()
        File(outDir, "$name.png").writeBytes(png)
        println("wrote $name.png")
    }

    for (dark in listOf(false, true)) {
        render(if (dark) "dashboard-dark" else "dashboard", dark) {
            TrafficAlScaffold(Tab.DASHBOARD, {}, text.appName, onBack = null) { padding ->
                DashboardScreen(
                    data = sample.dashboard,
                    appInfo = sample::app,
                    onRangeChange = {},
                    onAppClick = {},
                    header = { SampleStatusCard() },
                    modifier = Modifier.padding(padding),
                )
            }
        }
    }
    render("connections") {
        TrafficAlScaffold(Tab.CONNECTIONS, {}, text.tabConnections, onBack = null) { padding ->
            ConnectionsScreen(sample.connections, ConnectionFilter(), {}, {}, sample.now, Modifier.padding(padding))
        }
    }
    render("connections-attention") {
        TrafficAlScaffold(Tab.CONNECTIONS, {}, text.tabConnections, onBack = null) { padding ->
            ConnectionsScreen(
                connections = sample.connections,
                filter = ConnectionFilter(uid = Sample.FLASHLIGHT, attentionOnly = true),
                onFilterChange = {},
                onConnectionClick = {},
                nowMicros = sample.now,
                modifier = Modifier.padding(padding),
            )
        }
    }
    render("connection-detail") {
        TrafficAlScaffold(Tab.CONNECTIONS, {}, sample.tracker.app.label, onBack = {}) { padding ->
            ConnectionDetailScreen(sample.tracker, sample.trackerPackets, Modifier.padding(padding))
        }
    }
    render("dns") {
        TrafficAlScaffold(Tab.DNS, {}, text.tabDns, onBack = null) { padding ->
            DnsScreen(sample.dns, "", {}, Modifier.padding(padding))
        }
    }
}

/** Builds [UiText] from the app's strings.xml: property tabDashboard <- resource tab_dashboard. */
private fun loadUiText(stringsXml: File): UiText {
    val document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(stringsXml)
    val nodes = document.getElementsByTagName("string")
    val strings = (0 until nodes.length).associate { i ->
        val node = nodes.item(i)
        node.attributes.getNamedItem("name").nodeValue to node.textContent.replace("\\'", "'")
    }
    val constructor = UiText::class.primaryConstructor!!
    return constructor.callBy(
        constructor.parameters.associateWith { parameter ->
            val name = parameter.name!!.replace(Regex("([A-Z])")) { "_" + it.value.lowercase() }
            strings[name] ?: error("strings.xml has no string \"$name\" for UiText.${parameter.name}")
        },
    )
}

@Composable
private fun SampleStatusCard() {
    Card(Modifier.padding(horizontal = 16.dp).fillMaxWidth()) {
        androidx.compose.foundation.layout.Column(Modifier.padding(12.dp)) {
            Text("Capturing all traffic", style = MaterialTheme.typography.titleMedium)
            Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {}) { Text("Stop") }
                OutlinedButton(onClick = {}) { Text("Export PCAPNG") }
            }
        }
    }
}

/** Realistic sample data, pushed through the same core code the app uses. */
private class Sample {
    companion object {
        const val CHROME = 10101
        const val YOUTUBE = 10102
        const val WHATSAPP = 10103
        const val FLASHLIGHT = 10104
        const val PLAY_SERVICES = 10105
    }

    val now = 1_793_030_000_000_000L
    private val apps = mapOf(
        CHROME to AppInfo(CHROME, "com.android.chrome", "Chrome"),
        YOUTUBE to AppInfo(YOUTUBE, "com.google.android.youtube", "YouTube"),
        WHATSAPP to AppInfo(WHATSAPP, "com.whatsapp", "WhatsApp"),
        FLASHLIGHT to AppInfo(FLASHLIGHT, "com.example.flashlight", "Super Flashlight"),
        PLAY_SERVICES to AppInfo(PLAY_SERVICES, "com.google.android.gms", "Google Play services"),
    )

    fun app(uid: Int) = apps[uid] ?: AppInfo(uid, null, "uid $uid")

    private var nextId = 1L
    private val local = InetAddress.getByName("10.215.173.1")

    private fun flow(
        uid: Int, remote: String, port: Int, protocol: Int, appProtocol: String, category: String, breed: String,
        sni: String? = null, serverName: String? = null, dnsName: String? = null,
        bytesOut: Long, bytesIn: Long, ageSeconds: Long, durationSeconds: Long = 4, closed: Boolean = true,
    ): FlowInfo {
        val id = nextId++
        val last = now - ageSeconds * 1_000_000
        return FlowInfo(
            id = id, uid = uid, ipVersion = 4, protocol = protocol,
            localAddress = local, localPort = 40000 + id.toInt(), remoteAddress = InetAddress.getByName(remote), remotePort = port,
            sni = sni, dnsName = dnsName, bytesOut = bytesOut, bytesIn = bytesIn,
            packetsOut = maxOf(1, bytesOut / 900), packetsIn = maxOf(1, bytesIn / 1300),
            firstSeenMicros = last - durationSeconds * 1_000_000, lastSeenMicros = last,
            blocked = false, closed = closed, encryptedDns = false,
            appProtocol = appProtocol, category = category, serverName = serverName, breed = breed,
        )
    }

    private val flows: List<FlowInfo> = listOf(
        flow(YOUTUBE, "142.250.185.110", 443, IpProtocol.UDP, "QUIC.YouTube", "Media", "Fun",
            serverName = "rr3---sn-4g5e6nsz.googlevideo.com", bytesOut = 410_000, bytesIn = 48_300_000,
            ageSeconds = 1, durationSeconds = 170, closed = false),
        flow(YOUTUBE, "142.250.185.78", 443, IpProtocol.TCP, "TLS.YouTube", "Media", "Fun",
            sni = "www.youtube.com", bytesOut = 21_000, bytesIn = 380_000, ageSeconds = 40),
        flow(CHROME, "193.99.144.85", 443, IpProtocol.TCP, "TLS", "Web", "Safe",
            sni = "www.heise.de", bytesOut = 48_000, bytesIn = 2_400_000, ageSeconds = 12, durationSeconds = 30),
        flow(CHROME, "142.250.185.68", 443, IpProtocol.UDP, "QUIC.Google", "Web", "Safe",
            serverName = "www.google.com", bytesOut = 12_000, bytesIn = 160_000, ageSeconds = 20),
        flow(FLASHLIGHT, "142.250.186.34", 443, IpProtocol.TCP, "TLS.GoogleServices", "Advertisement", "Tracker_Ads",
            sni = "googleads.g.doubleclick.net", bytesOut = 6_400, bytesIn = 52_000, ageSeconds = 6),
        flow(FLASHLIGHT, "157.240.20.19", 443, IpProtocol.TCP, "TLS.Facebook", "SocialNetwork", "Fun",
            sni = "graph.facebook.com", bytesOut = 9_800, bytesIn = 4_100, ageSeconds = 8),
        flow(FLASHLIGHT, "185.199.110.153", 8443, IpProtocol.TCP, "TLS", "Unspecified", "Safe",
            bytesOut = 31_000, bytesIn = 1_200, ageSeconds = 9),
        flow(WHATSAPP, "157.240.20.53", 443, IpProtocol.TCP, "TLS.WhatsApp", "Chat", "Acceptable",
            sni = "g.whatsapp.net", bytesOut = 4_200, bytesIn = 3_900, ageSeconds = 3, durationSeconds = 290, closed = false),
        flow(PLAY_SERVICES, "142.250.186.42", 443, IpProtocol.TCP, "TLS.Google", "Cloud", "Safe",
            sni = "android.googleapis.com", bytesOut = 7_700, bytesIn = 21_000, ageSeconds = 25),
        flow(PLAY_SERVICES, "10.215.173.2", 53, IpProtocol.UDP, "DNS", "Network", "Acceptable",
            bytesOut = 74, bytesIn = 120, ageSeconds = 26, durationSeconds = 0),
    )

    val connections: List<Connection> = flows.sortedByDescending { it.lastSeenMicros }.map { Connection(it, app(it.uid)) }

    val dashboard = run {
        val timeline = TrafficTimeline()
        val random = Random(7)
        for (flow in flows) {
            val first = flow.firstSeenMicros / 1_000_000
            val last = flow.lastSeenMicros / 1_000_000
            val seconds = (last - first + 1).toInt()
            for (s in 0 until seconds) {
                val wave = 0.4 + random.nextDouble() * (if ((first + s) % 20 < 6) 2.0 else 0.6)
                val second = (first + s) * 1_000_000
                timeline.add(second, flow.uid, outgoing = true, bytes = (flow.bytesOut / seconds * wave).toInt())
                timeline.add(second + 1, flow.uid, outgoing = false, bytes = (flow.bytesIn / seconds * wave).toInt())
            }
        }
        dashboard(flows, timeline, TimeRange.FIVE_MINUTES, now)
    }

    val tracker: Connection = connections.first { it.flow.sni == "googleads.g.doubleclick.net" }

    val trackerPackets: List<FlowPacket> = run {
        val t = tracker.flow.firstSeenMicros
        val hello = hex(
            "1603010200010001fc0303" + "53e5db486d28e6425203ba14307d7c927d74ba41011e9121b727856351b16e17" +
                "20384c51a4782ce87972451f5c2c8df3827275db1ef7bf07fe39f12eb9c408d795" +
                "0024130213031301c02cc030c02bc02fcca9cca8" + "00000020001e00001b" +
                "676f6f676c656164732e672e646f75626c65636c69636b2e6e6574",
        )
        listOf(
            FlowPacket(t, Direction.OUT, 60, TcpFlags.SYN, ByteArray(0)),
            FlowPacket(t + 21_000, Direction.IN, 52, TcpFlags.SYN or TcpFlags.ACK, ByteArray(0)),
            FlowPacket(t + 21_300, Direction.OUT, 40, TcpFlags.ACK, ByteArray(0)),
            FlowPacket(t + 22_000, Direction.OUT, 40 + hello.size, TcpFlags.ACK or TcpFlags.PSH, hello),
            FlowPacket(t + 48_000, Direction.IN, 1500, TcpFlags.ACK, Random(3).nextBytes(1460)),
        )
    }

    val dns: List<DnsEvent> = listOf(
        DnsEvent(4, now / 1000 - 9_000, app(FLASHLIGHT), "googleads.g.doubleclick.net", "A", listOf("142.250.186.34"), 0, 18),
        DnsEvent(3, now / 1000 - 12_000, app(CHROME), "www.heise.de", "AAAA", listOf("2a02:2e0:3fe:1001:302::"), 0, 24),
        DnsEvent(2, now / 1000 - 13_000, app(CHROME), "www.heise.de", "A", listOf("193.99.144.85"), 0, 23),
        DnsEvent(1, now / 1000 - 30_000, app(PLAY_SERVICES), "tracking.invalid", "A", emptyList(), 3, 41),
    )

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
