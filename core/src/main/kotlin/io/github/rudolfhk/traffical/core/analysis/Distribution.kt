package io.github.rudolfhk.traffical.core.analysis

import io.github.rudolfhk.traffical.core.capture.FlowInfo

/**
 * One slice of a traffic distribution: a label (a protocol or a category) with the traffic
 * grouped under it. [bytes] is the slice's total in both directions; [connections] is how many
 * flows it covers.
 */
data class TrafficShare(
    val label: String,
    val bytesOut: Long,
    val bytesIn: Long,
    val connections: Int,
) {
    val bytes: Long get() = bytesOut + bytesIn
}

/** The label the connection list and the "Other" fold use for a tail of small slices. */
const val OTHER_SHARE_LABEL = "Other"

/**
 * Traffic grouped by application protocol ([FlowInfo.protocolLabel]: "TLS", "QUIC", "HTTP",
 * "DNS", "TCP", ...), largest by bytes first. At most [maxSlots] slices are returned: once there
 * are more groups than that, the smallest are folded into a single [otherLabel] slice, so a chart
 * never needs more colours than the validated palette has leading slots (the data-viz categorical
 * cap). The "Other" slice always sorts last.
 */
fun protocolMix(
    flows: List<FlowInfo>,
    maxSlots: Int = 5,
    otherLabel: String = OTHER_SHARE_LABEL,
): List<TrafficShare> {
    if (flows.isEmpty()) return emptyList()
    val groups = flows.groupBy { it.protocolLabel }
        .map { (label, group) ->
            TrafficShare(
                label = label,
                bytesOut = group.sumOf { it.bytesOut },
                bytesIn = group.sumOf { it.bytesIn },
                connections = group.size,
            )
        }
        // Largest by bytes, then by connections; ties by label so the order is stable.
        .sortedWith(compareByDescending<TrafficShare> { it.bytes }.thenByDescending { it.connections }.thenBy { it.label })

    if (maxSlots < 1 || groups.size <= maxSlots) return groups

    // Keep the largest maxSlots-1 named slices; fold the rest into one "Other" slice at the end.
    val head = groups.take(maxSlots - 1)
    val tail = groups.drop(maxSlots - 1)
    val other = TrafficShare(
        label = otherLabel,
        bytesOut = tail.sumOf { it.bytesOut },
        bytesIn = tail.sumOf { it.bytesIn },
        connections = tail.sumOf { it.connections },
    )
    return head + other
}
