package io.github.rudolfhk.traffical.core.analysis

/** Bytes transferred during one interval starting at [startMillis]. */
data class TrafficPoint(val startMillis: Long, val bytesOut: Long, val bytesIn: Long)

data class TrafficTotals(val bytesOut: Long = 0, val bytesIn: Long = 0) {
    val total: Long get() = bytesOut + bytesIn
}

/**
 * Traffic counters over time, for all apps together and per app uid:
 * - all apps: 1-second buckets for the last hour (live chart, rates, time ranges)
 * - per app: 1-second buckets for the last minute (rates) and 10-second buckets for the
 *   last hour (time ranges)
 * - all-time totals for both.
 * Not thread-safe.
 */
class TrafficTimeline {

    private class Ring(private val bucketSeconds: Long, size: Int) {
        private val bucket = LongArray(size) { Long.MIN_VALUE }
        private val bytesOut = LongArray(size)
        private val bytesIn = LongArray(size)
        var allOut = 0L
            private set
        var allIn = 0L
            private set

        fun add(second: Long, outgoing: Boolean, bytes: Int) {
            if (outgoing) allOut += bytes else allIn += bytes

            val b = Math.floorDiv(second, bucketSeconds)
            val i = index(b)
            if (bucket[i] > b) return // older than what the ring still holds
            if (bucket[i] != b) {
                bucket[i] = b
                bytesOut[i] = 0
                bytesIn[i] = 0
            }
            if (outgoing) bytesOut[i] += bytes.toLong() else bytesIn[i] += bytes.toLong()
        }

        /** Sum of the buckets overlapping the seconds (lastSecond - seconds, lastSecond]. */
        fun totals(lastSecond: Long, seconds: Long): TrafficTotals {
            var out = 0L
            var incoming = 0L
            val last = Math.floorDiv(lastSecond, bucketSeconds)
            val first = maxOf(Math.floorDiv(lastSecond - seconds + 1, bucketSeconds), last - bucket.size + 1)
            for (b in first..last) {
                val i = index(b)
                if (bucket[i] == b) {
                    out += bytesOut[i]
                    incoming += bytesIn[i]
                }
            }
            return TrafficTotals(out, incoming)
        }

        private fun index(b: Long) = Math.floorMod(b, bucket.size.toLong()).toInt()
    }

    private var all = Ring(1, HOUR)
    private val perUidFine = HashMap<Int, Ring>()
    private val perUidCoarse = HashMap<Int, Ring>()

    /** Second of the latest packet, or null if nothing was added yet. */
    var lastSecond: Long? = null
        private set

    fun add(timestampMicros: Long, uid: Int, outgoing: Boolean, bytes: Int) {
        val second = Math.floorDiv(timestampMicros, 1_000_000L)
        all.add(second, outgoing, bytes)
        perUidFine.getOrPut(uid) { Ring(1, MINUTE) }.add(second, outgoing, bytes)
        perUidCoarse.getOrPut(uid) { Ring(COARSE_BUCKET_SECONDS, HOUR / COARSE_BUCKET_SECONDS.toInt()) }
            .add(second, outgoing, bytes)
        lastSecond = maxOf(lastSecond ?: second, second)
    }

    /** Totals of all apps in the [seconds] up to [nowSecond]; all-time totals if [seconds] is null. */
    fun totals(nowSecond: Long, seconds: Long?): TrafficTotals =
        if (seconds == null) TrafficTotals(all.allOut, all.allIn) else all.totals(nowSecond, seconds)

    /** Like [totals] per app uid (10-second resolution at the start of the range). */
    fun totalsByUid(nowSecond: Long, seconds: Long?): Map<Int, TrafficTotals> =
        perUidCoarse.mapValues { (_, ring) ->
            if (seconds == null) TrafficTotals(ring.allOut, ring.allIn) else ring.totals(nowSecond, seconds)
        }

    /** Average bytes per second over the [seconds] complete seconds before [nowSecond]. */
    fun rate(nowSecond: Long, uid: Int? = null, seconds: Long = RATE_SECONDS): TrafficTotals {
        val ring = if (uid == null) all else perUidFine[uid] ?: return TrafficTotals()
        val totals = ring.totals(nowSecond - 1, seconds)
        return TrafficTotals(totals.bytesOut / seconds, totals.bytesIn / seconds)
    }

    /**
     * Traffic of all apps in the [seconds] up to [nowSecond], in at most [points] equally
     * long intervals (oldest first).
     */
    fun series(nowSecond: Long, seconds: Long, points: Int = 120): List<TrafficPoint> {
        val span = minOf(seconds, HOUR.toLong())
        val step = maxOf(1L, (span + points - 1) / points)
        val count = ((span + step - 1) / step).toInt()
        val start = nowSecond - count * step + 1
        return List(count) { i ->
            val first = start + i * step
            val totals = all.totals(first + step - 1, step)
            TrafficPoint(first * 1000, totals.bytesOut, totals.bytesIn)
        }
    }

    fun clear() {
        all = Ring(1, HOUR)
        perUidFine.clear()
        perUidCoarse.clear()
        lastSecond = null
    }

    companion object {
        private const val MINUTE = 60
        private const val HOUR = 3600
        private const val COARSE_BUCKET_SECONDS = 10L
        const val RATE_SECONDS = 5L
    }
}
