package io.github.biulight.phone_identity

/** Protocol-only limits. Persistent storage has its own schema and capacity limits. */
internal object ProtocolBounds {
    const val MAX_MESSAGE_BYTES = 65_536
    private const val LIFETIME = 300L

    fun validateTime(expires: Long, now: Long) {
        if (now < 0 || expires < now || expires - now > LIFETIME) fail()
    }

    fun requestExpiry(now: Long): Long {
        if (now < 0 || now > Long.MAX_VALUE - LIFETIME) fail()
        return now + LIFETIME
    }

    // Bound structure and declared lengths before Jackson builds an allocating tree.
    // Payload byte strings are opaque here; strictArray calls this again on the payload.
    fun validateEncoded(bytes: ByteArray) {
        if (bytes.isEmpty() || bytes.size > MAX_MESSAGE_BYTES) fail()
        var offset = 0
        fun byte(): Int {
            if (offset >= bytes.size) fail()
            return bytes[offset++].toInt() and 255
        }
        fun value(depth: Int) {
            if (depth > 16) fail()
            val first = byte()
            if (first == 0xf6) return
            val major = first ushr 5
            val additional = first and 31
            if (major !in listOf(0, 2, 3, 4) || additional > 27) fail()
            val length = if (additional < 24) additional.toLong() else {
                val count = 1 shl (additional - 24)
                var result = 0L
                repeat(count) { index ->
                    val next = byte()
                    if (count == 8 && index == 0 && next >= 128) fail()
                    result = (result shl 8) or next.toLong()
                }
                val minimum = when (count) { 1 -> 24L; 2 -> 256L; 4 -> 65536L; else -> 4294967296L }
                if (result < minimum) fail()
                result
            }
            when (major) {
                0 -> Unit
                2, 3 -> {
                    if (length > bytes.size - offset) fail()
                    offset += length.toInt()
                }
                4 -> {
                    if (length > 128) fail()
                    repeat(length.toInt()) { value(depth + 1) }
                }
            }
        }
        value(0)
        if (offset != bytes.size) fail()
    }

    private fun fail(): Nothing = throw OfflineEnvelopeCrypto.ProtocolException()
}
