package io.github.biulight.phone_identity

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.Assert.*
import org.junit.Test

class ProtocolBoundsTest {
    private val cases = ObjectMapper().readTree(requireNotNull(javaClass.classLoader?.getResourceAsStream("protocol-boundaries-v2.json")))

    @Test fun sharedTimeCases() {
        for (case in cases["time_cases"]) {
            val now = case["now"].asText().toLongOrNull()
            val expires = case["expires"].asText().toLongOrNull()
            val accepted = now != null && expires != null && runCatching { ProtocolBounds.validateTime(expires, now) }.isSuccess
            assertEquals(case["name"].asText(), case["accept"].asBoolean(), accepted)
        }
        for (case in cases["creation_cases"]) {
            val now = case["now"].asText().toLongOrNull()
            assertEquals(case["accept"].asBoolean(), now != null && runCatching { ProtocolBounds.requestExpiry(now) }.isSuccess)
        }
    }

    @Test fun malformedAndSizeBoundaries() {
        for (case in cases["invalid_cbor_hex"]) {
            val bytes = case.asText().chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            assertThrows(Exception::class.java) { OfflineEnvelopeCrypto.requestScope(bytes) }
            assertThrows(Exception::class.java) { OfflineEnvelopeCrypto.verifyPairingOffer(bytes) }
        }
        for (size in listOf(65536, 65537)) {
            val count = size - 70
            val bytes = byteArrayOf(0x82.toByte(), 0x59, (count shr 8).toByte(), count.toByte()) +
                ByteArray(count) + byteArrayOf(0x58, 0x40) + ByteArray(64)
            assertEquals(size, bytes.size)
            assertEquals(size == 65536, runCatching { ProtocolBounds.validateEncoded(bytes) }.isSuccess)
            assertThrows(Exception::class.java) { OfflineEnvelopeCrypto.requestScope(bytes) }
            assertThrows(Exception::class.java) { OfflineEnvelopeCrypto.verifyPairingOffer(bytes) }
        }
        val nested = ByteArray(2000) { 0x81.toByte() } + byteArrayOf(0)
        assertThrows(Exception::class.java) { OfflineEnvelopeCrypto.requestScope(nested) }
    }
}
