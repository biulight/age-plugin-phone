package io.github.biulight.phone_identity

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class WifiDiscoveryTest {
    private fun query(purpose: PhoneStreamSession.Purpose): ByteArray = ByteArray(72).also {
        byteArrayOf(0x41, 0x50, 0x57, 0x44).copyInto(it)
        it[5] = 1
        it[6] = 1
        it[7] = purpose.code.toByte()
        ByteArray(32) { 0x31 }.copyInto(it, 8)
        ByteArray(16) { 0x32 }.copyInto(it, 40)
        if (purpose == PhoneStreamSession.Purpose.UNWRAP) {
            ByteArray(16) { 0x33 }.copyInto(it, 56)
        }
    }

    @Test
    fun fixedQueriesRoundTripAndRejectUnknownFields() {
        for (purpose in PhoneStreamSession.Purpose.entries) {
            val encoded = query(purpose)
            val parsed = WifiDiscoveryCodec.parseQuery(encoded, purpose)
            assertEquals(purpose, parsed.purpose)
            assertArrayEquals(ByteArray(32) { 0x31 }, parsed.nonce)
            assertArrayEquals(ByteArray(16) { 0x32 }, parsed.desktopId)
            assertEquals(WifiDiscoveryCodec.QUERY_BYTES, WifiDiscoveryCodec.responsePrefix(parsed).size)
            parsed.clear()

            val trailing = encoded + 0
            runCatching { WifiDiscoveryCodec.parseQuery(trailing, purpose) }
                .onSuccess { throw AssertionError("trailing field accepted") }
            val wrongPurpose = encoded.copyOf().also { it[7] = (3 - purpose.code).toByte() }
            runCatching { WifiDiscoveryCodec.parseQuery(wrongPurpose, purpose) }
                .onSuccess { throw AssertionError("wrong purpose accepted") }
            for (offset in listOf(5, 6)) {
                val unknown = encoded.copyOf().also { it[offset] = 2 }
                runCatching { WifiDiscoveryCodec.parseQuery(unknown, purpose) }
                    .onSuccess { throw AssertionError("unknown field accepted") }
            }
            if (purpose == PhoneStreamSession.Purpose.PAIRING) {
                val identityBound = encoded.copyOf().also { it[56] = 1 }
                runCatching { WifiDiscoveryCodec.parseQuery(identityBound, purpose) }
                    .onSuccess { throw AssertionError("pairing identity accepted") }
            }
        }
    }

    @Test
    fun signedUnwrapResponseIsCompactLowSAndVerifiable() {
        val generator = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        val key = generator.generateKeyPair()
        val query = WifiDiscoveryCodec.parseQuery(
            query(PhoneStreamSession.Purpose.UNWRAP),
            PhoneStreamSession.Purpose.UNWRAP,
        )
        val response = WifiDiscoveryCodec.signedResponse(query, key.private)
        assertEquals(WifiDiscoveryCodec.SIGNED_RESPONSE_BYTES, response.size)
        val compact = response.copyOfRange(WifiDiscoveryCodec.QUERY_BYTES, response.size)
        val order = (key.public as ECPublicKey).params.order
        assertTrue(BigInteger(1, compact.copyOfRange(32, 64)) <= order.shiftRight(1))

        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(key.public)
        verifier.update("age-plugin-phone/wifi-discovery-response/v1".toByteArray(Charsets.US_ASCII))
        verifier.update(byteArrayOf(0))
        verifier.update(response, 0, WifiDiscoveryCodec.QUERY_BYTES)
        assertTrue(verifier.verify(compactToDer(compact)))
        query.clear()
        response.fill(0)
    }

    private fun compactToDer(compact: ByteArray): ByteArray {
        fun integer(part: ByteArray): ByteArray = BigInteger(1, part).toByteArray()
        val r = integer(compact.copyOfRange(0, 32))
        val s = integer(compact.copyOfRange(32, 64))
        return byteArrayOf(0x30, (4 + r.size + s.size).toByte(), 0x02, r.size.toByte()) + r +
            byteArrayOf(0x02, s.size.toByte()) + s
    }
}
