package io.github.biulight.phone_identity

import java.security.SecureRandom
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class QrScanSessionTest {
    @Test
    fun ignoresUnrelatedCodesAndReassemblesFramesWithoutExposingBytes() {
        val message = ByteArray(1_301) { (it % 251).toByte() }
        val frames = QrFraming.fragment(message, 600, fixedRandom(4))
        var verifierBytes: ByteArray? = null
        val session = QrScanSession(
            CompletedQrMessageVerifier { completed ->
                verifierBytes = completed
                assertArrayEquals(message, completed)
                "safe-display"
            },
        )

        assertTrue(session.accept("https://example.invalid", 1_000) is QrScanStatus.Ignored)
        assertFalse(session.hasStarted())
        assertTrue(session.accept(frames[2].value, 1_001) is QrScanStatus.InProgress)
        assertTrue(session.accept(frames[2].value, 1_002) is QrScanStatus.InProgress)
        assertTrue(session.accept(frames[1].value, 1_003) is QrScanStatus.InProgress)
        val completed = session.accept(frames[0].value, 1_004) as QrScanStatus.Complete
        assertEquals("safe-display", completed.display)
        assertEquals(4, completed.framesAccepted)
        assertTrue(requireNotNull(verifierBytes).all { it == 0.toByte() })
    }

    @Test
    fun differentTransferDoesNotEvictActiveAssembly() {
        val message = ByteArray(700) { 5 }
        val first = QrFraming.fragment(message, 600, fixedRandom(1))
        val other = QrFraming.fragment(message, 600, fixedRandom(2))
        val session = QrScanSession(CompletedQrMessageVerifier { "done" })
        assertTrue(session.accept(first[0].value, 0) is QrScanStatus.InProgress)
        assertTrue(session.accept(other[1].value, 1) is QrScanStatus.Ignored)
        assertTrue(session.accept(first[1].value, 2) is QrScanStatus.Complete)
    }

    @Test
    fun timeoutCancellationAndMalformedCandidateCloseSession() {
        val frames = QrFraming.fragment(ByteArray(700) { 8 }, 600, fixedRandom(3))
        val timeout = QrScanSession(CompletedQrMessageVerifier { "unused" })
        timeout.accept(frames[0].value, 10)
        assertCategory(QrFraming.Category.TIMEOUT) {
            timeout.expire(10 + QrFraming.MAX_ASSEMBLY_AGE_MS + 1)
        }
        assertCategory(QrFraming.Category.POISONED) { timeout.accept(frames[1].value, 20) }

        val cancelled = QrScanSession(CompletedQrMessageVerifier { "unused" })
        cancelled.accept(frames[0].value, 10)
        cancelled.cancel()
        assertCategory(QrFraming.Category.POISONED) { cancelled.accept(frames[1].value, 11) }

        val malformed = QrScanSession(CompletedQrMessageVerifier { "unused" })
        assertCategory(QrFraming.Category.MALFORMED_FRAME) {
            malformed.accept("age-phone:qr1:not-base64!", 0)
        }
        assertCategory(QrFraming.Category.POISONED) { malformed.accept(frames[0].value, 1) }
    }

    @Test
    fun verifierFailureClosesSessionAndClearsCompletedMessage() {
        val frames = QrFraming.fragment(ByteArray(32) { 6 }, 600, fixedRandom(5))
        var verifierBytes: ByteArray? = null
        val session = QrScanSession<String>(
            CompletedQrMessageVerifier { completed ->
                verifierBytes = completed
                throw IllegalArgumentException("synthetic verifier rejection")
            },
        )
        try {
            session.accept(frames.single().value, 0)
            fail("expected verifier failure")
        } catch (_: IllegalArgumentException) {
            assertTrue(requireNotNull(verifierBytes).all { it == 0.toByte() })
        }
        assertCategory(QrFraming.Category.POISONED) { session.accept(frames.single().value, 1) }
    }

    private fun assertCategory(category: QrFraming.Category, block: () -> Unit) {
        try {
            block()
            fail("expected QR failure")
        } catch (error: QrFraming.QrException) {
            assertEquals(category, error.category)
        }
    }

    private fun fixedRandom(seed: Int): SecureRandom = object : SecureRandom() {
        override fun nextBytes(bytes: ByteArray) {
            bytes.indices.forEach { bytes[it] = (seed + it).toByte() }
        }
    }
}
