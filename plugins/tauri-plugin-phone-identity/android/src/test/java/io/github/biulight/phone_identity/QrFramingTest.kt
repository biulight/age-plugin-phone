package io.github.biulight.phone_identity

import java.security.SecureRandom
import java.security.MessageDigest
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class QrFramingTest {
    @Test
    fun fragmentsAndReassemblesOutOfOrderWithDuplicates() {
        val message = ByteArray(3_002) { (it and 0xff).toByte() }
        val frames = QrFraming.fragment(message, 600, SequenceRandom(1))
        assertEquals(6, frames.size)
        assertEquals("EncodedQrFrame([REDACTED])", frames[0].toString())
        assertEquals(
            "5UAyIsE2JJ6HduQeKO9Ol_dIKe_qDfYinJPY9oJwiqQ",
            Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(frames[0].value.toByteArray(Charsets.US_ASCII)),
            ),
        )

        val reassembler = QrReassembler()
        listOf(4, 1, 1, 0, 5, 3).forEachIndexed { arrival, index ->
            val progress = reassembler.push(frames[index].value, 1_000L + arrival)
            assertTrue(progress is QrAssemblyStatus.InProgress)
        }
        val completed = reassembler.push(frames[2].value, 1_010) as QrAssemblyStatus.Complete
        assertArrayEquals(message, completed.message)
        assertEquals("Complete(messageBytes=3002)", completed.toString())
        completed.message.fill(0)
    }

    @Test
    fun rejectsSizesCrossTransferTimeoutAndClockRollback() {
        assertCategory(QrFraming.Category.MESSAGE_SIZE) {
            QrFraming.fragment(ByteArray(0), 600, SequenceRandom(0))
        }
        assertCategory(QrFraming.Category.CHUNK_SIZE) {
            QrFraming.fragment(byteArrayOf(1), 601, SequenceRandom(0))
        }
        assertCategory(QrFraming.Category.TOO_MANY_FRAGMENTS) {
            QrFraming.fragment(ByteArray(QrFraming.MAX_MESSAGE_BYTES), 1, SequenceRandom(0))
        }

        val first = QrFraming.fragment(ByteArray(700) { 1 }, 600, SequenceRandom(1))
        val other = QrFraming.fragment(ByteArray(700) { 2 }, 600, SequenceRandom(2))
        val reassembler = QrReassembler()
        reassembler.push(first[0].value, 100)
        assertCategory(QrFraming.Category.DIFFERENT_TRANSFER) {
            reassembler.push(other[0].value, 101)
        }
        assertCategory(QrFraming.Category.CLOCK_ROLLBACK) {
            reassembler.push(first[1].value, 99)
        }
        assertCategory(QrFraming.Category.POISONED) {
            reassembler.push(first[1].value, 102)
        }
        reassembler.reset()
        reassembler.push(first[0].value, 100)
        assertCategory(QrFraming.Category.TIMEOUT) {
            reassembler.push(first[1].value, 100 + QrFraming.MAX_ASSEMBLY_AGE_MS + 1)
        }
    }

    @Test
    fun rejectsNonCanonicalUnknownAndDigestTamper() {
        val frames = QrFraming.fragment(ByteArray(700) { 7 }, 600, SequenceRandom(1))
        assertCategory(QrFraming.Category.MALFORMED_FRAME) {
            QrReassembler().push(frames[0].value + "=", 0)
        }

        val prefix = "age-phone:qr1:"
        val decoder = Base64.getUrlDecoder()
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val canonical = decoder.decode(frames[0].value.substring(prefix.length))
        listOf(
            1 to QrFraming.Category.UNSUPPORTED_VERSION,
            2 to QrFraming.Category.UNSUPPORTED_TYPE,
        ).forEach { (offset, category) ->
            val unknown = canonical.copyOf().also { it[offset] = 2 }
            assertCategory(category) {
                QrReassembler().push(prefix + encoder.encodeToString(unknown), 0)
            }
        }
        val extra = canonical.copyOf().also { it[0] = 0x89.toByte() }
        assertCategory(QrFraming.Category.MALFORMED_FRAME) {
            QrReassembler().push(prefix + encoder.encodeToString(extra), 0)
        }
        val nonCanonical = canonical.toMutableList().apply {
            removeAt(1)
            add(1, 0x18)
            add(2, 0x01)
        }.toByteArray()
        assertCategory(QrFraming.Category.MALFORMED_FRAME) {
            QrReassembler().push(prefix + encoder.encodeToString(nonCanonical), 0)
        }

        val decoded = QrFraming.decode(frames[1].value)
        val tamperedChunk = decoded.chunk.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val tampered = QrFraming.encode(
            QrFraming.Frame(
                decoded.transferId,
                decoded.digest,
                decoded.index,
                decoded.count,
                decoded.totalLength,
                tamperedChunk,
            ),
        )
        decoded.chunk.fill(0)
        tamperedChunk.fill(0)
        val reassembler = QrReassembler()
        reassembler.push(frames[0].value, 0)
        assertCategory(QrFraming.Category.DIGEST_MISMATCH) {
            reassembler.push(tampered.value, 1)
        }
        assertCategory(QrFraming.Category.POISONED) {
            reassembler.push(frames[1].value, 2)
        }
    }

    @Test
    fun conflictingDuplicatePoisonsUntilExplicitReset() {
        val frames = QrFraming.fragment(ByteArray(1_000) { 4 }, 600, SequenceRandom(1))
        val decoded = QrFraming.decode(frames[0].value)
        val conflictChunk = decoded.chunk.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val conflict = QrFraming.encode(
            QrFraming.Frame(
                decoded.transferId,
                decoded.digest,
                decoded.index,
                decoded.count,
                decoded.totalLength,
                conflictChunk,
            ),
        )
        decoded.chunk.fill(0)
        conflictChunk.fill(0)
        val reassembler = QrReassembler()
        reassembler.push(frames[0].value, 0)
        assertCategory(QrFraming.Category.CONFLICTING_FRAGMENT) {
            reassembler.push(conflict.value, 1)
        }
        assertCategory(QrFraming.Category.POISONED) {
            reassembler.push(frames[1].value, 2)
        }
        reassembler.reset()
        reassembler.push(frames[0].value, 3)
        assertTrue(reassembler.push(frames[1].value, 4) is QrAssemblyStatus.Complete)
    }

    private fun assertCategory(expected: QrFraming.Category, action: () -> Unit) {
        assertEquals(
            expected,
            assertThrows(QrFraming.QrException::class.java) { action() }.category,
        )
    }

    private class SequenceRandom(private var next: Int) : SecureRandom() {
        override fun nextBytes(bytes: ByteArray) {
            bytes.indices.forEach { index ->
                bytes[index] = next.toByte()
                next = (next + 1) and 0xff
            }
        }
    }
}
