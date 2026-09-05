package io.github.biulight.phone_identity

import com.fasterxml.jackson.databind.ObjectMapper
import java.io.File
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class PairingConfirmationSessionTest {
    @get:Rule
    val temporary = TemporaryFolder()

    private val vector = ObjectMapper().readTree(
        requireNotNull(javaClass.classLoader?.getResourceAsStream("pairing-transcript-v2.json")),
    )

    @Test
    fun verifiesDisplaysAndCommitsSharedTranscriptOnce() {
        val root = temporary.newFolder("commit")
        val session = session(root)
        assertEquals(vector["desktop_label"].asText(), session.display.desktopLabel)
        assertEquals(vectorFingerprint(), session.display.transcriptFingerprint)

        val committed = session.confirm(session.display.transcriptFingerprint, now())
        assertEquals(session.display.desktopLabel, committed.desktopLabel)
        assertEquals(session.display.transcriptFingerprint, committed.transcriptFingerprint)

        val store = PairingStateStore.openAt(
            root,
            hexBytes(vector["desktop_id_hex"].asText()),
            hexBytes(vector["identity_id_hex"].asText()),
            JvmDurableFileOperations,
        )
        assertArrayEquals(
            Base64.getDecoder().decode(vector["fingerprint_base64"].asText()),
            store.pairingRecord().transcriptFingerprint,
        )
        store.close()
        assertCategory(PairingConfirmationSession.Category.SESSION_CLOSED) {
            session.confirm(session.display.transcriptFingerprint, now())
        }
    }

    @Test
    fun wrongOrNonCanonicalFingerprintTerminatesWithoutCreatingState() {
        listOf(
            "0".repeat(64),
            vectorFingerprint().uppercase(),
            vectorFingerprint().dropLast(1),
        ).forEachIndexed { index, fingerprint ->
            val root = temporary.newFolder("wrong-$index")
            val session = session(root)
            assertCategory(PairingConfirmationSession.Category.FINGERPRINT_MISMATCH) {
                session.confirm(fingerprint, now())
            }
            assertFalse(root.exists() && requireNotNull(root.listFiles()).any { it.extension == "cbor" })
            assertCategory(PairingConfirmationSession.Category.SESSION_CLOSED) {
                session.confirm(session.display.transcriptFingerprint, now())
            }
        }
    }

    @Test
    fun cancellationTerminatesWithoutCreatingState() {
        val root = temporary.newFolder("cancel")
        val session = session(root)
        session.cancel()
        session.cancel()
        assertCategory(PairingConfirmationSession.Category.SESSION_CLOSED) {
            session.confirm(session.display.transcriptFingerprint, now())
        }
        assertFalse(root.exists() && requireNotNull(root.listFiles()).any { it.extension == "cbor" })
    }

    @Test
    fun activityStopCancelsPendingTranscriptAndForegroundRequiresFreshExchange() {
        val root = temporary.newFolder("activity-stop")
        val coordinator = PairingConfirmationCoordinator { _, _ -> session(root) }
        val owner = Any()
        WifiAutoListenForegroundCoordinator.resetForTest()
        try {
            WifiAutoListenForegroundCoordinator.onStart()
            WifiAutoListenForegroundCoordinator.register(owner) { foreground ->
                if (!foreground) coordinator.cancel()
            }
            val display = coordinator.begin(offer(), response())
            WifiAutoListenForegroundCoordinator.onStop()
            WifiAutoListenForegroundCoordinator.onStop()
            WifiAutoListenForegroundCoordinator.onStart()
            assertCategory(PairingConfirmationSession.Category.SESSION_CLOSED) {
                coordinator.confirm(display.transcriptFingerprint, now())
            }
            assertFalse(requireNotNull(root.listFiles()).any { it.extension == "cbor" })
            val fresh = coordinator.begin(offer(), response())
            coordinator.confirm(fresh.transcriptFingerprint, now())
        } finally {
            WifiAutoListenForegroundCoordinator.unregister(owner)
            WifiAutoListenForegroundCoordinator.resetForTest()
        }
    }

    @Test
    fun rejectsMalformedOrMismatchedTranscriptsBeforeDisplay() {
        val offer = offer()
        val response = response()
        val malformed = offer + byteArrayOf(0)
        assertCategory(PairingConfirmationSession.Category.MALFORMED_TRANSCRIPT) {
            PairingConfirmationSession.beginWithCreator(malformed, response, failingCreator())
        }
        assertCategory(PairingConfirmationSession.Category.MALFORMED_TRANSCRIPT) {
            PairingConfirmationSession.beginWithCreator(
                offer,
                response.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() },
                failingCreator(),
            )
        }
    }

    @Test
    fun duplicatePairingAndWriteFailureCloseTheirSessions() {
        val root = temporary.newFolder("duplicate")
        val first = session(root)
        first.confirm(first.display.transcriptFingerprint, now())

        val duplicate = session(root)
        assertCategory(PairingConfirmationSession.Category.ALREADY_PAIRED) {
            duplicate.confirm(duplicate.display.transcriptFingerprint, now())
        }
        assertCategory(PairingConfirmationSession.Category.SESSION_CLOSED) {
            duplicate.confirm(duplicate.display.transcriptFingerprint, now())
        }

        val failed = PairingConfirmationSession.beginWithCreator(offer(), response(), failingCreator())
        assertCategory(PairingConfirmationSession.Category.STORAGE) {
            failed.confirm(failed.display.transcriptFingerprint, now())
        }
        assertCategory(PairingConfirmationSession.Category.SESSION_CLOSED) {
            failed.confirm(failed.display.transcriptFingerprint, now())
        }
    }

    @Test
    fun coordinatorRejectsConcurrentSessionAndRemovesTerminalSession() {
        val root = temporary.newFolder("coordinator")
        val coordinator = PairingConfirmationCoordinator(
            PairingSessionFactory { offer, response ->
                PairingConfirmationSession.beginWithCreator(
                    offer,
                    response,
                    PairingStateCreator { record, nowUnix ->
                        PairingStateStore.createAt(
                            root,
                            record,
                            nowUnix,
                            2,
                            JvmDurableFileOperations,
                        )
                    },
                )
            },
        )
        val display = coordinator.begin(offer(), response())
        assertCategory(PairingConfirmationSession.Category.SESSION_ACTIVE) {
            coordinator.begin(offer(), response())
        }
        coordinator.cancel()
        assertCategory(PairingConfirmationSession.Category.SESSION_CLOSED) {
            coordinator.confirm(display.transcriptFingerprint, now())
        }

        val retry = coordinator.begin(offer(), response())
        assertCategory(PairingConfirmationSession.Category.FINGERPRINT_MISMATCH) {
            coordinator.confirm("0".repeat(64), now())
        }
        assertCategory(PairingConfirmationSession.Category.SESSION_CLOSED) {
            coordinator.confirm(retry.transcriptFingerprint, now())
        }
    }

    private fun session(root: File): PairingConfirmationSession =
        PairingConfirmationSession.beginWithCreator(
            offer(),
            response(),
            PairingStateCreator { record, nowUnix ->
                PairingStateStore.createAt(
                    root,
                    record,
                    nowUnix,
                    2,
                    JvmDurableFileOperations,
                )
            },
        )

    private fun failingCreator(): PairingStateCreator = PairingStateCreator { _, _ ->
        throw java.io.IOException("injected")
    }

    private fun offer(): ByteArray = Base64.getDecoder().decode(vector["signed_offer_base64"].asText())
    private fun response(): ByteArray = Base64.getDecoder().decode(vector["signed_response_base64"].asText())
    private fun vectorFingerprint(): String = hex(Base64.getDecoder().decode(vector["fingerprint_base64"].asText()))
    private fun now(): Long = 1_777_777_777
    private fun hex(value: ByteArray): String = value.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun hexBytes(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun assertCategory(
        expected: PairingConfirmationSession.Category,
        action: () -> Unit,
    ) {
        assertEquals(
            expected,
            assertThrows(PairingConfirmationSession.PairingConfirmationException::class.java) {
                action()
            }.category,
        )
    }
}
