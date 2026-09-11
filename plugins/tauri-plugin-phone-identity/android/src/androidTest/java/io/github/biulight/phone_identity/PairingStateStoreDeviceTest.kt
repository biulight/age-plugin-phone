package io.github.biulight.phone_identity

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.File
import java.io.IOException
import java.util.Base64
import java.util.UUID
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PairingStateStoreDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val root = File(context.noBackupFilesDir, "pairing-state-device-${UUID.randomUUID()}")
    private val pairingVector = vector("pairing-transcript-v2.json")
    private val requestVector = vector("offline-envelope-v2.json")

    @After
    fun cleanup() {
        check(root.canonicalFile.parentFile == context.noBackupFilesDir.canonicalFile)
        check(root.name.startsWith("pairing-state-device-"))
        root.deleteRecursively()
    }

    @Test
    fun replacementFailureDoesNotConsumeAndPoisonsOnlyOpenHandle() {
        val record = record()
        val operations = FailingOperations()
        val store = PairingStateStore.createAt(root, record, now(), 2, operations)
        operations.failReplace = true

        assertCategory(PairingStateStore.Category.STORAGE) {
            OfflineEnvelopeCrypto.verifyRequestAndConsume(request(), store, now())
        }
        operations.failReplace = false
        assertCategory(PairingStateStore.Category.STORAGE) {
            OfflineEnvelopeCrypto.verifyRequestAndConsume(request(), store, now())
        }
        store.close()

        val reopened = PairingStateStore.openAt(
            root,
            record.desktopId,
            record.identityId,
            AndroidDurableFileOperations,
        )
        OfflineEnvelopeCrypto.verifyRequestAndConsume(request(), reopened, now())
        reopened.close()
    }

    @Test
    fun syncFailurePreservesUncertainReplayConsumptionAfterReopen() {
        val record = record()
        val operations = FailingOperations()
        val store = PairingStateStore.createAt(root, record, now(), 2, operations)
        operations.failSync = true

        assertCategory(PairingStateStore.Category.STORAGE) {
            OfflineEnvelopeCrypto.verifyRequestAndConsume(request(), store, now())
        }
        operations.failSync = false
        store.close()

        val reopened = PairingStateStore.openAt(
            root,
            record.desktopId,
            record.identityId,
            AndroidDurableFileOperations,
        )
        assertCategory(PairingStateStore.Category.REPLAY) {
            OfflineEnvelopeCrypto.verifyRequestAndConsume(request(), reopened, now())
        }
        reopened.close()
    }

    @Test
    fun clockRollbackRejectsWithoutConsumingOrChangingPairing() {
        val record = record()
        val store = PairingStateStore.createAt(
            root,
            record,
            now(),
            2,
            AndroidDurableFileOperations,
        )
        val verified = OfflineEnvelopeCrypto.verifyRequestAndConsume(request(), store, now())
        val next = verified.copy(
            request = verified.request.copy(
                requestId = ByteArray(16) { 0x71 },
                nonce = ByteArray(32) { 0x72 },
                expiresAtUnix = expires() - 1,
            ),
        )
        assertCategory(PairingStateStore.Category.CLOCK_ROLLBACK) {
            store.consumeRequest(next, now() - 1)
        }
        assertArrayEquals(record.offerDigest, store.pairingRecord().offerDigest)
        store.close()

        val reopened = PairingStateStore.openAt(
            root,
            record.desktopId,
            record.identityId,
            AndroidDurableFileOperations,
        )
        reopened.consumeRequest(next, now())
        reopened.close()
    }

    private fun vector(name: String): JsonNode =
        InstrumentationRegistry.getInstrumentation().context.assets.open(name).use {
            ObjectMapper().readTree(it)
        }

    private fun record(): StoredPairingRecord = StoredPairingRecord(
        desktopId = hex(pairingVector["desktop_id_hex"].asText()),
        identityId = hex(pairingVector["identity_id_hex"].asText()),
        desktopLabel = pairingVector["desktop_label"].asText(),
        recipient = pairingVector["recipient"].asText(),
        desktopSigningPublicKey = base64(pairingVector["desktop_signing_public_key_base64"].asText()),
        desktopSelectionPublicKey = base64(pairingVector["desktop_selection_public_key_base64"].asText()),
        phoneSigningPublicKey = base64(pairingVector["phone_signing_public_key_base64"].asText()),
        offerDigest = base64(pairingVector["offer_digest_base64"].asText()),
        transcriptFingerprint = base64(pairingVector["fingerprint_base64"].asText()),
    )

    private fun request(): ByteArray = base64(requestVector["signed_request_base64"].asText())
    private fun now(): Long = requestVector["now_unix"].asLong()
    private fun expires(): Long = requestVector["expires_at_unix"].asLong()

    private fun assertCategory(expected: PairingStateStore.Category, action: () -> Unit) {
        assertEquals(
            expected,
            assertThrows(PairingStateStore.PairingStateException::class.java) { action() }.category,
        )
    }

    private fun base64(value: String): ByteArray = Base64.getDecoder().decode(value)
    private fun hex(value: String): ByteArray =
        value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

private class FailingOperations : DurableFileOperations by AndroidDurableFileOperations {
    var failReplace = false
    var failSync = false

    override fun replace(source: File, target: File) {
        if (failReplace) throw IOException("injected replacement failure")
        AndroidDurableFileOperations.replace(source, target)
    }

    override fun syncDirectory(directory: File) {
        if (failSync) throw IOException("injected directory sync failure")
        AndroidDurableFileOperations.syncDirectory(directory)
    }
}
