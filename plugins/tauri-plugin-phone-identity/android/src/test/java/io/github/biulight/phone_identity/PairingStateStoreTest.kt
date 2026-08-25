package io.github.biulight.phone_identity

import com.fasterxml.jackson.databind.ObjectMapper
import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class PairingStateStoreTest {
    @get:Rule
    val temporary = TemporaryFolder()

    private val pairingVector = ObjectMapper().readTree(
        requireNotNull(javaClass.classLoader?.getResourceAsStream("pairing-transcript-v2.json")),
    )
    private val requestVector = ObjectMapper().readTree(
        requireNotNull(javaClass.classLoader?.getResourceAsStream("offline-envelope-v2.json")),
    )

    @Test
    fun persistsPairingAndRejectsReplayAfterRestart() {
        val root = temporary.newFolder("restart")
        val record = record()
        val store = PairingStateStore.createAt(root, record, now(), 2, JvmDurableFileOperations)
        assertCategory(PairingStateStore.Category.LOCKED) {
            PairingStateStore.openAt(root, record.desktopId, record.identityId, JvmDurableFileOperations)
        }
        OfflineEnvelopeCrypto.verifyRequestAndConsume(request(), store, now())
        store.close()

        val reopened = PairingStateStore.openAt(
            root,
            record.desktopId,
            record.identityId,
            JvmDurableFileOperations,
        )
        assertArrayEquals(record.offerDigest, reopened.pairingRecord().offerDigest)
        assertCategory(PairingStateStore.Category.REPLAY) {
            OfflineEnvelopeCrypto.verifyRequestAndConsume(request(), reopened, now())
        }
        reopened.deleteState()
        reopened.close()
        assertCategory(PairingStateStore.Category.MISSING) {
            PairingStateStore.openAt(root, record.desktopId, record.identityId, JvmDurableFileOperations)
        }
    }

    @Test
    fun verifiesBeforeConsumptionAndFailsClosedOnCapacityAndClockRollback() {
        val root = temporary.newFolder("policy")
        val record = record()
        val store = PairingStateStore.createAt(root, record, now(), 1, JvmDurableFileOperations)
        val modified = request().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertThrows(OfflineEnvelopeCrypto.ProtocolException::class.java) {
            OfflineEnvelopeCrypto.verifyRequestAndConsume(modified, store, now())
        }
        val verified = OfflineEnvelopeCrypto.verifyRequestAndConsume(request(), store, now())

        val another = verified.copy(
            request = verified.request.copy(
                requestId = ByteArray(16) { 0x71 },
                nonce = ByteArray(32) { 0x72 },
                expiresAtUnix = expires() - 1,
            ),
        )
        assertCategory(PairingStateStore.Category.CAPACITY) {
            store.consumeRequest(another, now())
        }
        assertCategory(PairingStateStore.Category.CLOCK_ROLLBACK) {
            store.consumeRequest(another, now() - 1)
        }

        val afterExpiry = another.copy(
            request = another.request.copy(expiresAtUnix = expires() + 301),
        )
        store.consumeRequest(afterExpiry, expires() + 1)
        store.close()
    }

    @Test
    fun rejectsSwappedCorruptNonCanonicalAndNonPrivateState() {
        val root = temporary.newFolder("malformed")
        val first = record()
        val second = first.copy(
            desktopId = ByteArray(16) { 0x66 },
            offerDigest = ByteArray(32) { 0x67 },
            transcriptFingerprint = ByteArray(32) { 0x68 },
        )
        PairingStateStore.createAt(root, first, now(), 2, JvmDurableFileOperations).close()
        val firstFile = stateFiles(root).single()
        PairingStateStore.createAt(root, second, now(), 2, JvmDurableFileOperations).close()
        val files = stateFiles(root)
        val secondFile = files.single { it != firstFile }
        val temporarySwap = File(root, "swap.tmp")
        Files.move(firstFile.toPath(), temporarySwap.toPath(), StandardCopyOption.ATOMIC_MOVE)
        Files.move(secondFile.toPath(), firstFile.toPath(), StandardCopyOption.ATOMIC_MOVE)
        Files.move(temporarySwap.toPath(), secondFile.toPath(), StandardCopyOption.ATOMIC_MOVE)
        assertCategory(PairingStateStore.Category.WRONG_SCOPE) {
            PairingStateStore.openAt(root, first.desktopId, first.identityId, JvmDurableFileOperations)
        }

        Files.move(secondFile.toPath(), firstFile.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        firstFile.appendBytes(byteArrayOf(0))
        assertCategory(PairingStateStore.Category.MALFORMED) {
            PairingStateStore.openAt(root, first.desktopId, first.identityId, JvmDurableFileOperations)
        }

        firstFile.writeBytes(byteArrayOf(0x80.toByte()))
        Files.setPosixFilePermissions(
            firstFile.toPath(),
            setOf(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.GROUP_READ,
            ),
        )
        assertCategory(PairingStateStore.Category.STORAGE) {
            PairingStateStore.openAt(root, first.desktopId, first.identityId, JvmDurableFileOperations)
        }
    }

    @Test
    fun rejectsVersionOnePairingStateWithoutMigration() {
        val root = temporary.newFolder("old-version")
        val record = record()
        PairingStateStore.createAt(root, record, now(), 2, JvmDurableFileOperations).close()
        val stateFile = stateFiles(root).single()
        val encoded = stateFile.readBytes()
        assertEquals(2, encoded[1].toInt())
        encoded[1] = 1
        stateFile.writeBytes(encoded)
        assertCategory(PairingStateStore.Category.MALFORMED) {
            PairingStateStore.openAt(root, record.desktopId, record.identityId, JvmDurableFileOperations)
        }
    }

    @Test
    fun rejectsSymlinkBeforeOpeningLockFile() {
        val root = temporary.newFolder("symlink-lock")
        val record = record()
        PairingStateStore.createAt(root, record, now(), 2, JvmDurableFileOperations).close()
        val lockFile = requireNotNull(root.listFiles()).single { it.name.endsWith(".lock") }
        val target = File(root, "unrelated")
        target.writeText("unchanged")
        Files.delete(lockFile.toPath())
        Files.createSymbolicLink(lockFile.toPath(), target.toPath())

        assertCategory(PairingStateStore.Category.STORAGE) {
            PairingStateStore.openAt(root, record.desktopId, record.identityId, JvmDurableFileOperations)
        }
        assertEquals("unchanged", target.readText())
    }

    @Test
    fun writeFailurePoisonsStoreWithoutConsumingRequest() {
        val root = temporary.newFolder("failure")
        val record = record()
        val operations = FailingOperations()
        val store = PairingStateStore.createAt(root, record, now(), 1, operations)
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
            JvmDurableFileOperations,
        )
        OfflineEnvelopeCrypto.verifyRequestAndConsume(request(), reopened, now())
        reopened.close()
    }

    @Test
    fun rejectsInvalidRecordAndExistingScope() {
        val root = temporary.newFolder("record")
        val record = record()
        assertCategory(PairingStateStore.Category.MALFORMED) {
            PairingStateStore.createAt(
                root,
                record.copy(phoneSigningPublicKey = record.desktopSigningPublicKey.copyOf()),
                now(),
                1,
                JvmDurableFileOperations,
            )
        }
        PairingStateStore.createAt(root, record, now(), 1, JvmDurableFileOperations).close()
        assertCategory(PairingStateStore.Category.ALREADY_EXISTS) {
            PairingStateStore.createAt(root, record, now(), 1, JvmDurableFileOperations)
        }
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

    private fun stateFiles(root: File): List<File> =
        requireNotNull(root.listFiles()).filter { it.extension == "cbor" }

    private fun assertCategory(
        expected: PairingStateStore.Category,
        action: () -> Unit,
    ) {
        assertEquals(
            expected,
            assertThrows(PairingStateStore.PairingStateException::class.java) { action() }.category,
        )
    }

    private fun base64(value: String): ByteArray = Base64.getDecoder().decode(value)
    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

internal object JvmDurableFileOperations : DurableFileOperations {
    private val ownerDirectoryPermissions = setOf(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE,
        PosixFilePermission.OWNER_EXECUTE,
    )
    private val ownerFilePermissions = setOf(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE,
    )

    override fun validatePrivateDirectory(directory: File) {
        if (Files.isSymbolicLink(directory.toPath()) || !directory.isDirectory) {
            throw PairingStateStore.PairingStateException(PairingStateStore.Category.STORAGE)
        }
        Files.setPosixFilePermissions(directory.toPath(), ownerDirectoryPermissions)
    }

    override fun rejectSymlinkIfPresent(file: File) {
        if (Files.isSymbolicLink(file.toPath())) {
            throw PairingStateStore.PairingStateException(PairingStateStore.Category.STORAGE)
        }
    }

    override fun hardenFile(file: File) {
        Files.setPosixFilePermissions(file.toPath(), ownerFilePermissions)
    }

    override fun validatePrivateRegularFile(file: File) {
        if (Files.isSymbolicLink(file.toPath()) || !Files.isRegularFile(file.toPath()) ||
            Files.getPosixFilePermissions(file.toPath()) != ownerFilePermissions
        ) {
            throw PairingStateStore.PairingStateException(PairingStateStore.Category.STORAGE)
        }
    }

    override fun replace(source: File, target: File) {
        Files.move(
            source.toPath(),
            target.toPath(),
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING,
        )
    }

    override fun syncDirectory(directory: File) {
        FileChannel.open(directory.toPath(), StandardOpenOption.READ).use { it.force(true) }
    }
}

private class FailingOperations : DurableFileOperations by JvmDurableFileOperations {
    var failReplace = false

    override fun replace(source: File, target: File) {
        if (failReplace) throw java.io.IOException("injected")
        JvmDurableFileOperations.replace(source, target)
    }
}
