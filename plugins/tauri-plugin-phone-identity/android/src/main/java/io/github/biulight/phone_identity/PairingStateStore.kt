package io.github.biulight.phone_identity

import android.content.Context
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import java.io.Closeable
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.security.MessageDigest
import java.security.PublicKey

internal data class StoredPairingRecord(
    val desktopId: ByteArray,
    val identityId: ByteArray,
    val desktopLabel: String,
    val recipient: String,
    val desktopSigningPublicKey: ByteArray,
    val desktopSelectionPublicKey: ByteArray,
    val phoneSigningPublicKey: ByteArray,
    val offerDigest: ByteArray,
    val transcriptFingerprint: ByteArray,
) {
    fun copySafe(): StoredPairingRecord = copy(
        desktopId = desktopId.copyOf(),
        identityId = identityId.copyOf(),
        desktopSigningPublicKey = desktopSigningPublicKey.copyOf(),
        desktopSelectionPublicKey = desktopSelectionPublicKey.copyOf(),
        phoneSigningPublicKey = phoneSigningPublicKey.copyOf(),
        offerDigest = offerDigest.copyOf(),
        transcriptFingerprint = transcriptFingerprint.copyOf(),
    )

    fun desktopSigningKey(): PublicKey =
        TaggedRecipientCrypto.decodeCompressed(desktopSigningPublicKey)

    companion object {
        fun fromVerifiedTranscript(
            offer: OfflineEnvelopeCrypto.VerifiedPairingOffer,
            response: OfflineEnvelopeCrypto.VerifiedPairingResponse,
        ): StoredPairingRecord = StoredPairingRecord(
            desktopId = offer.offer.desktopId.copyOf(),
            identityId = response.response.identityId.copyOf(),
            desktopLabel = offer.offer.desktopLabel,
            recipient = response.response.recipient,
            desktopSigningPublicKey = TaggedRecipientCrypto.encodeCompressed(
                offer.offer.desktopSigningPublicKey,
            ),
            desktopSelectionPublicKey = TaggedRecipientCrypto.encodeCompressed(
                offer.offer.desktopSelectionPublicKey,
            ),
            phoneSigningPublicKey = TaggedRecipientCrypto.encodeCompressed(
                response.response.phoneSigningPublicKey,
            ),
            offerDigest = offer.digest.copyOf(),
            transcriptFingerprint = OfflineEnvelopeCrypto.pairingFingerprint(offer, response),
        )
    }
}

internal data class StoredPairingSummary(
    val handle: String,
    val desktopLabel: String,
    val transcriptFingerprint: String,
    val deletionPending: Boolean,
)

internal class PairingStateStore private constructor(
    private val root: File,
    private val stateFile: File,
    private val operations: DurableFileOperations,
    private val lockFile: RandomAccessFile,
    private val lock: FileLock,
    private var state: State,
) : Closeable {
    private var unusable = false
    private var closed = false

    fun pairingRecord(): StoredPairingRecord {
        ensureUsable()
        return state.record.copySafe()
    }

    fun consumeRequest(request: OfflineEnvelopeCrypto.VerifiedRequest, nowUnix: Long) {
        ensureUsable()
        val payload = request.request
        if (!MessageDigest.isEqual(payload.desktopId, state.record.desktopId) ||
            !MessageDigest.isEqual(payload.identityId, state.record.identityId)
        ) {
            throw PairingStateException(Category.WRONG_SCOPE)
        }
        validateExpiry(payload.expiresAtUnix, nowUnix)
        if (nowUnix < state.lastSeenUnix) throw PairingStateException(Category.CLOCK_ROLLBACK)

        val entries = state.entries.filter { it.expiresAtUnix >= nowUnix }.toMutableList()
        if (entries.any {
                MessageDigest.isEqual(it.requestId, payload.requestId) ||
                    MessageDigest.isEqual(it.nonce, payload.nonce)
            }
        ) {
            throw PairingStateException(Category.REPLAY)
        }
        if (entries.size >= state.capacity) throw PairingStateException(Category.CAPACITY)
        entries.add(Entry(payload.requestId.copyOf(), payload.nonce.copyOf(), payload.expiresAtUnix))
        entries.sortWith(entryComparator)
        commit(state.copy(lastSeenUnix = nowUnix, entries = entries))
    }

    fun deleteState() {
        ensureUsable()
        if (!stateFile.delete() && stateFile.exists()) {
            unusable = true
            throw PairingStateException(Category.STORAGE)
        }
        try {
            operations.syncDirectory(root)
        } catch (_: Exception) {
            unusable = true
            throw PairingStateException(Category.STORAGE)
        }
        unusable = true
    }

    private fun revokeState() {
        ensureUsable()
        val pendingFile = File(root, stateFile.name + DELETION_SUFFIX)
        try {
            operations.rejectSymlinkIfPresent(pendingFile)
            if (pendingFile.exists()) throw PairingStateException(Category.DELETION_PENDING)
            operations.replace(stateFile, pendingFile)
            operations.syncDirectory(root)
            unusable = true
            if (!pendingFile.delete() && pendingFile.exists()) {
                throw PairingStateException(Category.STORAGE)
            }
            operations.syncDirectory(root)
        } catch (error: PairingStateException) {
            unusable = true
            throw error
        } catch (_: Exception) {
            unusable = true
            throw PairingStateException(Category.STORAGE)
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        try {
            lock.release()
        } finally {
            lockFile.close()
        }
    }

    private fun commit(next: State) {
        val encoded = encode(next)
        if (encoded.size > MAX_STATE_BYTES) throw PairingStateException(Category.CAPACITY)
        val temporary = try {
            File.createTempFile(stateFile.nameWithoutExtension + ".", ".tmp", root)
        } catch (_: Exception) {
            unusable = true
            throw PairingStateException(Category.STORAGE)
        }
        try {
            operations.hardenFile(temporary)
            FileOutputStream(temporary).use { output ->
                output.write(encoded)
                output.fd.sync()
            }
            operations.replace(temporary, stateFile)
            operations.syncDirectory(root)
            state = next
        } catch (_: Exception) {
            unusable = true
            throw PairingStateException(Category.STORAGE)
        } finally {
            if (temporary.exists()) temporary.delete()
        }
    }

    private fun ensureUsable() {
        if (closed || unusable) throw PairingStateException(Category.STORAGE)
    }

    companion object {
        const val DEFAULT_CAPACITY = 1_024
        private const val MAX_CAPACITY = 16_384
        private const val MAX_STATE_BYTES = 1_048_576
        private const val STATE_VERSION = 2
        private const val ROOT_NAME = "age-plugin-phone-pairings-v2"
        private const val DOCTOR_ROOT_NAME = "age-plugin-phone-pairing-doctor-v2"
        private const val DELETION_SUFFIX = ".deleting"
        private val stateDomain = "age-plugin-phone/android-pairing-state-scope/v2"
            .toByteArray(Charsets.US_ASCII)
        private val managementDomain = "age-plugin-phone/android-pairing-management/v1"
            .toByteArray(Charsets.US_ASCII)
        private val cbor = ObjectMapper(CBORFactory())
        private val entryComparator = Comparator<Entry> { left, right ->
            compareUnsigned(left.requestId, right.requestId)
                .takeIf { it != 0 }
                ?: compareUnsigned(left.nonce, right.nonce)
                    .takeIf { it != 0 }
                ?: left.expiresAtUnix.compareTo(right.expiresAtUnix)
        }

        fun create(
            context: Context,
            record: StoredPairingRecord,
            nowUnix: Long,
            capacity: Int = DEFAULT_CAPACITY,
        ): PairingStateStore = createAt(
            File(context.noBackupFilesDir, ROOT_NAME),
            record,
            nowUnix,
            capacity,
            AndroidDurableFileOperations,
        )

        fun open(
            context: Context,
            desktopId: ByteArray,
            identityId: ByteArray,
        ): PairingStateStore = openAt(
            File(context.noBackupFilesDir, ROOT_NAME),
            desktopId,
            identityId,
            AndroidDurableFileOperations,
        )

        fun list(context: Context, identityId: ByteArray): List<StoredPairingSummary> = listAt(
            File(context.noBackupFilesDir, ROOT_NAME),
            identityId,
            AndroidDurableFileOperations,
        )

        fun revoke(context: Context, identityId: ByteArray, handle: String) {
            revokeAt(
                File(context.noBackupFilesDir, ROOT_NAME),
                identityId,
                handle,
                AndroidDurableFileOperations,
            )
        }

        fun revokeAll(context: Context, identityId: ByteArray) {
            val root = File(context.noBackupFilesDir, ROOT_NAME)
            listAt(root, identityId, AndroidDurableFileOperations)
                .filterNot { it.deletionPending }
                .forEach { revokeAt(root, identityId, it.handle, AndroidDurableFileOperations) }
            cleanupPendingAt(root, identityId, AndroidDurableFileOperations)
        }

        internal fun createDoctor(
            context: Context,
            record: StoredPairingRecord,
            nowUnix: Long,
        ): PairingStateStore = createAt(
            File(context.noBackupFilesDir, DOCTOR_ROOT_NAME),
            record,
            nowUnix,
            2,
            AndroidDurableFileOperations,
        )

        internal fun openDoctor(
            context: Context,
            desktopId: ByteArray,
            identityId: ByteArray,
        ): PairingStateStore = openAt(
            File(context.noBackupFilesDir, DOCTOR_ROOT_NAME),
            desktopId,
            identityId,
            AndroidDurableFileOperations,
        )

        internal fun doctorRootIsNoBackup(context: Context): Boolean = try {
            File(context.noBackupFilesDir, DOCTOR_ROOT_NAME).canonicalFile.parentFile ==
                context.noBackupFilesDir.canonicalFile
        } catch (_: Exception) {
            false
        }

        internal fun cleanupDoctorArtifacts(context: Context): Boolean {
            val noBackup = try {
                context.noBackupFilesDir.canonicalFile
            } catch (_: Exception) {
                return false
            }
            val root = File(noBackup, DOCTOR_ROOT_NAME)
            if (!root.exists()) return true
            val canonical = try {
                root.canonicalFile
            } catch (_: Exception) {
                return false
            }
            if (canonical.parentFile != noBackup || canonical.name != DOCTOR_ROOT_NAME || !canonical.isDirectory) {
                return false
            }
            val children = canonical.listFiles() ?: return false
            if (children.any { it.isDirectory || !it.delete() }) return false
            return canonical.delete() || !canonical.exists()
        }

        internal fun createAt(
            root: File,
            record: StoredPairingRecord,
            nowUnix: Long,
            capacity: Int,
            operations: DurableFileOperations,
        ): PairingStateStore {
            validateRecord(record)
            validateCapacity(capacity)
            if (nowUnix < 0) throw PairingStateException(Category.MALFORMED)
            val canonicalRoot = prepareRoot(root, operations)
            val stateFile = stateFile(canonicalRoot, record.desktopId, record.identityId)
            val acquired = acquireLock(canonicalRoot, stateFile, operations)
            try {
                if (stateFile.exists()) throw PairingStateException(Category.ALREADY_EXISTS)
                val initial = State(record.copySafe(), nowUnix, nowUnix, capacity, emptyList())
                val store = PairingStateStore(
                    canonicalRoot,
                    stateFile,
                    operations,
                    acquired.first,
                    acquired.second,
                    initial,
                )
                store.commit(initial)
                return store
            } catch (error: Exception) {
                acquired.second.release()
                acquired.first.close()
                throw error
            }
        }

        internal fun validateRecordForCreation(record: StoredPairingRecord) {
            validateRecord(record)
        }

        internal fun listAt(
            root: File,
            identityId: ByteArray,
            operations: DurableFileOperations,
        ): List<StoredPairingSummary> {
            if (identityId.size != 16) throw PairingStateException(Category.MALFORMED)
            if (!root.exists()) return emptyList()
            val canonicalRoot = prepareRoot(root, operations)
            val files = canonicalRoot.listFiles() ?: throw PairingStateException(Category.STORAGE)
            return files.filter { it.name.endsWith(".cbor") || it.name.endsWith(".cbor$DELETION_SUFFIX") }
                .map { file ->
                    operations.rejectSymlinkIfPresent(file)
                    operations.validatePrivateRegularFile(file)
                    if (file.length() !in 1..MAX_STATE_BYTES.toLong()) {
                        throw PairingStateException(Category.MALFORMED)
                    }
                    val state = decode(FileInputStream(file).use { it.readBytes() })
                    val deleting = file.name.endsWith(DELETION_SUFFIX)
                    val expected = stateFile(canonicalRoot, state.record.desktopId, state.record.identityId)
                    val expectedName = expected.name + if (deleting) DELETION_SUFFIX else ""
                    if (file.name != expectedName) throw PairingStateException(Category.WRONG_SCOPE)
                    state.record to deleting
                }
                .filter { (record, _) -> MessageDigest.isEqual(record.identityId, identityId) }
                .map { (record, deleting) -> summary(record, deleting) }
                .sortedBy { it.handle }
        }

        internal fun revokeAt(
            root: File,
            identityId: ByteArray,
            handle: String,
            operations: DurableFileOperations,
        ) {
            if (!isCanonicalHandle(handle)) throw PairingStateException(Category.MALFORMED)
            val summary = listAt(root, identityId, operations).singleOrNull { it.handle == handle }
                ?: throw PairingStateException(Category.MISSING)
            if (summary.deletionPending) {
                finishPendingAt(root, identityId, handle, operations)
                return
            }
            val record = findRecordAt(root, identityId, handle, operations)
            val store = openAt(root, record.desktopId, record.identityId, operations)
            try {
                if (summary(store.state.record, false).handle != handle) {
                    throw PairingStateException(Category.WRONG_SCOPE)
                }
                store.revokeState()
            } finally {
                store.close()
            }
        }

        internal fun cleanupPendingAt(
            root: File,
            identityId: ByteArray,
            operations: DurableFileOperations,
        ) {
            if (!root.exists()) return
            val canonicalRoot = prepareRoot(root, operations)
            val pending = listAt(canonicalRoot, identityId, operations).filter { it.deletionPending }
            pending.forEach { item ->
                val record = findRecordAt(canonicalRoot, identityId, item.handle, operations, true)
                val file = File(
                    canonicalRoot,
                    stateFile(canonicalRoot, record.desktopId, record.identityId).name + DELETION_SUFFIX,
                )
                operations.rejectSymlinkIfPresent(file)
                if (!file.delete() && file.exists()) throw PairingStateException(Category.STORAGE)
            }
            if (pending.isNotEmpty()) operations.syncDirectory(canonicalRoot)
        }

        private fun finishPendingAt(
            root: File,
            identityId: ByteArray,
            handle: String,
            operations: DurableFileOperations,
        ) {
            val canonicalRoot = prepareRoot(root, operations)
            val record = findRecordAt(canonicalRoot, identityId, handle, operations, true)
            val file = File(
                canonicalRoot,
                stateFile(canonicalRoot, record.desktopId, record.identityId).name + DELETION_SUFFIX,
            )
            operations.rejectSymlinkIfPresent(file)
            operations.validatePrivateRegularFile(file)
            if (!file.delete() && file.exists()) throw PairingStateException(Category.STORAGE)
            operations.syncDirectory(canonicalRoot)
        }

        private fun findRecordAt(
            root: File,
            identityId: ByteArray,
            handle: String,
            operations: DurableFileOperations,
            deleting: Boolean = false,
        ): StoredPairingRecord {
            val canonicalRoot = prepareRoot(root, operations)
            val suffix = if (deleting) ".cbor$DELETION_SUFFIX" else ".cbor"
            val files = canonicalRoot.listFiles() ?: throw PairingStateException(Category.STORAGE)
            return files.filter { it.name.endsWith(suffix) }.mapNotNull { file ->
                operations.validatePrivateRegularFile(file)
                val state = decode(FileInputStream(file).use { it.readBytes() })
                state.record.takeIf {
                    MessageDigest.isEqual(it.identityId, identityId) && summary(it, deleting).handle == handle
                }
            }.singleOrNull() ?: throw PairingStateException(Category.MISSING)
        }

        private fun summary(record: StoredPairingRecord, deleting: Boolean): StoredPairingSummary =
            StoredPairingSummary(
                handle = managementHandle(record),
                desktopLabel = record.desktopLabel,
                transcriptFingerprint = record.transcriptFingerprint.toHex(),
                deletionPending = deleting,
            )

        private fun managementHandle(record: StoredPairingRecord): String {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(managementDomain)
            digest.update(0.toByte())
            digest.update(record.identityId)
            digest.update(record.desktopId)
            digest.update(record.transcriptFingerprint)
            return digest.digest().toHex()
        }

        private fun isCanonicalHandle(value: String): Boolean =
            value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }

        private fun ByteArray.toHex(): String =
            joinToString("") { "%02x".format(it.toInt() and 0xff) }

        internal fun openAt(
            root: File,
            desktopId: ByteArray,
            identityId: ByteArray,
            operations: DurableFileOperations,
        ): PairingStateStore {
            if (desktopId.size != 16 || identityId.size != 16) {
                throw PairingStateException(Category.MALFORMED)
            }
            val canonicalRoot = prepareRoot(root, operations)
            val stateFile = stateFile(canonicalRoot, desktopId, identityId)
            val acquired = acquireLock(canonicalRoot, stateFile, operations)
            try {
                if (!stateFile.exists()) throw PairingStateException(Category.MISSING)
                operations.validatePrivateRegularFile(stateFile)
                if (stateFile.length() !in 1..MAX_STATE_BYTES.toLong()) {
                    throw PairingStateException(Category.MALFORMED)
                }
                val encoded = FileInputStream(stateFile).use { it.readBytes() }
                val state = decode(encoded)
                if (!MessageDigest.isEqual(state.record.desktopId, desktopId) ||
                    !MessageDigest.isEqual(state.record.identityId, identityId)
                ) {
                    throw PairingStateException(Category.WRONG_SCOPE)
                }
                return PairingStateStore(
                    canonicalRoot,
                    stateFile,
                    operations,
                    acquired.first,
                    acquired.second,
                    state,
                )
            } catch (error: Exception) {
                acquired.second.release()
                acquired.first.close()
                throw error
            }
        }

        private fun prepareRoot(root: File, operations: DurableFileOperations): File {
            if (!root.exists() && !root.mkdirs()) throw PairingStateException(Category.STORAGE)
            val canonical = try {
                root.canonicalFile
            } catch (_: Exception) {
                throw PairingStateException(Category.STORAGE)
            }
            operations.validatePrivateDirectory(canonical)
            return canonical
        }

        private fun acquireLock(
            root: File,
            stateFile: File,
            operations: DurableFileOperations,
        ): Pair<RandomAccessFile, FileLock> {
            val lockPath = File(root, stateFile.name + ".lock")
            operations.rejectSymlinkIfPresent(lockPath)
            val randomAccess = try {
                RandomAccessFile(lockPath, "rw")
            } catch (_: Exception) {
                throw PairingStateException(Category.STORAGE)
            }
            return try {
                operations.hardenFile(lockPath)
                operations.validatePrivateRegularFile(lockPath)
                val lock = try {
                    randomAccess.channel.tryLock()
                } catch (_: OverlappingFileLockException) {
                    null
                } ?: throw PairingStateException(Category.LOCKED)
                randomAccess to lock
            } catch (error: Exception) {
                randomAccess.close()
                throw error
            }
        }

        private fun stateFile(root: File, desktopId: ByteArray, identityId: ByteArray): File {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(stateDomain)
            digest.update(0.toByte())
            digest.update(desktopId)
            digest.update(identityId)
            val name = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
            return File(root, "$name.cbor")
        }

        private fun encode(state: State): ByteArray = encodeArray {
            add(STATE_VERSION)
            add(state.record.desktopId)
            add(state.record.identityId)
            add(state.record.desktopLabel)
            add(state.record.recipient)
            add(state.record.desktopSigningPublicKey)
            add(state.record.desktopSelectionPublicKey)
            add(state.record.phoneSigningPublicKey)
            add(state.record.offerDigest)
            add(state.record.transcriptFingerprint)
            add(state.createdAtUnix)
            add(state.lastSeenUnix)
            add(state.capacity)
            add(cbor.createArrayNode().apply {
                state.entries.forEach { entry ->
                    add(cbor.createArrayNode().apply {
                        add(entry.requestId)
                        add(entry.nonce)
                        add(entry.expiresAtUnix)
                    })
                }
            })
        }

        private fun decode(encoded: ByteArray): State {
            val node = strictArray(encoded, 14)
            if (!node[0].isIntegralNumber ||
                !node[0].canConvertToInt() ||
                node[0].intValue() != STATE_VERSION
            ) {
                throw PairingStateException(Category.MALFORMED)
            }
            val record = StoredPairingRecord(
                bytes(node[1], 16),
                bytes(node[2], 16),
                text(node[3], 64),
                text(node[4], 160),
                bytes(node[5], 33),
                bytes(node[6], 33),
                bytes(node[7], 33),
                bytes(node[8], 32),
                bytes(node[9], 32),
            )
            val createdAtUnix = unsignedLong(node[10])
            val lastSeenUnix = unsignedLong(node[11])
            val capacity = unsignedInt(node[12])
            validateRecord(record)
            validateCapacity(capacity)
            val entriesNode = node[13] as? ArrayNode ?: throw PairingStateException(Category.MALFORMED)
            if (entriesNode.size() > capacity) throw PairingStateException(Category.CAPACITY)
            val entries = entriesNode.map { entryNode ->
                val entry = entryNode as? ArrayNode ?: throw PairingStateException(Category.MALFORMED)
                if (entry.size() != 3) throw PairingStateException(Category.MALFORMED)
                Entry(bytes(entry[0], 16), bytes(entry[1], 32), unsignedLong(entry[2]))
            }
            val state = State(record, createdAtUnix, lastSeenUnix, capacity, entries)
            validateState(state)
            if (!MessageDigest.isEqual(encode(state), encoded)) {
                throw PairingStateException(Category.MALFORMED)
            }
            return state
        }

        private fun validateState(state: State) {
            if (state.createdAtUnix < 0 || state.lastSeenUnix < state.createdAtUnix ||
                state.entries.any { it.expiresAtUnix < state.lastSeenUnix }
            ) {
                throw PairingStateException(Category.MALFORMED)
            }
            var previous: Entry? = null
            val requestIds = HashSet<ByteKey>()
            val nonces = HashSet<ByteKey>()
            for (entry in state.entries) {
                if (previous != null && entryComparator.compare(previous, entry) >= 0) {
                    throw PairingStateException(Category.MALFORMED)
                }
                if (!requestIds.add(ByteKey(entry.requestId)) || !nonces.add(ByteKey(entry.nonce))) {
                    throw PairingStateException(Category.MALFORMED)
                }
                previous = entry
            }
        }

        private fun validateRecord(record: StoredPairingRecord) {
            if (record.desktopId.size != 16 || record.identityId.size != 16 ||
                record.desktopLabel.toByteArray().size > 64 ||
                record.offerDigest.size != 32 || record.transcriptFingerprint.size != 32
            ) {
                throw PairingStateException(Category.MALFORMED)
            }
            val identityPublic = try {
                TaggedRecipientCrypto.encodeCompressed(
                    TaggedRecipientCrypto.decodeRecipient(record.recipient),
                )
            } catch (_: Exception) {
                throw PairingStateException(Category.MALFORMED)
            }
            try {
                TaggedRecipientCrypto.decodeCompressed(record.desktopSigningPublicKey)
                TaggedRecipientCrypto.decodeCompressed(record.desktopSelectionPublicKey)
                TaggedRecipientCrypto.decodeCompressed(record.phoneSigningPublicKey)
            } catch (_: Exception) {
                throw PairingStateException(Category.MALFORMED)
            }
            if (MessageDigest.isEqual(identityPublic, record.desktopSigningPublicKey) ||
                MessageDigest.isEqual(identityPublic, record.desktopSelectionPublicKey) ||
                MessageDigest.isEqual(identityPublic, record.phoneSigningPublicKey) ||
                MessageDigest.isEqual(record.desktopSigningPublicKey, record.desktopSelectionPublicKey) ||
                MessageDigest.isEqual(record.desktopSelectionPublicKey, record.phoneSigningPublicKey) ||
                MessageDigest.isEqual(record.desktopSigningPublicKey, record.phoneSigningPublicKey)
            ) {
                throw PairingStateException(Category.MALFORMED)
            }
        }

        private fun validateCapacity(capacity: Int) {
            if (capacity !in 1..MAX_CAPACITY) throw PairingStateException(Category.CAPACITY)
        }

        private fun validateExpiry(expiresAtUnix: Long, nowUnix: Long) {
            if (nowUnix < 0 || expiresAtUnix < nowUnix) throw PairingStateException(Category.EXPIRED)
            if (expiresAtUnix > nowUnix + 300) throw PairingStateException(Category.LIFETIME)
        }

        private fun strictArray(encoded: ByteArray, size: Int): ArrayNode {
            val node = try {
                cbor.readTree(encoded) as? ArrayNode
            } catch (_: Exception) {
                null
            } ?: throw PairingStateException(Category.MALFORMED)
            if (node.size() != size || !MessageDigest.isEqual(cbor.writeValueAsBytes(node), encoded)) {
                throw PairingStateException(Category.MALFORMED)
            }
            return node
        }

        private fun encodeArray(build: ArrayNode.() -> Unit): ByteArray =
            cbor.writeValueAsBytes(cbor.createArrayNode().apply(build))

        private fun bytes(node: JsonNode, size: Int): ByteArray {
            if (!node.isBinary) throw PairingStateException(Category.MALFORMED)
            return node.binaryValue().also {
                if (it.size != size) throw PairingStateException(Category.MALFORMED)
            }
        }

        private fun text(node: JsonNode, maxBytes: Int): String {
            if (!node.isTextual || node.textValue().toByteArray().size > maxBytes) {
                throw PairingStateException(Category.MALFORMED)
            }
            return node.textValue()
        }

        private fun unsignedLong(node: JsonNode): Long {
            if (!node.isIntegralNumber || !node.canConvertToLong() || node.longValue() < 0) {
                throw PairingStateException(Category.MALFORMED)
            }
            return node.longValue()
        }

        private fun unsignedInt(node: JsonNode): Int {
            if (!node.isIntegralNumber || !node.canConvertToInt() || node.intValue() < 0) {
                throw PairingStateException(Category.MALFORMED)
            }
            return node.intValue()
        }

        private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
            for (index in left.indices) {
                val comparison = (left[index].toInt() and 0xff).compareTo(right[index].toInt() and 0xff)
                if (comparison != 0) return comparison
            }
            return left.size.compareTo(right.size)
        }
    }

    private data class State(
        val record: StoredPairingRecord,
        val createdAtUnix: Long,
        val lastSeenUnix: Long,
        val capacity: Int,
        val entries: List<Entry>,
    )

    private data class Entry(
        val requestId: ByteArray,
        val nonce: ByteArray,
        val expiresAtUnix: Long,
    )

    private class ByteKey(private val value: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is ByteKey && MessageDigest.isEqual(value, other.value)

        override fun hashCode(): Int = value.contentHashCode()
    }

    enum class Category {
        ALREADY_EXISTS,
        CAPACITY,
        CLOCK_ROLLBACK,
        DELETION_PENDING,
        EXPIRED,
        LIFETIME,
        LOCKED,
        MALFORMED,
        MISSING,
        REPLAY,
        STORAGE,
        WRONG_SCOPE,
    }

    class PairingStateException(val category: Category) : Exception()
}

internal interface DurableFileOperations {
    fun validatePrivateDirectory(directory: File)
    fun rejectSymlinkIfPresent(file: File)
    fun hardenFile(file: File)
    fun validatePrivateRegularFile(file: File)
    fun replace(source: File, target: File)
    fun syncDirectory(directory: File)
}

private object AndroidDurableFileOperations : DurableFileOperations {
    override fun validatePrivateDirectory(directory: File) {
        val status = try {
            Os.lstat(directory.absolutePath)
        } catch (_: Exception) {
            throw PairingStateStore.PairingStateException(PairingStateStore.Category.STORAGE)
        }
        if (status.st_mode and OsConstants.S_IFMT != OsConstants.S_IFDIR) {
            throw PairingStateStore.PairingStateException(PairingStateStore.Category.STORAGE)
        }
        Os.chmod(directory.absolutePath, 0x1c0)
    }

    override fun rejectSymlinkIfPresent(file: File) {
        val status = try {
            Os.lstat(file.absolutePath)
        } catch (error: ErrnoException) {
            if (error.errno == OsConstants.ENOENT) return
            throw PairingStateStore.PairingStateException(PairingStateStore.Category.STORAGE)
        } catch (_: Exception) {
            throw PairingStateStore.PairingStateException(PairingStateStore.Category.STORAGE)
        }
        if (status.st_mode and OsConstants.S_IFMT == OsConstants.S_IFLNK) {
            throw PairingStateStore.PairingStateException(PairingStateStore.Category.STORAGE)
        }
    }

    override fun hardenFile(file: File) {
        try {
            Os.chmod(file.absolutePath, 0x180)
        } catch (_: Exception) {
            throw PairingStateStore.PairingStateException(PairingStateStore.Category.STORAGE)
        }
    }

    override fun validatePrivateRegularFile(file: File) {
        val status = try {
            Os.lstat(file.absolutePath)
        } catch (_: Exception) {
            throw PairingStateStore.PairingStateException(PairingStateStore.Category.STORAGE)
        }
        if (status.st_mode and OsConstants.S_IFMT != OsConstants.S_IFREG ||
            status.st_mode and 0x3f != 0
        ) {
            throw PairingStateStore.PairingStateException(PairingStateStore.Category.STORAGE)
        }
    }

    override fun replace(source: File, target: File) {
        Os.rename(source.absolutePath, target.absolutePath)
    }

    override fun syncDirectory(directory: File) {
        val descriptor = Os.open(
            directory.absolutePath,
            OsConstants.O_RDONLY,
            0,
        )
        try {
            Os.fsync(descriptor)
        } finally {
            Os.close(descriptor)
        }
    }
}
