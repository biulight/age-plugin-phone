package io.github.biulight.phone_identity

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement

internal data class PhoneIdentityPublic(
    val identityId: ByteArray,
    val recipient: String,
    val identityPublicKey: ByteArray,
    val signingPublicKey: ByteArray,
) {
    fun copySafe() = copy(
        identityId = identityId.copyOf(),
        identityPublicKey = identityPublicKey.copyOf(),
        signingPublicKey = signingPublicKey.copyOf(),
    )
}

internal data class PhoneKeyInspection(
    val identityStrongBox: Boolean,
    val identityAgreeOnly: Boolean,
    val identityAuthPerUse: Boolean,
    val identityBiometricStrong: Boolean,
    val signingStrongBox: Boolean,
    val signingPurposeSignOnly: Boolean,
    val signingNoUserAuth: Boolean,
    val privateKeysNonExportable: Boolean,
)

internal data class PhoneIdentityProvision(
    val public: PhoneIdentityPublic,
    val inspection: PhoneKeyInspection,
    val recoveredPreparingState: Boolean,
)

internal data class PreparedIdentityAgreement(
    val agreement: KeyAgreement,
    val identityPublicKey: PublicKey,
)

internal class PhoneIdentityKeyStore private constructor(
    private val context: Context,
    private val rootName: String,
    private val identityAliasPrefix: String,
    private val signingAliasPrefix: String,
) {
    fun provision(): PhoneIdentityProvision = synchronized(processLock) {
        requireSupportedApi()
        val root = prepareRoot()
        val stateFile = File(root, STATE_FILE_NAME)
        var recovered = false
        if (stateFile.exists()) {
            val existing = readState(stateFile)
            if (existing is StoredState.Committed) throw KeyStoreException(Category.ALREADY_EXISTS)
            if (existing is StoredState.Deleting) throw KeyStoreException(Category.DELETION_PENDING)
            cleanupAliases(existing.identityId)
            deleteState(root, stateFile)
            recovered = true
        }

        val identityId = ByteArray(IDENTITY_ID_BYTES).also(SecureRandom()::nextBytes)
        val identityAlias = identityAlias(identityId)
        val signingAlias = signingAlias(identityId)
        val store = keyStore()
        if (store.containsAlias(identityAlias) || store.containsAlias(signingAlias)) {
            throw KeyStoreException(Category.ALIAS_COLLISION)
        }
        commit(root, stateFile, encodePreparing(identityId))

        try {
            generateIdentityKey(identityAlias)
            generateSigningKey(signingAlias)
            val public = publicMetadata(store, identityId)
            val inspection = inspect(store, identityId)
            if (!inspection.isAcceptable()) throw KeyStoreException(Category.WRONG_SECURITY_LEVEL)
            commit(root, stateFile, encodeCommitted(public))
            PhoneIdentityProvision(public.copySafe(), inspection, recovered)
        } catch (error: Exception) {
            runCatching { cleanupAliases(identityId) }
            runCatching { deleteState(root, stateFile) }
            when (error) {
                is android.security.keystore.StrongBoxUnavailableException ->
                    throw KeyStoreException(Category.STRONGBOX_UNAVAILABLE)
                is KeyStoreException -> throw error
                else -> throw KeyStoreException(Category.GENERATION_FAILED)
            }
        }
    }

    fun open(): PhoneIdentityProvision = synchronized(processLock) {
        requireSupportedApi()
        val stateFile = File(prepareRoot(), STATE_FILE_NAME)
        if (!stateFile.exists()) throw KeyStoreException(Category.MISSING)
        val committed = when (val state = readState(stateFile)) {
            is StoredState.Committed -> state
            is StoredState.Deleting -> throw KeyStoreException(Category.DELETION_PENDING)
            is StoredState.Preparing -> throw KeyStoreException(Category.INCOMPLETE)
        }
        val store = keyStore()
        val live = publicMetadata(store, committed.identityId)
        if (!publicEqual(committed.public, live)) throw KeyStoreException(Category.METADATA_MISMATCH)
        val inspection = inspect(store, committed.identityId)
        if (!inspection.isAcceptable()) throw KeyStoreException(Category.WRONG_SECURITY_LEVEL)
        PhoneIdentityProvision(live.copySafe(), inspection, false)
    }

    fun deleteIdentity(): Boolean = synchronized(processLock) {
        requireSupportedApi()
        val root = prepareRoot()
        val stateFile = File(root, STATE_FILE_NAME)
        if (!stateFile.exists()) throw KeyStoreException(Category.MISSING)
        val current = readState(stateFile)
        val public = when (current) {
            is StoredState.Committed -> {
                commit(root, stateFile, encodeDeleting(current.public))
                current.public
            }
            is StoredState.Deleting -> current.public
            is StoredState.Preparing -> throw KeyStoreException(Category.INCOMPLETE)
        }

        try {
            PairingStateStore.revokeAll(context, public.identityId)
            cleanupAliases(public.identityId)
            val store = keyStore()
            if (store.containsAlias(identityAlias(public.identityId)) ||
                store.containsAlias(signingAlias(public.identityId))
            ) {
                throw KeyStoreException(Category.STORAGE)
            }
            deleteState(root, stateFile)
            true
        } catch (error: KeyStoreException) {
            throw error
        } catch (_: Exception) {
            throw KeyStoreException(Category.STORAGE)
        }
    }

    fun createPairingResponse(signedOffer: ByteArray): ByteArray = synchronized(processLock) {
        val provision = open()
        val store = keyStore()
        val signingPrivate = store.getKey(signingAlias(provision.public.identityId), null) as? PrivateKey
            ?: throw KeyStoreException(Category.MISSING)
        val offer = try {
            OfflineEnvelopeCrypto.verifyPairingOffer(signedOffer)
        } catch (_: Exception) {
            throw KeyStoreException(Category.MALFORMED)
        }
        try {
            OfflineEnvelopeCrypto.createPairingResponse(
                offer,
                provision.public,
                signingPrivate,
                SecureRandom(),
            ).encoded
        } catch (_: Exception) {
            throw KeyStoreException(Category.GENERATION_FAILED)
        } finally {
            offer.encoded.fill(0)
            offer.digest.fill(0)
            offer.offer.desktopId.fill(0)
            offer.offer.nonce.fill(0)
        }
    }

    fun prepareIdentityAgreement(
        expectedIdentityId: ByteArray,
        peerPublicKey: PublicKey,
    ): PreparedIdentityAgreement = synchronized(processLock) {
        TaggedRecipientCrypto.encodeCompressed(peerPublicKey)
        val provision = open()
        if (!MessageDigest.isEqual(provision.public.identityId, expectedIdentityId)) {
            throw KeyStoreException(Category.MALFORMED)
        }
        val store = keyStore()
        val identityPrivate = store.getKey(identityAlias(provision.public.identityId), null) as? PrivateKey
            ?: throw KeyStoreException(Category.MISSING)
        val identityPublic = store.getCertificate(identityAlias(provision.public.identityId))?.publicKey
            ?: throw KeyStoreException(Category.MISSING)
        val agreement = KeyAgreement.getInstance("ECDH", ANDROID_KEY_STORE)
        agreement.init(identityPrivate)
        PreparedIdentityAgreement(agreement, identityPublic)
    }

    fun createUnwrapResponse(
        request: OfflineEnvelopeCrypto.VerifiedRequest,
        fileKey: ByteArray,
    ): ByteArray = synchronized(processLock) {
        val provision = open()
        if (!MessageDigest.isEqual(provision.public.identityId, request.request.identityId)) {
            throw KeyStoreException(Category.MALFORMED)
        }
        val store = keyStore()
        val signingPrivate = store.getKey(signingAlias(provision.public.identityId), null) as? PrivateKey
            ?: throw KeyStoreException(Category.MISSING)
        val signingPublic = store.getCertificate(signingAlias(provision.public.identityId))?.publicKey
            ?: throw KeyStoreException(Category.MISSING)
        try {
            OfflineEnvelopeCrypto.sealResponse(
                request,
                fileKey,
                signingPrivate,
                signingPublic,
                SecureRandom(),
            ).encoded
        } catch (_: Exception) {
            throw KeyStoreException(Category.GENERATION_FAILED)
        }
    }

    fun cleanup(): Boolean = synchronized(processLock) {
        val root = prepareRoot()
        val stateFile = File(root, STATE_FILE_NAME)
        val id = if (stateFile.exists()) {
            runCatching { readState(stateFile).identityId }.getOrNull()
        } else {
            null
        }
        if (id != null) cleanupAliases(id) else cleanupNamespacedAliases()
        if (stateFile.exists()) deleteState(root, stateFile)
        cleanupNamespacedAliases()
        val children = root.listFiles()
        if (root.exists() && children != null && children.isEmpty()) root.delete()
        !stateFile.exists() && namespacedAliases().isEmpty()
    }

    internal fun createPreparingStateForDoctor(identityId: ByteArray) = synchronized(processLock) {
        if (identityId.size != IDENTITY_ID_BYTES) throw KeyStoreException(Category.MALFORMED)
        val root = prepareRoot()
        val stateFile = File(root, STATE_FILE_NAME)
        if (stateFile.exists()) throw KeyStoreException(Category.ALREADY_EXISTS)
        commit(root, stateFile, encodePreparing(identityId))
    }

    internal fun rootIsNoBackup(): Boolean = try {
        rootFile().canonicalFile.parentFile == context.noBackupFilesDir.canonicalFile
    } catch (_: Exception) {
        false
    }

    private fun publicMetadata(store: KeyStore, identityId: ByteArray): PhoneIdentityPublic {
        val identityPublic = store.getCertificate(identityAlias(identityId))?.publicKey
            ?: throw KeyStoreException(Category.MISSING)
        val signingPublic = store.getCertificate(signingAlias(identityId))?.publicKey
            ?: throw KeyStoreException(Category.MISSING)
        val identityBytes = compressed(identityPublic)
        val signingBytes = compressed(signingPublic)
        if (MessageDigest.isEqual(identityBytes, signingBytes)) {
            throw KeyStoreException(Category.WRONG_KEY_ROLE)
        }
        return PhoneIdentityPublic(
            identityId.copyOf(),
            TaggedRecipientCrypto.encodeRecipient(identityPublic),
            identityBytes,
            signingBytes,
        )
    }

    private fun inspect(store: KeyStore, identityId: ByteArray): PhoneKeyInspection {
        val identityPrivate = store.getKey(identityAlias(identityId), null) as? PrivateKey
            ?: throw KeyStoreException(Category.MISSING)
        val signingPrivate = store.getKey(signingAlias(identityId), null) as? PrivateKey
            ?: throw KeyStoreException(Category.MISSING)
        val identityInfo = keyInfo(identityPrivate)
        val signingInfo = keyInfo(signingPrivate)
        return PhoneKeyInspection(
            identityInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX,
            identityInfo.origin == KeyProperties.ORIGIN_GENERATED &&
                identityInfo.purposes == KeyProperties.PURPOSE_AGREE_KEY,
            identityInfo.isUserAuthenticationRequired &&
                identityInfo.userAuthenticationValidityDurationSeconds == 0 &&
                identityInfo.isUserAuthenticationRequirementEnforcedBySecureHardware,
            identityInfo.userAuthenticationType == KeyProperties.AUTH_BIOMETRIC_STRONG,
            signingInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX,
            signingInfo.origin == KeyProperties.ORIGIN_GENERATED &&
                signingInfo.purposes == KeyProperties.PURPOSE_SIGN,
            !signingInfo.isUserAuthenticationRequired,
            identityPrivate.format == null && identityPrivate.encoded == null &&
                signingPrivate.format == null && signingPrivate.encoded == null,
        )
    }

    private fun generateIdentityKey(alias: String) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
            .setAlgorithmParameterSpec(ECGenParameterSpec(P256_NAME))
            .setIsStrongBoxBacked(true)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .build()
        generator(spec).generateKeyPair()
    }

    private fun generateSigningKey(alias: String) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec(P256_NAME))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(true)
            .setUserAuthenticationRequired(false)
            .build()
        generator(spec).generateKeyPair()
    }

    private fun generator(spec: KeyGenParameterSpec): KeyPairGenerator =
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE).apply {
            initialize(spec)
        }

    private fun keyInfo(privateKey: PrivateKey): KeyInfo =
        KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEY_STORE)
            .getKeySpec(privateKey, KeyInfo::class.java)

    private fun cleanupAliases(identityId: ByteArray) {
        val store = keyStore()
        listOf(identityAlias(identityId), signingAlias(identityId)).forEach { alias ->
            if (store.containsAlias(alias)) store.deleteEntry(alias)
        }
    }

    private fun cleanupNamespacedAliases() {
        val store = keyStore()
        namespacedAliases(store).forEach(store::deleteEntry)
    }

    private fun namespacedAliases(store: KeyStore = keyStore()): List<String> =
        store.aliases().toList().filter {
            isValidAlias(it, identityAliasPrefix) || isValidAlias(it, signingAliasPrefix)
        }

    private fun readState(file: File): StoredState {
        validatePrivateFile(file)
        if (file.length() !in 1..MAX_STATE_BYTES.toLong()) throw KeyStoreException(Category.MALFORMED)
        return decodeState(FileInputStream(file).use { it.readBytes() })
    }

    private fun commit(root: File, stateFile: File, encoded: ByteArray) {
        val temporary = try {
            File.createTempFile("identity.", ".tmp", root)
        } catch (_: Exception) {
            throw KeyStoreException(Category.STORAGE)
        }
        try {
            Os.chmod(temporary.absolutePath, PRIVATE_FILE_MODE)
            FileOutputStream(temporary).use { output ->
                output.write(encoded)
                output.fd.sync()
            }
            rejectSymlinkIfPresent(stateFile)
            Os.rename(temporary.absolutePath, stateFile.absolutePath)
            syncDirectory(root)
        } catch (_: Exception) {
            throw KeyStoreException(Category.STORAGE)
        } finally {
            if (temporary.exists()) temporary.delete()
        }
    }

    private fun deleteState(root: File, stateFile: File) {
        rejectSymlinkIfPresent(stateFile)
        if (!stateFile.delete() && stateFile.exists()) throw KeyStoreException(Category.STORAGE)
        if (root.exists()) syncDirectory(root)
    }

    private fun prepareRoot(): File {
        val noBackup = try {
            context.noBackupFilesDir.canonicalFile
        } catch (_: Exception) {
            throw KeyStoreException(Category.STORAGE)
        }
        val root = File(noBackup, rootName)
        rejectSymlinkIfPresent(root)
        if (!root.exists() && !root.mkdir()) throw KeyStoreException(Category.STORAGE)
        val canonical = try {
            root.canonicalFile
        } catch (_: Exception) {
            throw KeyStoreException(Category.STORAGE)
        }
        if (canonical.parentFile != noBackup || canonical.name != rootName) {
            throw KeyStoreException(Category.STORAGE)
        }
        val status = try {
            Os.lstat(canonical.absolutePath)
        } catch (_: Exception) {
            throw KeyStoreException(Category.STORAGE)
        }
        if (status.st_mode and OsConstants.S_IFMT != OsConstants.S_IFDIR) {
            throw KeyStoreException(Category.STORAGE)
        }
        Os.chmod(canonical.absolutePath, PRIVATE_DIRECTORY_MODE)
        return canonical
    }

    private fun rootFile() = File(context.noBackupFilesDir, rootName)

    private fun validatePrivateFile(file: File) {
        val status = try {
            Os.lstat(file.absolutePath)
        } catch (_: Exception) {
            throw KeyStoreException(Category.STORAGE)
        }
        if (status.st_mode and OsConstants.S_IFMT != OsConstants.S_IFREG ||
            status.st_mode and 0x3f != 0
        ) {
            throw KeyStoreException(Category.STORAGE)
        }
    }

    private fun rejectSymlinkIfPresent(file: File) {
        val status = try {
            Os.lstat(file.absolutePath)
        } catch (error: ErrnoException) {
            if (error.errno == OsConstants.ENOENT) return
            throw KeyStoreException(Category.STORAGE)
        } catch (_: Exception) {
            throw KeyStoreException(Category.STORAGE)
        }
        if (status.st_mode and OsConstants.S_IFMT == OsConstants.S_IFLNK) {
            throw KeyStoreException(Category.STORAGE)
        }
    }

    private fun syncDirectory(directory: File) {
        val descriptor = Os.open(directory.absolutePath, OsConstants.O_RDONLY, 0)
        try {
            Os.fsync(descriptor)
        } finally {
            Os.close(descriptor)
        }
    }

    private fun requireSupportedApi() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            throw KeyStoreException(Category.UNSUPPORTED_API)
        }
    }

    private fun identityAlias(identityId: ByteArray) = alias(identityAliasPrefix, identityId)

    private fun signingAlias(identityId: ByteArray) = alias(signingAliasPrefix, identityId)

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    enum class Category {
        ALIAS_COLLISION,
        ALREADY_EXISTS,
        GENERATION_FAILED,
        INCOMPLETE,
        MALFORMED,
        METADATA_MISMATCH,
        MISSING,
        STORAGE,
        STRONGBOX_UNAVAILABLE,
        UNSUPPORTED_API,
        WRONG_KEY_ROLE,
        WRONG_SECURITY_LEVEL,
        DELETION_PENDING,
    }

    class KeyStoreException(val category: Category) : Exception()

    private sealed class StoredState(open val identityId: ByteArray) {
        data class Preparing(override val identityId: ByteArray) : StoredState(identityId)
        data class Committed(val public: PhoneIdentityPublic) : StoredState(public.identityId)
        data class Deleting(val public: PhoneIdentityPublic) : StoredState(public.identityId)
    }

    companion object {
        private const val STATE_VERSION = 1
        private const val PHASE_PREPARING = 0
        private const val PHASE_COMMITTED = 1
        private const val PHASE_DELETING = 2
        private const val IDENTITY_ID_BYTES = 16
        private const val PUBLIC_KEY_BYTES = 33
        private const val MAX_STATE_BYTES = 512
        private const val STATE_FILE_NAME = "identity.cbor"
        private const val P256_NAME = "secp256r1"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val PRIVATE_DIRECTORY_MODE = 0x1c0
        private const val PRIVATE_FILE_MODE = 0x180
        private const val PRODUCTION_ROOT = "age-plugin-phone-identity-v1"
        private const val PRODUCTION_IDENTITY_PREFIX = "age-plugin-phone-identity-v1-"
        private const val PRODUCTION_SIGNING_PREFIX = "age-plugin-phone-signing-v1-"
        private const val DOCTOR_ROOT = "age-plugin-phone-identity-doctor-v1"
        private const val DOCTOR_IDENTITY_PREFIX = "age-plugin-phone-identity-doctor-v1-"
        private const val DOCTOR_SIGNING_PREFIX = "age-plugin-phone-signing-doctor-v1-"
        private val cbor = ObjectMapper(CBORFactory())
        private val processLock = Any()

        fun production(context: Context) = PhoneIdentityKeyStore(
            context,
            PRODUCTION_ROOT,
            PRODUCTION_IDENTITY_PREFIX,
            PRODUCTION_SIGNING_PREFIX,
        )

        internal fun doctor(context: Context) = PhoneIdentityKeyStore(
            context,
            DOCTOR_ROOT,
            DOCTOR_IDENTITY_PREFIX,
            DOCTOR_SIGNING_PREFIX,
        )

        internal fun alias(prefix: String, identityId: ByteArray): String {
            if (identityId.size != IDENTITY_ID_BYTES || !isValidPrefix(prefix)) {
                throw KeyStoreException(Category.MALFORMED)
            }
            return prefix + identityId.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        }

        internal fun isValidAlias(value: String, prefix: String): Boolean =
            isValidPrefix(prefix) && Regex("^${Regex.escape(prefix)}[0-9a-f]{32}$").matches(value)

        private fun isValidPrefix(prefix: String): Boolean = prefix in setOf(
            PRODUCTION_IDENTITY_PREFIX,
            PRODUCTION_SIGNING_PREFIX,
            DOCTOR_IDENTITY_PREFIX,
            DOCTOR_SIGNING_PREFIX,
        )

        internal fun encodePreparing(identityId: ByteArray): ByteArray {
            if (identityId.size != IDENTITY_ID_BYTES) throw KeyStoreException(Category.MALFORMED)
            return cbor.writeValueAsBytes(cbor.createArrayNode().apply {
                add(STATE_VERSION)
                add(PHASE_PREPARING)
                add(identityId)
            })
        }

        internal fun encodeCommitted(public: PhoneIdentityPublic): ByteArray {
            validatePublic(public)
            return cbor.writeValueAsBytes(cbor.createArrayNode().apply {
                add(STATE_VERSION)
                add(PHASE_COMMITTED)
                add(public.identityId)
                add(public.recipient)
                add(public.identityPublicKey)
                add(public.signingPublicKey)
            })
        }

        internal fun encodeDeleting(public: PhoneIdentityPublic): ByteArray {
            validatePublic(public)
            return cbor.writeValueAsBytes(cbor.createArrayNode().apply {
                add(STATE_VERSION)
                add(PHASE_DELETING)
                add(public.identityId)
                add(public.recipient)
                add(public.identityPublicKey)
                add(public.signingPublicKey)
            })
        }

        internal fun decodeForTest(encoded: ByteArray): PhoneIdentityPublic? =
            when (val state = decodeState(encoded)) {
                is StoredState.Preparing -> null
                is StoredState.Committed -> state.public.copySafe()
                is StoredState.Deleting -> null
            }

        private fun decodeState(encoded: ByteArray): StoredState {
            val node = try {
                cbor.readTree(encoded) as? ArrayNode
            } catch (_: Exception) {
                null
            } ?: throw KeyStoreException(Category.MALFORMED)
            if (node.size() !in setOf(3, 6) || node[0].asInt(-1) != STATE_VERSION ||
                !MessageDigest.isEqual(cbor.writeValueAsBytes(node), encoded)
            ) {
                throw KeyStoreException(Category.MALFORMED)
            }
            val phase = node[1].asInt(-1)
            val identityId = binary(node, 2, IDENTITY_ID_BYTES)
            if (phase == PHASE_PREPARING && node.size() == 3) {
                return StoredState.Preparing(identityId)
            }
            if (phase !in setOf(PHASE_COMMITTED, PHASE_DELETING) ||
                node.size() != 6 || !node[3].isTextual
            ) {
                throw KeyStoreException(Category.MALFORMED)
            }
            val public = PhoneIdentityPublic(
                identityId,
                node[3].textValue(),
                binary(node, 4, PUBLIC_KEY_BYTES),
                binary(node, 5, PUBLIC_KEY_BYTES),
            )
            validatePublic(public)
            val canonical = if (phase == PHASE_COMMITTED) {
                encodeCommitted(public)
            } else {
                encodeDeleting(public)
            }
            if (!MessageDigest.isEqual(canonical, encoded)) {
                throw KeyStoreException(Category.MALFORMED)
            }
            return if (phase == PHASE_COMMITTED) {
                StoredState.Committed(public)
            } else {
                StoredState.Deleting(public)
            }
        }

        private fun validatePublic(public: PhoneIdentityPublic) {
            if (public.identityId.size != IDENTITY_ID_BYTES ||
                public.identityPublicKey.size != PUBLIC_KEY_BYTES ||
                public.signingPublicKey.size != PUBLIC_KEY_BYTES ||
                MessageDigest.isEqual(public.identityPublicKey, public.signingPublicKey)
            ) {
                throw KeyStoreException(Category.MALFORMED)
            }
            val identityKey = try {
                TaggedRecipientCrypto.decodeCompressed(public.identityPublicKey)
            } catch (_: Exception) {
                throw KeyStoreException(Category.MALFORMED)
            }
            try {
                TaggedRecipientCrypto.decodeCompressed(public.signingPublicKey)
            } catch (_: Exception) {
                throw KeyStoreException(Category.MALFORMED)
            }
            if (TaggedRecipientCrypto.encodeRecipient(identityKey) != public.recipient ||
                public.recipient.toByteArray().size > 160
            ) {
                throw KeyStoreException(Category.MALFORMED)
            }
        }

        private fun binary(node: ArrayNode, index: Int, size: Int): ByteArray {
            if (!node[index].isBinary) throw KeyStoreException(Category.MALFORMED)
            return node[index].binaryValue().also {
                if (it.size != size) throw KeyStoreException(Category.MALFORMED)
            }
        }

        private fun compressed(publicKey: PublicKey): ByteArray = try {
            TaggedRecipientCrypto.encodeCompressed(publicKey)
        } catch (_: Exception) {
            throw KeyStoreException(Category.WRONG_KEY_ROLE)
        }

        private fun publicEqual(left: PhoneIdentityPublic, right: PhoneIdentityPublic): Boolean =
            MessageDigest.isEqual(left.identityId, right.identityId) &&
                left.recipient == right.recipient &&
                MessageDigest.isEqual(left.identityPublicKey, right.identityPublicKey) &&
                MessageDigest.isEqual(left.signingPublicKey, right.signingPublicKey)

        private fun PhoneKeyInspection.isAcceptable(): Boolean =
            identityStrongBox && identityAgreeOnly && identityAuthPerUse &&
                identityBiometricStrong && signingStrongBox && signingPurposeSignOnly &&
                signingNoUserAuth && privateKeysNonExportable
    }
}
