package io.github.biulight.phone_identity

import android.content.Context
import java.security.MessageDigest

internal data class PairingConfirmationDisplay(
    val desktopLabel: String,
    val transcriptFingerprint: String,
)

internal data class CommittedPairingDisplay(
    val desktopLabel: String,
    val transcriptFingerprint: String,
)

internal fun interface PairingStateCreator {
    fun create(record: StoredPairingRecord, nowUnix: Long): PairingStateStore
}

internal fun interface PairingSessionFactory {
    fun begin(signedOffer: ByteArray, signedResponse: ByteArray): PairingConfirmationSession
}

internal class PairingConfirmationCoordinator(
    private val sessionFactory: PairingSessionFactory,
) {
    private val lock = Any()
    private var pending: PairingConfirmationSession? = null

    fun begin(signedOffer: ByteArray, signedResponse: ByteArray): PairingConfirmationDisplay {
        val session = sessionFactory.begin(signedOffer, signedResponse)
        synchronized(lock) {
            if (pending != null) {
                session.cancel()
                throw PairingConfirmationSession.PairingConfirmationException(
                    PairingConfirmationSession.Category.SESSION_ACTIVE,
                )
            }
            pending = session
        }
        return session.display
    }

    fun confirm(displayedFingerprint: String, nowUnix: Long): CommittedPairingDisplay {
        val session = synchronized(lock) {
            pending.also { pending = null }
        } ?: throw PairingConfirmationSession.PairingConfirmationException(
            PairingConfirmationSession.Category.SESSION_CLOSED,
        )
        return session.confirm(displayedFingerprint, nowUnix)
    }

    fun cancel() {
        synchronized(lock) {
            pending.also { pending = null }
        }?.cancel()
    }
}

/**
 * One verified pairing transcript awaiting an explicit native-UI comparison.
 *
 * The controller must call [confirm] only from the native fingerprint confirmation action. Raw QR
 * bytes and protocol objects never leave this session for a WebView presentation model.
 */
internal class PairingConfirmationSession private constructor(
    val display: PairingConfirmationDisplay,
    private val record: StoredPairingRecord,
    private val expectedFingerprint: ByteArray,
    private val stateCreator: PairingStateCreator,
) {
    private var terminal = false

    @Synchronized
    fun confirm(displayedFingerprint: String, nowUnix: Long): CommittedPairingDisplay {
        ensureOpen()
        terminal = true

        val confirmed = decodeCanonicalFingerprint(displayedFingerprint)
        if (confirmed == null || !MessageDigest.isEqual(confirmed, expectedFingerprint)) {
            throw PairingConfirmationException(Category.FINGERPRINT_MISMATCH)
        }

        try {
            stateCreator.create(record.copySafe(), nowUnix).use { }
        } catch (error: PairingStateStore.PairingStateException) {
            val category = if (error.category == PairingStateStore.Category.ALREADY_EXISTS) {
                Category.ALREADY_PAIRED
            } else {
                Category.STORAGE
            }
            throw PairingConfirmationException(category)
        } catch (_: Exception) {
            throw PairingConfirmationException(Category.STORAGE)
        }

        return CommittedPairingDisplay(display.desktopLabel, display.transcriptFingerprint)
    }

    @Synchronized
    fun cancel() {
        if (!terminal) terminal = true
    }

    private fun ensureOpen() {
        if (terminal) throw PairingConfirmationException(Category.SESSION_CLOSED)
    }

    companion object {
        fun begin(
            context: Context,
            signedOffer: ByteArray,
            signedResponse: ByteArray,
        ): PairingConfirmationSession = beginWithCreator(
            signedOffer,
            signedResponse,
            PairingStateCreator { record, nowUnix ->
                PairingStateStore.create(context, record, nowUnix)
            },
        )

        internal fun beginWithCreator(
            signedOffer: ByteArray,
            signedResponse: ByteArray,
            stateCreator: PairingStateCreator,
        ): PairingConfirmationSession {
            val record = try {
                val offer = OfflineEnvelopeCrypto.verifyPairingOffer(signedOffer)
                val response = OfflineEnvelopeCrypto.verifyPairingResponse(signedResponse, offer)
                StoredPairingRecord.fromVerifiedTranscript(offer, response).also {
                    PairingStateStore.validateRecordForCreation(it)
                }
            } catch (_: Exception) {
                throw PairingConfirmationException(Category.MALFORMED_TRANSCRIPT)
            }
            val fingerprint = record.transcriptFingerprint.copyOf()
            return PairingConfirmationSession(
                PairingConfirmationDisplay(
                    desktopLabel = record.desktopLabel,
                    transcriptFingerprint = encodeFingerprint(fingerprint),
                ),
                record.copySafe(),
                fingerprint,
                stateCreator,
            )
        }

        private fun encodeFingerprint(value: ByteArray): String =
            value.joinToString("") { "%02x".format(it.toInt() and 0xff) }

        private fun decodeCanonicalFingerprint(value: String): ByteArray? {
            if (value.length != 64 || value.any { it !in '0'..'9' && it !in 'a'..'f' }) return null
            return ByteArray(32) { index ->
                value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
        }
    }

    enum class Category {
        ALREADY_PAIRED,
        FINGERPRINT_MISMATCH,
        MALFORMED_TRANSCRIPT,
        SESSION_ACTIVE,
        SESSION_CLOSED,
        STORAGE,
    }

    class PairingConfirmationException(val category: Category) : Exception()
}
