package io.github.biulight.phone_identity

internal fun interface CompletedQrMessageVerifier<T> {
    fun verify(message: ByteArray): T
}

internal sealed class QrScanStatus<out T> {
    data object Ignored : QrScanStatus<Nothing>()

    class InProgress(val received: Int, val total: Int) : QrScanStatus<Nothing>()

    class Complete<T>(val display: T, val framesAccepted: Int) : QrScanStatus<T>()
}

/** Keeps raw scanner values and completed protocol bytes inside the native boundary. */
internal class QrScanSession<T>(
    private val verifier: CompletedQrMessageVerifier<T>,
) {
    private val reassembler = QrReassembler()
    private var startedAtMs: Long? = null
    private var closed = false
    private var accepted = 0

    fun accept(rawValue: String, nowMs: Long): QrScanStatus<T> {
        ensureOpen()
        if (!QrFraming.isFrameCandidate(rawValue)) return QrScanStatus.Ignored

        val status = try {
            reassembler.push(rawValue, nowMs)
        } catch (error: QrFraming.QrException) {
            if (error.category == QrFraming.Category.DIFFERENT_TRANSFER) {
                return QrScanStatus.Ignored
            }
            close()
            throw error
        }
        if (startedAtMs == null) startedAtMs = nowMs
        accepted += 1
        return when (status) {
            is QrAssemblyStatus.InProgress -> QrScanStatus.InProgress(status.received, status.total)
            is QrAssemblyStatus.Complete -> {
                try {
                    QrScanStatus.Complete(verifier.verify(status.message), accepted)
                } finally {
                    status.message.fill(0)
                    close()
                }
            }
        }
    }

    fun expire(nowMs: Long) {
        ensureOpen()
        val started = startedAtMs ?: return
        val category = when {
            nowMs < started -> QrFraming.Category.CLOCK_ROLLBACK
            nowMs - started > QrFraming.MAX_ASSEMBLY_AGE_MS -> QrFraming.Category.TIMEOUT
            else -> return
        }
        close()
        throw QrFraming.QrException(category)
    }

    fun cancel() {
        close()
    }

    fun hasStarted(): Boolean = startedAtMs != null

    private fun ensureOpen() {
        if (closed) throw QrFraming.QrException(QrFraming.Category.POISONED)
    }

    private fun close() {
        if (closed) return
        reassembler.reset()
        startedAtMs = null
        closed = true
    }
}
