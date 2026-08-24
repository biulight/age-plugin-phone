package io.github.biulight.phone_identity

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

internal class EncodedQrFrame internal constructor(internal val value: String) {
    override fun toString(): String = "EncodedQrFrame([REDACTED])"
}

internal sealed class QrAssemblyStatus {
    class InProgress(val received: Int, val total: Int) : QrAssemblyStatus()

    class Complete(val message: ByteArray) : QrAssemblyStatus() {
        override fun toString(): String = "Complete(messageBytes=${message.size})"
    }
}

internal object QrFraming {
    const val DEFAULT_CHUNK_BYTES = 600
    const val MAX_MESSAGE_BYTES = 65_536
    const val MAX_FRAGMENTS = 128
    const val MAX_ASSEMBLY_AGE_MS = 30_000L
    private const val MAX_ENCODED_FRAME_CHARS = 2_048
    private const val PREFIX = "age-phone:qr1:"
    private const val VERSION = 1
    private const val FRAME_TYPE = 1
    private val digestDomain = "age-plugin-phone/qr-message-digest/v1"
        .toByteArray(Charsets.US_ASCII)
    private val cbor = ObjectMapper(CBORFactory())
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    fun isFrameCandidate(value: String): Boolean = value.startsWith(PREFIX)

    fun fragment(
        message: ByteArray,
        chunkBytes: Int = DEFAULT_CHUNK_BYTES,
        random: SecureRandom = SecureRandom(),
    ): List<EncodedQrFrame> {
        if (message.isEmpty() || message.size > MAX_MESSAGE_BYTES) throw QrException(Category.MESSAGE_SIZE)
        if (chunkBytes !in 1..DEFAULT_CHUNK_BYTES) throw QrException(Category.CHUNK_SIZE)
        val count = (message.size + chunkBytes - 1) / chunkBytes
        if (count > MAX_FRAGMENTS) throw QrException(Category.TOO_MANY_FRAGMENTS)
        val transferId = ByteArray(16).also(random::nextBytes)
        val digest = messageDigest(message)
        return (0 until count).map { index ->
            val start = index * chunkBytes
            val chunk = message.copyOfRange(start, minOf(start + chunkBytes, message.size))
            try {
                encode(
                    Frame(transferId, digest, index, count, message.size, chunk),
                )
            } finally {
                chunk.fill(0)
            }
        }
    }

    internal fun decode(encoded: String): Frame {
        if (encoded.length > MAX_ENCODED_FRAME_CHARS || !encoded.startsWith(PREFIX)) {
            throw QrException(Category.MALFORMED_FRAME)
        }
        val payload = encoded.substring(PREFIX.length)
        if (payload.isEmpty() || payload.contains('=')) throw QrException(Category.MALFORMED_FRAME)
        val encodedBytes = try {
            decoder.decode(payload)
        } catch (_: IllegalArgumentException) {
            throw QrException(Category.MALFORMED_FRAME)
        }
        if (encoder.encodeToString(encodedBytes) != payload) throw QrException(Category.MALFORMED_FRAME)
        val nodes = try {
            cbor.readTree(encodedBytes) as? ArrayNode
        } catch (_: Exception) {
            null
        } ?: throw QrException(Category.MALFORMED_FRAME)
        if (nodes.size() != 8) throw QrException(Category.MALFORMED_FRAME)
        val version = integer(nodes[0])
        if (version != VERSION) throw QrException(Category.UNSUPPORTED_VERSION)
        val type = integer(nodes[1])
        if (type != FRAME_TYPE) throw QrException(Category.UNSUPPORTED_TYPE)
        val frame = Frame(
            transferId = bytes(nodes[2], 16),
            digest = bytes(nodes[3], 32),
            index = integer(nodes[4]),
            count = integer(nodes[5]),
            totalLength = integer(nodes[6]),
            chunk = bytes(nodes[7], null),
        )
        if (frame.count !in 1..MAX_FRAGMENTS || frame.index !in 0 until frame.count ||
            frame.totalLength !in 1..MAX_MESSAGE_BYTES || frame.chunk.isEmpty() ||
            frame.chunk.size > DEFAULT_CHUNK_BYTES || frame.chunk.size > frame.totalLength ||
            !MessageDigest.isEqual(encodeCbor(frame), encodedBytes)
        ) {
            frame.chunk.fill(0)
            throw QrException(Category.MALFORMED_FRAME)
        }
        return frame
    }

    internal fun encode(frame: Frame): EncodedQrFrame {
        val value = PREFIX + encoder.encodeToString(encodeCbor(frame))
        if (value.length > MAX_ENCODED_FRAME_CHARS) throw QrException(Category.CHUNK_SIZE)
        return EncodedQrFrame(value)
    }

    private fun encodeCbor(frame: Frame): ByteArray = cbor.writeValueAsBytes(
        cbor.createArrayNode().apply {
            add(VERSION)
            add(FRAME_TYPE)
            add(frame.transferId)
            add(frame.digest)
            add(frame.index)
            add(frame.count)
            add(frame.totalLength)
            add(frame.chunk)
        },
    )

    private fun integer(node: JsonNode): Int {
        if (!node.isIntegralNumber || !node.canConvertToInt() || node.intValue() < 0) {
            throw QrException(Category.MALFORMED_FRAME)
        }
        return node.intValue()
    }

    private fun bytes(node: JsonNode, size: Int?): ByteArray {
        if (!node.isBinary) throw QrException(Category.MALFORMED_FRAME)
        val value = try {
            node.binaryValue()
        } catch (_: Exception) {
            throw QrException(Category.MALFORMED_FRAME)
        }
        if (size != null && value.size != size) throw QrException(Category.MALFORMED_FRAME)
        return value
    }

    internal fun messageDigest(message: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").run {
        update(digestDomain)
        update(0.toByte())
        digest(message)
    }

    internal class Frame(
        val transferId: ByteArray,
        val digest: ByteArray,
        val index: Int,
        val count: Int,
        val totalLength: Int,
        val chunk: ByteArray,
    ) {
        override fun toString(): String = "Frame([REDACTED])"
    }

    enum class Category {
        CHUNK_SIZE,
        CLOCK_ROLLBACK,
        CONFLICTING_FRAGMENT,
        DIFFERENT_TRANSFER,
        DIGEST_MISMATCH,
        MALFORMED_FRAME,
        MESSAGE_SIZE,
        POISONED,
        TIMEOUT,
        TOO_MANY_FRAGMENTS,
        UNSUPPORTED_TYPE,
        UNSUPPORTED_VERSION,
    }

    class QrException(val category: Category) : Exception()
}

internal class QrReassembler {
    private var active: ActiveAssembly? = null
    private var poisoned = false

    fun push(encoded: String, nowMs: Long): QrAssemblyStatus {
        if (poisoned) throw QrFraming.QrException(QrFraming.Category.POISONED)
        if (nowMs < 0) throw QrFraming.QrException(QrFraming.Category.CLOCK_ROLLBACK)
        val frame = QrFraming.decode(encoded)
        try {
            if (active == null) active = ActiveAssembly(frame, nowMs)
            val current = requireNotNull(active)
            if (nowMs < current.startedAtMs) poison(QrFraming.Category.CLOCK_ROLLBACK)
            if (nowMs - current.startedAtMs > QrFraming.MAX_ASSEMBLY_AGE_MS) {
                poison(QrFraming.Category.TIMEOUT)
            }
            if (!MessageDigest.isEqual(frame.transferId, current.transferId) ||
                !MessageDigest.isEqual(frame.digest, current.digest) ||
                frame.count != current.count || frame.totalLength != current.totalLength
            ) {
                throw QrFraming.QrException(QrFraming.Category.DIFFERENT_TRANSFER)
            }

            val existing = current.chunks[frame.index]
            if (existing != null) {
                if (!MessageDigest.isEqual(existing, frame.chunk)) {
                    poison(QrFraming.Category.CONFLICTING_FRAGMENT)
                }
            } else {
                current.receivedBytes = try {
                    Math.addExact(current.receivedBytes, frame.chunk.size)
                } catch (_: ArithmeticException) {
                    poison(QrFraming.Category.MALFORMED_FRAME)
                }
                if (current.receivedBytes > current.totalLength) {
                    poison(QrFraming.Category.MALFORMED_FRAME)
                }
                current.chunks[frame.index] = frame.chunk.copyOf()
                current.received += 1
            }

            if (current.received != current.count) {
                return QrAssemblyStatus.InProgress(current.received, current.count)
            }
            return assemble(current)
        } finally {
            frame.chunk.fill(0)
        }
    }

    fun reset() {
        clearActive()
        poisoned = false
    }

    private fun assemble(current: ActiveAssembly): QrAssemblyStatus {
        try {
            val firstSize = current.chunks.firstOrNull()?.size
                ?: poison(QrFraming.Category.MALFORMED_FRAME)
            if (firstSize == 0 || current.chunks.dropLast(1).any { it == null || it.size != firstSize } ||
                current.chunks.lastOrNull().let { it == null || it.isEmpty() || it.size > firstSize }
            ) {
                poison(QrFraming.Category.MALFORMED_FRAME)
            }
            val message = ByteArray(current.totalLength)
            var offset = 0
            for (chunk in current.chunks) {
                requireNotNull(chunk).copyInto(message, offset)
                offset += chunk.size
            }
            if (offset != message.size) {
                message.fill(0)
                poison(QrFraming.Category.MALFORMED_FRAME)
            }
            if (!MessageDigest.isEqual(QrFraming.messageDigest(message), current.digest)) {
                message.fill(0)
                poison(QrFraming.Category.DIGEST_MISMATCH)
            }
            clearActive()
            return QrAssemblyStatus.Complete(message)
        } catch (error: QrFraming.QrException) {
            throw error
        } catch (_: Exception) {
            poison(QrFraming.Category.MALFORMED_FRAME)
        }
    }

    private fun poison(category: QrFraming.Category): Nothing {
        clearActive()
        poisoned = true
        throw QrFraming.QrException(category)
    }

    private fun clearActive() {
        active?.chunks?.forEach { it?.fill(0) }
        active = null
    }

    private class ActiveAssembly(frame: QrFraming.Frame, val startedAtMs: Long) {
        val transferId = frame.transferId.copyOf()
        val digest = frame.digest.copyOf()
        val count = frame.count
        val totalLength = frame.totalLength
        val chunks = arrayOfNulls<ByteArray>(count)
        var received = 0
        var receivedBytes = 0
    }
}
