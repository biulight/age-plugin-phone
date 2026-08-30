package io.github.biulight.phone_identity

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit

/** One bounded native-only request/response stream carried by ADB reverse. */
internal class PhoneStreamSession private constructor(
    private val socket: Socket,
    private val purpose: Purpose,
) : AutoCloseable {
    enum class Purpose(val code: Int) { PAIRING(1), UNWRAP(2) }

    private var sessionId: ByteArray? = null
    private var closed = false
    private var peerDisconnectMonitor: PeerDisconnectMonitor? = null

    fun receiveRequest(): ByteArray {
        check(!closed && sessionId == null)
        val message = StreamTransportCodec.read(
            socket.getInputStream(),
            purpose,
            StreamTransportCodec.DESKTOP_REQUEST,
            null,
        )
        sessionId = message.sessionId
        return message.body
    }

    fun sendResponse(response: ByteArray) {
        check(!closed)
        val id = sessionId ?: throw StreamTransportException()
        peerDisconnectMonitor?.suppress()
        val write = FutureTask<Unit> {
            StreamTransportCodec.write(
                socket.getOutputStream(),
                purpose,
                StreamTransportCodec.PHONE_RESPONSE,
                id,
                response,
            )
            socket.getOutputStream().flush()
        }
        Thread(write, "phone-adb-response").start()
        try {
            write.get(WRITE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (error: Exception) {
            write.cancel(true)
            throw StreamTransportException(error)
        } finally {
            close()
        }
    }

    fun watchPeerDisconnect(onDisconnect: () -> Unit) {
        check(!closed && sessionId != null && peerDisconnectMonitor == null)
        PeerDisconnectMonitor(socket.getInputStream(), onDisconnect).also {
            peerDisconnectMonitor = it
            it.start()
        }
    }

    override fun close() {
        if (closed) return
        peerDisconnectMonitor?.suppress()
        closed = true
        sessionId?.fill(0)
        sessionId = null
        try {
            socket.close()
        } catch (_: Exception) {
            // The session is terminal even when the OS close reports an error.
        }
    }

    companion object {
        private const val LOOPBACK_PORT = 47_139
        private const val CONNECT_TIMEOUT_MS = 30_000
        private const val MESSAGE_TIMEOUT_MS = 90_000
        private const val WRITE_TIMEOUT_MS = 30_000L

        fun connect(purpose: Purpose): PhoneStreamSession {
            val socket = Socket()
            try {
                socket.soTimeout = MESSAGE_TIMEOUT_MS
                socket.tcpNoDelay = true
                socket.connect(
                    InetSocketAddress("127.0.0.1", LOOPBACK_PORT),
                    CONNECT_TIMEOUT_MS,
                )
                return PhoneStreamSession(socket, purpose)
            } catch (error: Exception) {
                try {
                    socket.close()
                } catch (_: Exception) {
                    // Preserve the original fail-closed category.
                }
                throw StreamTransportException(error)
            }
        }
    }
}

/**
 * Watches the otherwise-unused desktop-to-phone half of a one-shot session.
 *
 * EOF, reset, timeout, or any unexpected extra byte is terminal. Local close and the start of a
 * response suppress the callback before they disturb the socket, so only peer-side loss reaches
 * the biometric lifecycle.
 */
internal class PeerDisconnectMonitor(
    private val input: InputStream,
    private val onDisconnect: () -> Unit,
) {
    private val lock = Any()
    private var terminal = false

    fun start() {
        Thread(
            {
                try {
                    input.read()
                } catch (_: Exception) {
                    // EOF, reset, timeout, and malformed extra input are the same terminal signal.
                }
                val notify = synchronized(lock) {
                    if (terminal) {
                        false
                    } else {
                        terminal = true
                        true
                    }
                }
                if (notify) onDisconnect()
            },
            "phone-adb-peer-watch",
        ).apply { isDaemon = true }.start()
    }

    fun suppress() {
        synchronized(lock) { terminal = true }
    }
}

internal data class StreamTransportMessage(val sessionId: ByteArray, val body: ByteArray)

internal object StreamTransportCodec {
    const val DESKTOP_REQUEST = 1
    const val PHONE_RESPONSE = 2
    private const val VERSION = 1
    private const val MAX_MESSAGE_BYTES = 65_536
    private val MAGIC = byteArrayOf(0x41, 0x50, 0x54, 0x53)

    fun read(
        input: InputStream,
        purpose: PhoneStreamSession.Purpose,
        direction: Int,
        expectedSessionId: ByteArray?,
    ): StreamTransportMessage {
        val header = ByteArray(28)
        try {
            DataInputStream(input).readFully(header)
            val version = ((header[4].toInt() and 0xff) shl 8) or
                (header[5].toInt() and 0xff)
            val sessionId = header.copyOfRange(8, 24)
            if (!header.copyOfRange(0, 4).contentEquals(MAGIC) ||
                version != VERSION ||
                (header[6].toInt() and 0xff) != purpose.code ||
                (header[7].toInt() and 0xff) != direction ||
                expectedSessionId != null && !sessionId.contentEquals(expectedSessionId)
            ) {
                sessionId.fill(0)
                throw StreamTransportException()
            }
            val length = ((header[24].toLong() and 0xff) shl 24) or
                ((header[25].toLong() and 0xff) shl 16) or
                ((header[26].toLong() and 0xff) shl 8) or
                (header[27].toLong() and 0xff)
            if (length > MAX_MESSAGE_BYTES) {
                sessionId.fill(0)
                throw StreamTransportException()
            }
            val body = ByteArray(length.toInt())
            try {
                DataInputStream(input).readFully(body)
            } catch (error: Exception) {
                body.fill(0)
                sessionId.fill(0)
                throw StreamTransportException(error)
            }
            return StreamTransportMessage(sessionId, body)
        } catch (error: StreamTransportException) {
            throw error
        } catch (error: Exception) {
            throw StreamTransportException(error)
        } finally {
            header.fill(0)
        }
    }

    fun write(
        output: OutputStream,
        purpose: PhoneStreamSession.Purpose,
        direction: Int,
        sessionId: ByteArray,
        body: ByteArray,
    ) {
        if (sessionId.size != 16 || body.size > MAX_MESSAGE_BYTES) {
            throw StreamTransportException()
        }
        val data = DataOutputStream(output)
        try {
            data.write(MAGIC)
            data.writeShort(VERSION)
            data.writeByte(purpose.code)
            data.writeByte(direction)
            data.write(sessionId)
            data.writeInt(body.size)
            data.write(body)
        } catch (error: Exception) {
            throw StreamTransportException(error)
        }
    }
}

internal class StreamTransportException(cause: Throwable? = null) : Exception(cause)
