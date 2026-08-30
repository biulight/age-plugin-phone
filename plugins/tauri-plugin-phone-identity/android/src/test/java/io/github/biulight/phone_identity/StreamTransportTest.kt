package io.github.biulight.phone_identity

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

class StreamTransportTest {
    @Test
    fun roundTripsBoundedOpaqueMessage() {
        val encoded = ByteArrayOutputStream()
        val sessionId = ByteArray(16) { it.toByte() }
        StreamTransportCodec.write(
            encoded,
            PhoneStreamSession.Purpose.PAIRING,
            StreamTransportCodec.DESKTOP_REQUEST,
            sessionId,
            byteArrayOf(1, 2, 3),
        )
        val decoded = StreamTransportCodec.read(
            ByteArrayInputStream(encoded.toByteArray()),
            PhoneStreamSession.Purpose.PAIRING,
            StreamTransportCodec.DESKTOP_REQUEST,
            null,
        )
        assertArrayEquals(sessionId, decoded.sessionId)
        assertArrayEquals(byteArrayOf(1, 2, 3), decoded.body)
    }

    @Test
    fun rejectsWrongPurposeDirectionSessionAndVersion() {
        val sessionId = ByteArray(16) { 7 }
        val encoded = ByteArrayOutputStream().also {
            StreamTransportCodec.write(
                it,
                PhoneStreamSession.Purpose.PAIRING,
                StreamTransportCodec.DESKTOP_REQUEST,
                sessionId,
                byteArrayOf(1),
            )
        }.toByteArray()
        assertThrows(StreamTransportException::class.java) {
            StreamTransportCodec.read(
                ByteArrayInputStream(encoded),
                PhoneStreamSession.Purpose.UNWRAP,
                StreamTransportCodec.DESKTOP_REQUEST,
                null,
            )
        }
        assertThrows(StreamTransportException::class.java) {
            StreamTransportCodec.read(
                ByteArrayInputStream(encoded),
                PhoneStreamSession.Purpose.PAIRING,
                StreamTransportCodec.PHONE_RESPONSE,
                null,
            )
        }
        assertThrows(StreamTransportException::class.java) {
            StreamTransportCodec.read(
                ByteArrayInputStream(encoded),
                PhoneStreamSession.Purpose.PAIRING,
                StreamTransportCodec.DESKTOP_REQUEST,
                ByteArray(16),
            )
        }
        encoded[5] = 2
        assertThrows(StreamTransportException::class.java) {
            StreamTransportCodec.read(
                ByteArrayInputStream(encoded),
                PhoneStreamSession.Purpose.PAIRING,
                StreamTransportCodec.DESKTOP_REQUEST,
                null,
            )
        }
    }

    @Test
    fun rejectsOversizeAndTruncation() {
        val oversized = ByteArrayOutputStream().also {
            StreamTransportCodec.write(
                it,
                PhoneStreamSession.Purpose.UNWRAP,
                StreamTransportCodec.DESKTOP_REQUEST,
                ByteArray(16),
                byteArrayOf(),
            )
        }.toByteArray()
        oversized[24] = 1
        assertThrows(StreamTransportException::class.java) {
            StreamTransportCodec.read(
                ByteArrayInputStream(oversized),
                PhoneStreamSession.Purpose.UNWRAP,
                StreamTransportCodec.DESKTOP_REQUEST,
                null,
            )
        }
        assertThrows(StreamTransportException::class.java) {
            StreamTransportCodec.read(
                ByteArrayInputStream(ByteArray(27)),
                PhoneStreamSession.Purpose.UNWRAP,
                StreamTransportCodec.DESKTOP_REQUEST,
                null,
            )
        }
    }

    @Test
    fun peerDisconnectNotifiesExactlyOnce() {
        val input = PipedInputStream()
        val output = PipedOutputStream(input)
        val notified = CountDownLatch(1)
        val calls = AtomicInteger()
        PeerDisconnectMonitor(input) {
            calls.incrementAndGet()
            notified.countDown()
        }.start()

        output.close()

        assertTrue(notified.await(1, TimeUnit.SECONDS))
        assertEquals(1, calls.get())
    }

    @Test
    fun unexpectedDesktopByteIsTerminal() {
        val input = PipedInputStream()
        val output = PipedOutputStream(input)
        val notified = CountDownLatch(1)
        PeerDisconnectMonitor(input) { notified.countDown() }.start()

        output.write(1)
        output.flush()

        assertTrue(notified.await(1, TimeUnit.SECONDS))
        output.close()
    }

    @Test
    fun localSuppressionDoesNotReportPeerLoss() {
        val input = PipedInputStream()
        val output = PipedOutputStream(input)
        val notified = CountDownLatch(1)
        val monitor = PeerDisconnectMonitor(input) { notified.countDown() }
        monitor.start()

        monitor.suppress()
        output.close()

        assertFalse(notified.await(100, TimeUnit.MILLISECONDS))
    }

    @Test
    fun foregroundWifiListenerAcceptsOneBoundedUnwrap() {
        val listener = PhoneWifiListener.start(0)
        val response = AtomicReference<ByteArray>()
        val client = Thread {
            Socket().use { socket ->
                socket.soTimeout = 1_000
                socket.connect(InetSocketAddress("127.0.0.1", listener.localPort), 1_000)
                val sessionId = ByteArray(16) { 9 }
                StreamTransportCodec.write(
                    socket.getOutputStream(),
                    PhoneStreamSession.Purpose.UNWRAP,
                    StreamTransportCodec.DESKTOP_REQUEST,
                    sessionId,
                    byteArrayOf(4, 5, 6),
                )
                socket.getOutputStream().flush()
                response.set(
                    StreamTransportCodec.read(
                        socket.getInputStream(),
                        PhoneStreamSession.Purpose.UNWRAP,
                        StreamTransportCodec.PHONE_RESPONSE,
                        sessionId,
                    ).body,
                )
            }
        }.apply { start() }

        val session = listener.acceptUnwrap()
        assertArrayEquals(byteArrayOf(4, 5, 6), session.receiveRequest())
        session.sendResponse(byteArrayOf(7, 8, 9))
        client.join(1_000)

        assertFalse(client.isAlive)
        assertArrayEquals(byteArrayOf(7, 8, 9), response.get())
    }

    @Test
    fun closingForegroundWifiListenerCancelsAccept() {
        val listener = PhoneWifiListener.start(0)
        listener.close()
        assertThrows(StreamTransportException::class.java) { listener.acceptUnwrap() }
    }
}
