package io.github.biulight.phone_identity

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.junit.Assert.assertArrayEquals
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
}
