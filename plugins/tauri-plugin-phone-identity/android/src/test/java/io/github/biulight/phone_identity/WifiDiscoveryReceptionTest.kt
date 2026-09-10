package io.github.biulight.phone_identity

import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class WifiDiscoveryReceptionTest {
    @Test
    fun closeReleasesOnceIncludingConcurrentLifecycleClosure() {
        val acquired = AtomicInteger()
        val released = AtomicInteger()
        val reception = WifiDiscoveryReception.acquire({ acquired.incrementAndGet() }, { released.incrementAndGet() })
        val threads = List(4) { Thread { reception.close() }.apply { start() } }
        threads.forEach { it.join() }
        reception.close()
        assertEquals(1, acquired.get())
        assertEquals(1, released.get())
    }

    @Test
    fun acquisitionFailureReleasesPartialOwnershipAndDoesNotCreateListener() {
        var released = 0
        assertThrows(IllegalStateException::class.java) {
            WifiDiscoveryReception.acquire({ throw IllegalStateException() }, { released += 1 })
        }
        assertEquals(1, released)
    }

    @Test
    fun listenerCloseAndBindFailureReleaseReception() {
        var released = 0
        val reception = WifiDiscoveryReception.acquire({}, { released += 1 })
        val responder = WifiDiscoveryResponder.start(PhoneStreamSession.Purpose.UNWRAP, { reception }) { null }
        responder.close()
        responder.close()
        assertEquals(1, released)
        DatagramSocket(null).use { occupied ->
            occupied.reuseAddress = false
            occupied.bind(InetSocketAddress("0.0.0.0", WifiDiscoveryCodec.DISCOVERY_PORT))
            val failed = WifiDiscoveryReception.acquire({}, { released += 1 })
            assertThrows(StreamTransportException::class.java) {
                WifiDiscoveryResponder.start(PhoneStreamSession.Purpose.UNWRAP, { failed }) { null }
            }
        }
        assertEquals(2, released)
    }
}
