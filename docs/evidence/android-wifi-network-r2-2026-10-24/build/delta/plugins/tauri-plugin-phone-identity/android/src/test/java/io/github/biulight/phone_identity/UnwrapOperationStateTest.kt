package io.github.biulight.phone_identity

import java.util.UUID
import org.junit.Assert.*
import org.junit.Test

class UnwrapOperationStateTest {
    private data class Pending(val token: UUID = UUID.randomUUID(), val wifi: Boolean = true)

    @Test
    fun cancelledWorkerCannotPublishOverNewGeneration() {
        val state = UnwrapOperationState<Pending> { it.token }
        val oldWorker = UUID.randomUUID()
        state.wifiToken = oldWorker
        state.wifiToken = null // network loss before the worker publishes its prepared request
        val newWorker = UUID.randomUUID()
        state.wifiToken = newWorker
        assertFalse(state.publishWifi(oldWorker, Pending()))
        assertEquals(newWorker, state.wifiToken)
        assertNull(state.pending)
        val current = Pending()
        assertTrue(state.publishWifi(newWorker, current))
        assertFalse(state.publishWifi(oldWorker, Pending()))
        assertSame(current, state.pending)
    }

    @Test
    fun cancelledAuthorizationRejectsLateSuccessTimeoutAndDisconnectAgainstReplacement() {
        val state = UnwrapOperationState<Pending> { it.token }
        val old = Pending()
        state.pending = old
        assertSame(old, state.cancelMatching { it.wifi })
        val current = Pending()
        state.pending = current
        assertFalse(state.isActive(old.token))
        assertNull(state.beginResponse(old.token)) // delayed biometric success
        assertNull(state.takePending(old.token)) // delayed timeout or peer-disconnect callback
        assertTrue(state.isActive(current.token))
        assertSame(current, state.beginResponse(current.token))
        assertNull(state.beginResponse(current.token)) // response handoff is one-shot
        assertSame(current, state.takeResponse(current.token))
        assertNull(state.takeResponse(current.token))
    }

    @Test
    fun cancellationAfterResponseHandoffCannotCompleteOrClearReplacement() {
        val state = UnwrapOperationState<Pending> { it.token }
        val old = Pending()
        state.pending = old
        assertSame(old, state.beginResponse(old.token))
        assertSame(old, state.cancelMatching { it.wifi })
        val current = Pending()
        state.pending = current
        assertSame(current, state.beginResponse(current.token))
        assertNull(state.takeResponse(old.token))
        assertSame(current, state.response)
    }

    @Test
    fun wifiCancellationDoesNotCancelOtherTransportAndWorkerCannotOverwritePending() {
        val state = UnwrapOperationState<Pending> { it.token }
        val usb = Pending(wifi = false)
        state.pending = usb
        assertNull(state.cancelMatching { it.wifi })
        val worker = UUID.randomUUID()
        state.wifiToken = worker
        assertFalse(state.publishWifi(worker, Pending()))
        assertSame(usb, state.pending)
    }
}
