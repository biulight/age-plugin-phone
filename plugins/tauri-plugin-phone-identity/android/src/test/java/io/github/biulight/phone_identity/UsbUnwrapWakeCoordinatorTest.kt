package io.github.biulight.phone_identity

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UsbUnwrapWakeCoordinatorTest {
    @After
    fun resetCoordinator() {
        UsbUnwrapWakeCoordinator.resetForTest()
    }

    @Test
    fun coldStartWakeIsQueuedOnceAndDrainedOnce() {
        var starts = 0
        val owner = Any()

        assertTrue(UsbUnwrapWakeCoordinator.request())
        assertFalse(UsbUnwrapWakeCoordinator.request())
        UsbUnwrapWakeCoordinator.register(owner) {
            starts += 1
            true
        }

        assertEquals(1, starts)
        UsbUnwrapWakeCoordinator.unregister(owner)
    }

    @Test
    fun warmWakeStartsImmediatelyAndBusyWakeIsDropped() {
        var starts = 0
        var accepts = true
        val owner = Any()
        UsbUnwrapWakeCoordinator.register(owner) {
            starts += 1
            accepts
        }

        assertTrue(UsbUnwrapWakeCoordinator.request())
        accepts = false
        assertFalse(UsbUnwrapWakeCoordinator.request())
        assertEquals(2, starts)

        UsbUnwrapWakeCoordinator.unregister(owner)
        UsbUnwrapWakeCoordinator.register(Any()) {
            starts += 1
            true
        }
        assertEquals(2, starts)
    }

    @Test
    fun acceptsOnlyTheExactPayloadFreeAction() {
        assertTrue(valid())
        assertFalse(valid(action = "wrong.action"))
        assertFalse(valid(hasData = true))
        assertFalse(valid(hasClipData = true))
        assertFalse(valid(hasExtras = true))
        assertFalse(valid(hasSelector = true))
        assertFalse(valid(hasType = true))
        assertFalse(valid(hasCategories = true))
        assertFalse(valid(hasIdentifier = true))
        assertFalse(valid(hasSourceBounds = true))
    }

    private fun valid(
        action: String? = UsbUnwrapWakeCoordinator.ACTION,
        hasData: Boolean = false,
        hasClipData: Boolean = false,
        hasExtras: Boolean = false,
        hasSelector: Boolean = false,
        hasType: Boolean = false,
        hasCategories: Boolean = false,
        hasIdentifier: Boolean = false,
        hasSourceBounds: Boolean = false,
    ): Boolean = UsbUnwrapWakeCoordinator.isPayloadFreeUnwrapAction(
        action,
        hasData,
        hasClipData,
        hasExtras,
        hasSelector,
        hasType,
        hasCategories,
        hasIdentifier,
        hasSourceBounds,
    )
}
