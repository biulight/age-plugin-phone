package io.github.biulight.phone_identity

import org.junit.Assert.assertEquals
import org.junit.Test

class WifiNetworkMonitorTest {
    @Test
    fun reconnectWithSameAddressStillInvalidatesTheOldResources() {
        val events = mutableListOf<Boolean>()
        val state = WifiNetworkState<String>(events::add)
        state.available("first-network")
        state.properties("first-network", "wlan0:192.168.1.2/24")
        state.lost("first-network")
        state.available("replacement-network")
        state.properties("replacement-network", "wlan0:192.168.1.2/24")
        assertEquals(listOf(false, true, false, false, true), events)
    }

    @Test
    fun ipv4RemovalAndAddressChangeInvalidateButDuplicateNotificationsDoNot() {
        val events = mutableListOf<Boolean>()
        val state = WifiNetworkState<String>(events::add)
        state.properties("network", "wlan0:192.168.1.2/24")
        state.available("network")
        state.properties("network", "wlan0:192.168.1.2/24")
        state.properties("network", null)
        state.properties("network", "wlan0:192.168.2.2/24")
        state.properties("network", "wlan0:192.168.3.2/24")
        assertEquals(listOf(true, false, true, true), events)
    }

    @Test
    fun lossOfOneWifiNetworkDoesNotForgetAnotherAndBackgroundClearsAll() {
        val events = mutableListOf<Boolean>()
        val state = WifiNetworkState<String>(events::add)
        state.properties("one", "wlan0:192.168.1.2/24")
        state.properties("two", "wlan1:192.168.2.2/24")
        state.lost("one")
        state.lost("unknown")
        state.clear()
        state.available("two")
        assertEquals(listOf(true, true, true, false, false), events)
    }

    private class Queue {
        data class Job(val delay: Long, val action: () -> Unit)
        val jobs = mutableListOf<Job>()
        fun post(delay: Long, action: () -> Unit) { jobs += Job(delay, action) }
        fun runNext() { jobs.removeAt(0).action() }
        fun drain() { while (jobs.isNotEmpty()) runNext() }
    }

    @Test
    fun failedRegistrationRetriesWithoutForegroundToggleAndIgnoresFailedObserver() {
        val queue = Queue()
        val events = mutableListOf<Boolean>()
        val observers = mutableListOf<WifiNetworkObservation.Observer<String>>()
        val monitor = WifiNetworkObservation<String>(queue::post, { observer ->
            observers += observer
            if (observers.size == 1) throw IllegalStateException("transient registration failure")
            val cleanup: () -> Unit = {}
            cleanup
        }, events::add)
        monitor.start()
        assertEquals(1_000L, queue.jobs.single().delay)
        observers.first().properties("old", "address")
        queue.runNext() // retry succeeds before stale callback is delivered
        observers.last().properties("new", "address")
        queue.drain()
        assertEquals(listOf(false, false, true), events)
        assertEquals(2, observers.size)
        monitor.close()
    }

    @Test
    fun backgroundCancelsRetryAndOldRetryCannotRegisterInNewForeground() {
        val queue = Queue()
        var registrations = 0
        val monitor = WifiNetworkObservation<String>(queue::post, {
            registrations += 1
            throw IllegalStateException("unavailable")
        }, {})
        monitor.start()
        monitor.close()
        monitor.start()
        queue.runNext() // previous generation's retry
        assertEquals(2, registrations)
        monitor.close()
        queue.drain()
        assertEquals(2, registrations)
    }

    @Test
    fun queuedCallbacksAfterCloseCannotInvalidateReplacementEvenWhenUnregisterFails() {
        val queue = Queue()
        val events = mutableListOf<Boolean>()
        val observers = mutableListOf<WifiNetworkObservation.Observer<String>>()
        val monitor = WifiNetworkObservation<String>(queue::post, { observer ->
            observers += observer
            val cleanup: () -> Unit = { throw IllegalStateException("unregister failed") }
            cleanup
        }, events::add)
        monitor.start()
        val old = observers.single()
        old.properties("old", "address")
        monitor.close()
        monitor.start()
        observers.last().properties("new", "address")
        old.lost("old")
        queue.drain()
        assertEquals(listOf(false, false, false, true), events)
        old.properties("old", "different-address")
        monitor.close()
        queue.drain()
        assertEquals(false, events.last())
        assertEquals(5, events.size)
    }

    @Test
    fun repeatedRegistrationFailuresUseBoundedBackoffAndSuccessfulStartIsIdempotent() {
        val queue = Queue()
        var registrations = 0
        val monitor = WifiNetworkObservation<String>(queue::post, {
            registrations += 1
            if (registrations <= 7) throw IllegalStateException("unavailable")
            val cleanup: () -> Unit = {}
            cleanup
        }, {})
        monitor.start()
        val delays = mutableListOf<Long>()
        repeat(7) { delays += queue.jobs.single().delay; queue.runNext() }
        assertEquals(listOf(1000L, 2000L, 4000L, 8000L, 16000L, 30000L, 30000L), delays)
        monitor.start()
        assertEquals(8, registrations)
        assertEquals(0, queue.jobs.size)
        monitor.close()
    }
}
