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
}
