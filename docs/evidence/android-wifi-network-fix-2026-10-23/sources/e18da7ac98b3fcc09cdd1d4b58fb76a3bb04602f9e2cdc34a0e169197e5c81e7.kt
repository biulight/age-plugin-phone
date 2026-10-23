package io.github.biulight.phone_identity

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import java.net.Inet4Address

/** Tracks transport availability only; a change invalidates existing Wi-Fi resources. */
internal class WifiNetworkState<T>(private val changed: (Boolean) -> Unit) {
    private val links = mutableMapOf<T, String?>()

    fun available(network: T) {
        if (!links.containsKey(network)) {
            links[network] = null
            notifyChanged()
        }
    }

    fun properties(network: T, ipv4Link: String?) {
        if (!links.containsKey(network) || links[network] != ipv4Link) {
            links[network] = ipv4Link
            notifyChanged()
        }
    }

    fun lost(network: T) {
        if (links.containsKey(network)) {
            links.remove(network)
            notifyChanged()
        }
    }

    fun clear() {
        links.clear()
        changed(false)
    }

    private fun notifyChanged() = changed(links.values.any { it != null })
}

/** Foreground-only network observer. Call start/close on the same main handler. */
internal class WifiNetworkMonitor(
    context: Context,
    private val handler: Handler,
    changed: (Boolean) -> Unit,
) : AutoCloseable {
    private val manager = context.applicationContext
        .getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val state = WifiNetworkState<Network>(changed)
    private var callback: ConnectivityManager.NetworkCallback? = null

    fun start() {
        if (callback != null) return
        state.clear()
        val observer = object : ConnectivityManager.NetworkCallback() {
            private fun deliver(action: () -> Unit) {
                handler.post {
                    // Ignore queued notifications from a stopped foreground generation.
                    if (callback === this) action()
                }
            }

            override fun onAvailable(network: Network) = deliver { state.available(network) }
            override fun onLost(network: Network) = deliver { state.lost(network) }
            override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
                val addresses = properties.linkAddresses.filter { it.address is Inet4Address }
                    .map { it.toString() }.sorted()
                val link = if (addresses.isEmpty()) null else
                    properties.interfaceName.orEmpty() + ":" + addresses.joinToString(",")
                deliver { state.properties(network, link) }
            }
        }
        callback = observer
        try {
            manager.registerNetworkCallback(
                NetworkRequest.Builder().clearCapabilities()
                    .addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build(),
                observer,
            )
        } catch (_: Exception) {
            callback = null
            state.clear() // Without network observation, keep the availability gate closed.
        }
    }

    override fun close() {
        val owned = callback
        callback = null
        if (owned != null) runCatching { manager.unregisterNetworkCallback(owned) }
        state.clear()
    }
}
