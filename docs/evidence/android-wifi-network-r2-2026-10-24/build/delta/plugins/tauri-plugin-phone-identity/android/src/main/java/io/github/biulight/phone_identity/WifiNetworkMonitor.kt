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

/** Serialized lifecycle shared by the Android adapter and deterministic queue tests. */
internal class WifiNetworkObservation<N>(
    private val post: (Long, () -> Unit) -> Unit,
    private val register: (Observer<N>) -> (() -> Unit),
    changed: (Boolean) -> Unit,
) : AutoCloseable {
    interface Observer<N> {
        fun available(network: N)
        fun properties(network: N, link: String?)
        fun lost(network: N)
    }

    private val state = WifiNetworkState<N>(changed)
    private var foreground = false
    private var generation = 0L
    private var observer: Observer<N>? = null
    private var unregister: (() -> Unit)? = null
    private var retryMillis = 1_000L

    fun start() {
        if (foreground) return
        foreground = true
        generation += 1
        retryMillis = 1_000L
        state.clear()
        observe(generation)
    }

    private fun observe(expected: Long) {
        if (!foreground || generation != expected || observer != null) return
        val current = object : Observer<N> {
            private fun deliver(action: () -> Unit) {
                post(0) {
                    if (foreground && generation == expected && observer === this) action()
                }
            }
            override fun available(network: N) = deliver { state.available(network) }
            override fun properties(network: N, link: String?) = deliver { state.properties(network, link) }
            override fun lost(network: N) = deliver { state.lost(network) }
        }
        observer = current
        try {
            unregister = register(current)
            retryMillis = 1_000L
        } catch (_: Exception) {
            observer = null
            state.clear()
            val delay = retryMillis
            retryMillis = (retryMillis * 2).coerceAtMost(30_000L)
            // Retry only observation. Never retry a signed unwrap or retain authorization.
            post(delay) { observe(expected) }
        }
    }

    override fun close() {
        foreground = false
        generation += 1
        observer = null
        val owned = unregister
        unregister = null
        // Invalidate queued callbacks before asking Android to unregister.
        if (owned != null) runCatching { owned() }
        state.clear()
    }
}

/** start/close and queued work run on the main handler. */
internal class WifiNetworkMonitor(
    context: Context,
    handler: Handler,
    changed: (Boolean) -> Unit,
) : AutoCloseable {
    private val manager = context.applicationContext
        .getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val observation = WifiNetworkObservation<Network>(
        post = { delay, action -> handler.postDelayed({ action() }, delay); Unit },
        register = { sink ->
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = sink.available(network)
                override fun onLost(network: Network) = sink.lost(network)
                override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
                    val addresses = properties.linkAddresses.filter { it.address is Inet4Address }
                        .map { it.toString() }.sorted()
                    val link = if (addresses.isEmpty()) null else
                        properties.interfaceName.orEmpty() + ":" + addresses.joinToString(",")
                    sink.properties(network, link)
                }
            }
            manager.registerNetworkCallback(
                NetworkRequest.Builder().clearCapabilities()
                    .addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build(),
                callback,
            )
            val cleanup: () -> Unit = { manager.unregisterNetworkCallback(callback) }
            cleanup
        },
        changed = changed,
    )

    fun start() = observation.start()
    override fun close() = observation.close()
}
