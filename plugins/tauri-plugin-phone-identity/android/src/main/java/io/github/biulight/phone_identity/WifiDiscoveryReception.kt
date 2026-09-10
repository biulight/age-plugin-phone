package io.github.biulight.phone_identity

import android.content.Context
import android.net.wifi.WifiManager
import java.util.concurrent.atomic.AtomicBoolean

/** Transport reception only. This lock never authorizes an identity operation. */
internal class WifiDiscoveryReception private constructor(
    private val release: () -> Unit,
) : AutoCloseable {
    private val closed = AtomicBoolean(false)

    override fun close() {
        if (closed.compareAndSet(false, true)) release()
    }

    companion object {
        fun acquire(context: Context): WifiDiscoveryReception {
            val manager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                ?: throw StreamTransportException()
            val lock = manager.createMulticastLock("age-phone-foreground-discovery")
            lock.setReferenceCounted(false)
            return acquire(
                acquire = { lock.acquire(); check(lock.isHeld) },
                release = { if (lock.isHeld) lock.release() },
            )
        }

        internal fun acquire(acquire: () -> Unit, release: () -> Unit): WifiDiscoveryReception {
            try {
                acquire()
            } catch (error: Exception) {
                runCatching(release)
                throw error
            }
            return WifiDiscoveryReception(release)
        }
    }
}
