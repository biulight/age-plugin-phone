package io.github.biulight.phone_identity

import android.content.Intent
import android.os.Build

/** Accepts only the fixed, payload-free Developer USB unwrap wake action. */
object UsbUnwrapWakeCoordinator {
    const val ACTION = "io.github.biulight.age_plugin_phone.action.UNWRAP_USB"

    private data class Listener(val owner: Any, val start: () -> Boolean)

    private val lock = Any()
    private var listener: Listener? = null
    private var pending = false

    @JvmStatic
    fun consume(intent: Intent): Boolean {
        if (intent.action != ACTION) return false
        val valid = isPayloadFreeUnwrapAction(
            action = intent.action,
            hasData = intent.data != null,
            hasClipData = intent.clipData != null,
            hasExtras = intent.extras?.isEmpty == false,
            hasSelector = intent.selector != null,
            hasType = intent.type != null,
            hasCategories = !intent.categories.isNullOrEmpty(),
            hasIdentifier = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && intent.identifier != null,
            hasSourceBounds = intent.sourceBounds != null,
        )
        intent.action = null
        if (!valid) return false
        return request()
    }

    internal fun register(owner: Any, start: () -> Boolean) {
        val dispatch = synchronized(lock) {
            listener = Listener(owner, start)
            if (pending) {
                pending = false
                start
            } else {
                null
            }
        }
        dispatch?.invoke()
    }

    internal fun unregister(owner: Any) {
        synchronized(lock) {
            if (listener?.owner === owner) listener = null
            pending = false
        }
    }

    internal fun clearPending() {
        synchronized(lock) { pending = false }
    }

    internal fun request(): Boolean {
        val start = synchronized(lock) {
            val current = listener
            if (current == null) {
                if (pending) return false
                pending = true
                return true
            }
            current.start
        }
        return try {
            start()
        } catch (_: Exception) {
            false
        }
    }

    internal fun resetForTest() {
        synchronized(lock) {
            listener = null
            pending = false
        }
    }

    internal fun isPayloadFreeUnwrapAction(
        action: String?,
        hasData: Boolean,
        hasClipData: Boolean,
        hasExtras: Boolean,
        hasSelector: Boolean,
        hasType: Boolean,
        hasCategories: Boolean,
        hasIdentifier: Boolean,
        hasSourceBounds: Boolean,
    ): Boolean = action == ACTION && !hasData && !hasClipData && !hasExtras && !hasSelector &&
        !hasType && !hasCategories && !hasIdentifier && !hasSourceBounds
}
