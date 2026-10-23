package io.github.biulight.phone_identity

import java.util.UUID

/** Ownership only; every call is protected by the plugin's stateLock. No authorization is stored. */
internal class UnwrapOperationState<T>(private val tokenOf: (T) -> UUID) {
    var wifiToken: UUID? = null
    var pending: T? = null
    var response: T? = null
        private set

    fun publishWifi(token: UUID, value: T): Boolean {
        if (wifiToken != token || pending != null || response != null) return false
        wifiToken = null
        pending = value
        return true
    }

    fun isActive(token: UUID): Boolean = pending?.let(tokenOf) == token

    fun takePending(token: UUID): T? =
        pending?.takeIf { tokenOf(it) == token }?.also { pending = null }

    fun beginResponse(token: UUID): T? {
        if (response != null) return null
        return takePending(token)?.also { response = it }
    }

    fun takeResponse(token: UUID): T? =
        response?.takeIf { tokenOf(it) == token }?.also { response = null }

    fun cancelMatching(matches: (T) -> Boolean): T? {
        val owned = pending?.takeIf(matches) ?: response?.takeIf(matches) ?: return null
        if (pending === owned) pending = null
        if (response === owned) response = null
        return owned
    }
}
