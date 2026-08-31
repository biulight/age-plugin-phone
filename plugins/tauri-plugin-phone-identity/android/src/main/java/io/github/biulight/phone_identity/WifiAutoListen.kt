package io.github.biulight.phone_identity

import android.content.Context
import java.io.File
import java.io.FileOutputStream

internal object WifiAutoListenRetryPolicy {
    private val bindDelays = longArrayOf(1_000, 2_000, 4_000, 8_000, 16_000, 30_000)

    fun bindDelay(failures: Int): Long = bindDelays[
        failures.coerceIn(0, bindDelays.lastIndex),
    ]
}

/** App-private, non-backed-up opt-in for foreground Wi-Fi transport availability. */
internal class WifiAutoListenSetting(private val directory: File) {
    fun enabled(): Boolean = try {
        val bytes = settingFile().readBytes()
        bytes.contentEquals(ENABLED_BYTES)
    } catch (_: Exception) {
        false
    }

    @Throws(Exception::class)
    fun setEnabled(enabled: Boolean) {
        directory.mkdirs()
        check(directory.isDirectory)
        val target = settingFile()
        val temporary = File(directory, "$FILE_NAME.tmp")
        if (!enabled) {
            if (temporary.exists() && !temporary.delete()) throw IllegalStateException()
            if (target.exists() && !target.delete()) throw IllegalStateException()
            return
        }
        FileOutputStream(temporary, false).use { output ->
            output.write(ENABLED_BYTES)
            output.fd.sync()
        }
        if (target.exists() && !target.delete()) {
            temporary.delete()
            throw IllegalStateException()
        }
        if (!temporary.renameTo(target)) {
            temporary.delete()
            throw IllegalStateException()
        }
    }

    private fun settingFile(): File = File(directory, FILE_NAME)

    companion object {
        private const val FILE_NAME = "wifi-auto-listen-v1"
        private val ENABLED_BYTES = byteArrayOf(0x41, 0x50, 0x57, 0x01)

        fun production(context: Context): WifiAutoListenSetting =
            WifiAutoListenSetting(context.noBackupFilesDir)
    }
}

/** Bridges Activity foreground lifecycle to the native plugin without protocol data. */
object WifiAutoListenForegroundCoordinator {
    private data class Listener(val owner: Any, val changed: (Boolean) -> Unit)

    private val lock = Any()
    private var listener: Listener? = null
    private var foreground = false

    internal fun register(owner: Any, changed: (Boolean) -> Unit) {
        val current = synchronized(lock) {
            listener = Listener(owner, changed)
            foreground
        }
        changed(current)
    }

    internal fun unregister(owner: Any) {
        synchronized(lock) {
            if (listener?.owner === owner) listener = null
        }
    }

    @JvmStatic
    fun onStart() {
        val changed = synchronized(lock) {
            foreground = true
            listener?.changed
        }
        changed?.invoke(true)
    }

    @JvmStatic
    fun onStop() {
        val changed = synchronized(lock) {
            foreground = false
            listener?.changed
        }
        changed?.invoke(false)
    }

    internal fun resetForTest() {
        synchronized(lock) {
            listener = null
            foreground = false
        }
    }
}
