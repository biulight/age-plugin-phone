package io.github.biulight.phone_identity

import android.app.Activity
import android.app.Dialog
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter

internal data class PreparedPhonePairing(
    val display: PairingConfirmationDisplay,
    val responseFrames: List<EncodedQrFrame>,
)

/** Keeps response QR contents and confirmation below the native presentation boundary. */
internal class NativePairingResponseController(
    private val activity: Activity,
    private val prepared: PreparedPhonePairing,
    private val confirmation: PairingConfirmationCoordinator,
    private val onComplete: (CommittedPairingDisplay) -> Unit,
    private val onFailure: (String) -> Unit,
) {
    private val handler = Handler(Looper.getMainLooper())
    private var dialog: Dialog? = null
    private var fingerprint: TextView? = null
    private var image: ImageView? = null
    private var frameIndex = 0
    private var terminal = false
    private val advance = object : Runnable {
        override fun run() {
            if (terminal) return
            try {
                renderFrame()
            } catch (_: Exception) {
                fail("response_qr_failed")
                return
            }
            handler.postDelayed(this, FRAME_INTERVAL_MS)
        }
    }
    private val timeout = Runnable { fail("confirmation_timeout") }

    fun start() {
        if (prepared.responseFrames.isEmpty()) {
            fail("response_qr_failed")
            return
        }
        val root = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(40, 56, 40, 56)
            setBackgroundColor(Color.WHITE)
        }
        root.addView(TextView(activity).apply {
            text = "Scan this response on the desktop"
            textSize = 21f
            setTextColor(Color.BLACK)
            gravity = Gravity.CENTER
        })
        root.addView(TextView(activity).apply {
            text = "Desktop label (untrusted display hint):"
            textSize = 14f
            setTextColor(Color.DKGRAY)
            gravity = Gravity.CENTER
        })
        root.addView(TextView(activity).apply {
            text = prepared.display.desktopLabel
            textSize = 16f
            setTextColor(Color.BLACK)
            gravity = Gravity.CENTER
        })
        image = ImageView(activity).also {
            root.addView(
                it,
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    0,
                    1f,
                ),
            )
        }
        root.addView(TextView(activity).apply {
            text = "Compare the full transcript fingerprint on both screens:"
            textSize = 15f
            setTextColor(Color.DKGRAY)
            gravity = Gravity.CENTER
        })
        fingerprint = TextView(activity).apply {
            text = prepared.display.transcriptFingerprint
            textSize = 16f
            setTextColor(Color.BLACK)
            gravity = Gravity.CENTER
            setTextIsSelectable(false)
        }.also(root::addView)
        root.addView(Button(activity).apply {
            text = "Fingerprints match"
            setOnClickListener { confirm() }
        })
        root.addView(Button(activity).apply {
            text = "Cancel"
            setOnClickListener { fail("user_cancelled") }
        })
        dialog = Dialog(activity, android.R.style.Theme_Material_Light_NoActionBar_Fullscreen).apply {
            setContentView(root)
            setCancelable(false)
            show()
        }
        try {
            renderFrame()
        } catch (_: Exception) {
            fail("response_qr_failed")
            return
        }
        handler.postDelayed(advance, FRAME_INTERVAL_MS)
        handler.postDelayed(timeout, CONFIRMATION_TIMEOUT_MS)
    }

    fun cancel() {
        fail("user_cancelled")
    }

    private fun confirm() {
        if (terminal) return
        val displayed = fingerprint?.text?.toString() ?: run {
            fail("fingerprint_mismatch")
            return
        }
        val committed = try {
            confirmation.confirm(displayed, System.currentTimeMillis() / 1_000)
        } catch (error: PairingConfirmationSession.PairingConfirmationException) {
            val category = when (error.category) {
                PairingConfirmationSession.Category.FINGERPRINT_MISMATCH -> "fingerprint_mismatch"
                PairingConfirmationSession.Category.ALREADY_PAIRED -> "already_paired"
                else -> "pairing_storage_failed"
            }
            finish()
            onFailure(category)
            return
        }
        finish()
        onComplete(committed)
    }

    private fun fail(category: String) {
        if (terminal) return
        confirmation.cancel()
        finish()
        onFailure(category)
    }

    private fun finish() {
        terminal = true
        handler.removeCallbacks(advance)
        handler.removeCallbacks(timeout)
        image?.setImageDrawable(null)
        image = null
        fingerprint = null
        dialog?.dismiss()
        dialog = null
    }

    private fun renderFrame() {
        val frame = prepared.responseFrames[frameIndex]
        frameIndex = (frameIndex + 1) % prepared.responseFrames.size
        val matrix = MultiFormatWriter().encode(
            frame.value,
            BarcodeFormat.QR_CODE,
            QR_PIXELS,
            QR_PIXELS,
        )
        val pixels = IntArray(QR_PIXELS * QR_PIXELS) { index ->
            if (matrix[index % QR_PIXELS, index / QR_PIXELS]) Color.BLACK else Color.WHITE
        }
        image?.setImageBitmap(
            Bitmap.createBitmap(pixels, QR_PIXELS, QR_PIXELS, Bitmap.Config.ARGB_8888),
        )
    }

    companion object {
        private const val FRAME_INTERVAL_MS = 250L
        private const val CONFIRMATION_TIMEOUT_MS = 5 * 60 * 1_000L
        private const val QR_PIXELS = 768
    }
}
