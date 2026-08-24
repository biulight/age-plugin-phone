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

internal data class PreparedUnwrapResponse(
    val requestFingerprint: String,
    val responseFrames: List<EncodedQrFrame>,
)

/** Presents opaque response frames without exposing protocol bytes to the WebView. */
internal class NativeUnwrapResponseController(
    private val activity: Activity,
    private val prepared: PreparedUnwrapResponse,
    private val onComplete: () -> Unit,
    private val onFailure: (String) -> Unit,
) {
    private val handler = Handler(Looper.getMainLooper())
    private var dialog: Dialog? = null
    private var image: ImageView? = null
    private var frameIndex = 0
    private var terminal = false
    private val advance = object : Runnable {
        override fun run() {
            if (terminal) return
            try {
                renderFrame()
                handler.postDelayed(this, FRAME_INTERVAL_MS)
            } catch (_: Exception) {
                fail("response_qr_failed")
            }
        }
    }
    private val timeout = Runnable { fail("response_timeout") }

    fun start() {
        if (prepared.responseFrames.isEmpty()) return fail("response_qr_failed")
        val root = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(40, 56, 40, 56)
            setBackgroundColor(Color.WHITE)
        }
        root.addView(TextView(activity).apply {
            text = "Scan this one-time unwrap response on the desktop"
            textSize = 21f
            setTextColor(Color.BLACK)
            gravity = Gravity.CENTER
        })
        image = ImageView(activity).also {
            root.addView(
                it,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f),
            )
        }
        root.addView(TextView(activity).apply {
            text = "Request fingerprint: ${prepared.requestFingerprint}"
            textSize = 14f
            setTextColor(Color.DKGRAY)
            gravity = Gravity.CENTER
            setTextIsSelectable(false)
        })
        root.addView(Button(activity).apply {
            text = "Desktop received response"
            setOnClickListener { complete() }
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
        renderFrame()
        handler.postDelayed(advance, FRAME_INTERVAL_MS)
        handler.postDelayed(timeout, RESPONSE_TIMEOUT_MS)
    }

    fun cancel() = fail("user_cancelled")

    private fun complete() {
        if (terminal) return
        finish()
        onComplete()
    }

    private fun fail(category: String) {
        if (terminal) return
        finish()
        onFailure(category)
    }

    private fun finish() {
        terminal = true
        handler.removeCallbacks(advance)
        handler.removeCallbacks(timeout)
        image?.setImageDrawable(null)
        image = null
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
        private const val RESPONSE_TIMEOUT_MS = 5 * 60 * 1_000L
        private const val QR_PIXELS = 768
    }
}
