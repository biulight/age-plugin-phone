package io.github.biulight.phone_identity

import android.app.Activity
import android.app.Dialog
import android.graphics.Color
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.mlkit.vision.MlKitAnalyzer
import androidx.camera.view.CameraController
import androidx.camera.view.LifecycleCameraController
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScanner
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode

internal data class PairingOfferScanDisplay(
    val desktopLabel: String,
    val offerFingerprint: String,
)

internal class NativeQrScannerController(
    private val activity: Activity,
    private val onComplete: (PairingOfferScanDisplay, Int) -> Unit,
    private val onFailure: (String) -> Unit,
) {
    private val handler = Handler(Looper.getMainLooper())
    private val session = QrScanSession(
        CompletedQrMessageVerifier(::verifyOffer),
    )
    private val scanner: BarcodeScanner = BarcodeScanning.getClient(
        BarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build(),
    )
    private var cameraController: LifecycleCameraController? = null
    private var dialog: Dialog? = null
    private var status: TextView? = null
    private var finished = false
    private var assemblyDeadlineScheduled = false
    private val overallTimeout = Runnable { finishFailure("scan_timeout") }
    private val assemblyTimeout = Runnable {
        try {
            session.expire(SystemClock.elapsedRealtime())
        } catch (_: QrFraming.QrException) {
            finishFailure("qr_timeout")
        }
    }

    fun start() {
        try {
            startCamera()
        } catch (_: Exception) {
            finishFailure("camera_unavailable")
        }
    }

    private fun startCamera() {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (finished || dialog != null) return
        val owner = activity as? LifecycleOwner ?: run {
            finishFailure("camera_unavailable")
            return
        }
        val preview = PreviewView(activity).apply {
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            )
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
        val root = FrameLayout(activity).apply {
            setBackgroundColor(Color.BLACK)
            addView(preview)
        }
        val controls = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(48, 48, 48, 64)
            setBackgroundColor(0x99000000.toInt())
        }
        status = TextView(activity).apply {
            text = "Scan pairing QR · 0 frames"
            setTextColor(Color.WHITE)
            textSize = 18f
            gravity = Gravity.CENTER
        }
        val cancel = Button(activity).apply {
            text = "Cancel"
            setOnClickListener { finishFailure("user_cancelled") }
        }
        controls.addView(status)
        controls.addView(cancel)
        root.addView(
            controls,
            FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM,
            ),
        )

        dialog = Dialog(activity, android.R.style.Theme_Black_NoTitleBar_Fullscreen).apply {
            setContentView(root)
            setCancelable(false)
            show()
        }

        val executor = ContextCompat.getMainExecutor(activity)
        val controller = LifecycleCameraController(activity).apply {
            cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA
            setEnabledUseCases(CameraController.IMAGE_ANALYSIS)
            setImageAnalysisAnalyzer(
                executor,
                MlKitAnalyzer(
                    listOf(scanner),
                    ImageAnalysis.COORDINATE_SYSTEM_ORIGINAL,
                    executor,
                ) { result ->
                    result.getValue(scanner)
                        ?.asSequence()
                        ?.mapNotNull { it.rawValue }
                        ?.firstOrNull(QrFraming::isFrameCandidate)
                        ?.let(::acceptFrame)
                },
            )
            bindToLifecycle(owner)
        }
        cameraController = controller
        preview.controller = controller
        handler.postDelayed(overallTimeout, OVERALL_SCAN_TIMEOUT_MS)
    }

    fun cancel() {
        if (!finished) finishFailure("user_cancelled")
    }

    private fun acceptFrame(rawValue: String) {
        if (finished) return
        try {
            when (val result = session.accept(rawValue, SystemClock.elapsedRealtime())) {
                QrScanStatus.Ignored -> Unit
                is QrScanStatus.InProgress -> {
                    status?.text = "Scan pairing QR · ${result.received}/${result.total} frames"
                    if (!assemblyDeadlineScheduled) {
                        assemblyDeadlineScheduled = true
                        handler.postDelayed(
                            assemblyTimeout,
                            QrFraming.MAX_ASSEMBLY_AGE_MS + 1,
                        )
                    }
                }
                is QrScanStatus.Complete -> finishSuccess(result.display, result.framesAccepted)
            }
        } catch (error: QrFraming.QrException) {
            val category = when (error.category) {
                QrFraming.Category.TIMEOUT -> "qr_timeout"
                QrFraming.Category.UNSUPPORTED_TYPE,
                QrFraming.Category.UNSUPPORTED_VERSION,
                -> "unsupported_qr_frame"
                else -> "invalid_qr_frame"
            }
            finishFailure(category)
        } catch (_: Exception) {
            finishFailure("invalid_pairing_offer")
        }
    }

    private fun finishSuccess(display: PairingOfferScanDisplay, framesAccepted: Int) {
        if (finished) return
        finished = true
        closeResources()
        onComplete(display, framesAccepted)
    }

    private fun finishFailure(category: String) {
        if (finished) return
        finished = true
        session.cancel()
        closeResources()
        onFailure(category)
    }

    private fun closeResources() {
        handler.removeCallbacks(overallTimeout)
        handler.removeCallbacks(assemblyTimeout)
        cameraController?.clearImageAnalysisAnalyzer()
        cameraController?.unbind()
        cameraController = null
        scanner.close()
        status = null
        dialog?.dismiss()
        dialog = null
    }

    private fun verifyOffer(message: ByteArray): PairingOfferScanDisplay {
        val verified = OfflineEnvelopeCrypto.verifyPairingOffer(message)
        return try {
            PairingOfferScanDisplay(
                desktopLabel = verified.offer.desktopLabel,
                offerFingerprint = verified.digest.toHex(),
            )
        } finally {
            verified.encoded.fill(0)
            verified.digest.fill(0)
            verified.offer.desktopId.fill(0)
            verified.offer.nonce.fill(0)
        }
    }

    private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
        "%02x".format(byte.toInt() and 0xff)
    }

    companion object {
        private const val OVERALL_SCAN_TIMEOUT_MS = 60_000L
    }
}
