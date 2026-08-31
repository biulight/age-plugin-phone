package io.github.biulight.phone_identity

import android.app.Activity
import android.app.AlertDialog
import android.Manifest
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyPermanentlyInvalidatedException
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.PermissionState
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.KeyAgreement
import org.json.JSONArray

@InvokeArg
class RevokePairingArgs {
    lateinit var handle: String
}

@TauriPlugin(
    permissions = [Permission(strings = [Manifest.permission.CAMERA], alias = "camera")],
)
class PhoneIdentityPlugin(private val activity: Activity) : Plugin(activity) {
    private val keys = ProbeKeyStore(activity)
    private val doctor = StrongBoxDoctor(activity, keys)
    private val productionIdentity = PhoneIdentityKeyStore.production(activity)
    private val mainHandler = Handler(Looper.getMainLooper())
    private val stateLock = Any()
    private val pairingDoctorLock = Any()
    private var active: PendingAgreement? = null
    private var activeQrScanner: NativeQrScannerController<*>? = null
    private var activePairingResponse: NativePairingResponseController? = null
    private var activePhoneUnwrap: PendingPhoneUnwrap? = null
    private var activeStreamResponse: PendingPhoneUnwrap? = null
    private var activeUnwrapResponse: NativeUnwrapResponseController? = null
    private var activeUsbSession: PhoneStreamSession? = null
    private var activeUsbToken: UUID? = null
    private var activeWifiListener: PhoneWifiListener? = null
    private var activeWifiSession: PhoneStreamSession? = null
    private var activeWifiToken: UUID? = null
    private var activeWifiInvoke: Invoke? = null
    private var activeLifecycle: PendingLifecycle? = null
    private var activeProvisioning = false
    private var cameraPermissionPending = false
    private var pairingPermissionPending = false
    private var unwrapPermissionPending = false
    private val usbWakeOwner = Any()
    private val pairingConfirmation = PairingConfirmationCoordinator(
        PairingSessionFactory { signedOffer, signedResponse ->
            PairingConfirmationSession.begin(activity, signedOffer, signedResponse)
        },
    )

    init {
        UsbUnwrapWakeCoordinator.register(usbWakeOwner, ::startAutomaticUsbUnwrap)
    }

    @Command
    fun doctorCapabilities(invoke: Invoke) {
        invoke.resolve(doctor.capabilities())
    }

    @Command
    fun doctorIdentityCustody(invoke: Invoke) {
        invoke.resolve(doctor.identityCustody())
    }

    @Command
    fun doctorCreateProbe(invoke: Invoke) {
        if (!doctor.strongBiometricAvailable()) {
            invoke.resolve(ProbeKeyStore.emptyProbeReport("strong_biometric_unavailable"))
            return
        }
        invoke.resolve(keys.createProbe())
    }

    @Command
    fun doctorRunAgreement(invoke: Invoke) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S || !hasKeyAgreementCryptoObject()) {
            invoke.resolve(agreementReport(false, false, "unsupported_api"))
            return
        }

        val prepared = try {
            prepareAgreement(invoke)
        } catch (_: KeyPermanentlyInvalidatedException) {
            invoke.resolve(agreementReport(false, false, "key_permanently_invalidated"))
            return
        } catch (_: Exception) {
            invoke.resolve(agreementReport(false, false, "agreement_failed"))
            return
        }

        if (prepared == null) return
        activity.runOnUiThread { showPrompt(prepared) }
    }

    @Command
    fun doctorCleanup(invoke: Invoke) {
        cancelActive("authentication_failed")
        invoke.resolve(keys.cleanup())
    }

    @Command
    fun doctorPairingStorage(invoke: Invoke) {
        invoke.resolve(synchronized(pairingDoctorLock) { runPairingStorageDoctor() })
    }

    @Command
    fun identityStatus(invoke: Invoke) {
        invoke.resolve(identityStatusReport())
    }

    @Command
    fun provisionIdentity(invoke: Invoke) {
        synchronized(stateLock) {
            if (nativeOperationActive()) {
                invoke.resolve(identityStatusReport("operation_active"))
                return
            }
            activeProvisioning = true
        }
        try {
            productionIdentity.provision()
            invoke.resolve(identityStatusReport())
        } catch (error: PhoneIdentityKeyStore.KeyStoreException) {
            invoke.resolve(identityStatusReport(keyStoreCategory(error.category)))
        } finally {
            synchronized(stateLock) { activeProvisioning = false }
        }
    }

    @Command
    fun revokePairing(invoke: Invoke) {
        val handle = try {
            invoke.parseArgs(RevokePairingArgs::class.java).handle
        } catch (_: Exception) {
            invoke.resolve(lifecycleReport(false, "ready", "malformed_request"))
            return
        }
        val provision = try {
            productionIdentity.open()
        } catch (error: PhoneIdentityKeyStore.KeyStoreException) {
            invoke.resolve(lifecycleReport(false, "unavailable", keyStoreCategory(error.category)))
            return
        }
        val pairing = try {
            PairingStateStore.list(activity, provision.public.identityId).singleOrNull {
                it.handle == handle
            } ?: throw PairingStateStore.PairingStateException(PairingStateStore.Category.MISSING)
        } catch (error: PairingStateStore.PairingStateException) {
            invoke.resolve(lifecycleReport(false, "ready", pairingCategory(error.category)))
            return
        }
        startLifecycleConfirmation(
            invoke = invoke,
            title = "Revoke paired desktop?",
            message = "Untrusted label: ${pairing.desktopLabel.take(64)}\n\n" +
                "Fingerprint: ${pairing.transcriptFingerprint}\n\n" +
                "Old ciphertext may require recovery and re-encryption.",
            positiveLabel = if (pairing.deletionPending) "Finish cleanup" else "Revoke desktop",
        ) {
            PairingStateStore.revoke(activity, provision.public.identityId, handle)
            lifecycleReport(true, "ready", null)
        }
    }

    @Command
    fun deleteIdentity(invoke: Invoke) {
        val status = identityStatusReport()
        if (status.optString("state") !in setOf("ready", "deletion_pending")) {
            invoke.resolve(lifecycleReport(false, status.optString("state"), "identity_unavailable"))
            return
        }
        startLifecycleConfirmation(
            invoke = invoke,
            title = "Delete phone identity?",
            message = "This permanently destroys the StrongBox identity and revokes every paired " +
                "desktop. Ciphertexts are not deleted. Continue only after verifying an independent " +
                "recovery recipient.",
            positiveLabel = "Delete identity",
        ) {
            productionIdentity.deleteIdentity()
            lifecycleReport(true, "not_configured", null)
        }
    }

    @Command
    fun scanPairingOffer(invoke: Invoke) {
        val granted = getPermissionState("camera") == PermissionState.GRANTED
        synchronized(stateLock) {
            if (nativeOperationActive()) {
                invoke.resolve(pairingOfferScanReport(false, false, null, null, 0, "scan_active"))
                return
            }
            cameraPermissionPending = !granted
        }
        if (granted) {
            activity.runOnUiThread { startPairingOfferScanner(invoke) }
        } else {
            requestPermissionForAlias("camera", invoke, "cameraPermissionGranted")
        }
    }

    @Command
    fun pairPhone(invoke: Invoke) {
        val granted = getPermissionState("camera") == PermissionState.GRANTED
        synchronized(stateLock) {
            if (nativeOperationActive()) {
                invoke.resolve(phonePairingReport(false, null, null, "pairing_active"))
                return
            }
            pairingPermissionPending = !granted
        }
        if (granted) {
            activity.runOnUiThread { startPhonePairingScanner(invoke) }
        } else {
            requestPermissionForAlias("camera", invoke, "pairingCameraPermissionGranted")
        }
    }

    @Command
    fun unwrapPhone(invoke: Invoke) {
        val granted = getPermissionState("camera") == PermissionState.GRANTED
        synchronized(stateLock) {
            if (nativeOperationActive()) {
                invoke.resolve(phoneUnwrapReport(false, false, null, "unwrap_active"))
                return
            }
            unwrapPermissionPending = !granted
        }
        if (granted) {
            activity.runOnUiThread { startPhoneUnwrapScanner(invoke) }
        } else {
            requestPermissionForAlias("camera", invoke, "unwrapCameraPermissionGranted")
        }
    }

    @Command
    fun pairPhoneUsb(invoke: Invoke) {
        val token = UUID.randomUUID()
        synchronized(stateLock) {
            if (nativeOperationActive()) {
                invoke.resolve(phonePairingReport(false, null, null, "pairing_active"))
                return
            }
            activeUsbToken = token
        }
        Thread({ runUsbPairing(token, invoke) }, "phone-adb-pairing").start()
    }

    @Command
    fun unwrapPhoneWifi(invoke: Invoke) {
        val token = UUID.randomUUID()
        synchronized(stateLock) {
            if (nativeOperationActive()) {
                invoke.resolve(phoneUnwrapReport(false, false, null, "unwrap_active"))
                return
            }
            activeWifiToken = token
            activeWifiInvoke = invoke
        }
        Thread({ runWifiUnwrap(token, invoke) }, "phone-wifi-unwrap").start()
    }

    @Command
    fun cancelWifiUnwrap(invoke: Invoke) {
        val cancelled = cancelWifiOperation("user_cancelled", includePendingAuthorization = true)
        invoke.resolve(
            lifecycleReport(
                completed = cancelled,
                state = "ready",
                error = if (cancelled) null else "wifi_not_active",
            ),
        )
    }

    @Command
    fun wifiUnwrapStatus(invoke: Invoke) {
        val active = synchronized(stateLock) { wifiOperationActive() }
        invoke.resolve(JSObject().apply { put("active", active) })
    }

    private fun startAutomaticUsbUnwrap(): Boolean {
        val token = UUID.randomUUID()
        synchronized(stateLock) {
            if (nativeOperationActive()) {
                return false
            }
            activeUsbToken = token
        }
        Thread({ runUsbUnwrap(token, null) }, "phone-adb-unwrap").start()
        return true
    }

    @PermissionCallback
    fun cameraPermissionGranted(invoke: Invoke) {
        synchronized(stateLock) { cameraPermissionPending = false }
        if (getPermissionState("camera") == PermissionState.GRANTED) {
            activity.runOnUiThread { startPairingOfferScanner(invoke) }
        } else {
            invoke.resolve(
                pairingOfferScanReport(false, false, null, null, 0, "camera_permission_denied"),
            )
        }
    }

    @PermissionCallback
    fun pairingCameraPermissionGranted(invoke: Invoke) {
        synchronized(stateLock) { pairingPermissionPending = false }
        if (getPermissionState("camera") == PermissionState.GRANTED) {
            activity.runOnUiThread { startPhonePairingScanner(invoke) }
        } else {
            invoke.resolve(phonePairingReport(false, null, null, "camera_permission_denied"))
        }
    }

    @PermissionCallback
    fun unwrapCameraPermissionGranted(invoke: Invoke) {
        synchronized(stateLock) { unwrapPermissionPending = false }
        if (getPermissionState("camera") == PermissionState.GRANTED) {
            activity.runOnUiThread { startPhoneUnwrapScanner(invoke) }
        } else {
            invoke.resolve(phoneUnwrapReport(false, false, null, "camera_permission_denied"))
        }
    }

    override fun onStop() {
        UsbUnwrapWakeCoordinator.clearPending()
        cancelActive("authentication_failed")
        cancelPendingPairing()
        cancelQrScanner()
        cancelPairingResponse()
        cancelPhoneUnwrap("authentication_failed")
        cancelUnwrapResponse()
        cancelUsbSession()
        cancelWifiOperation("authentication_failed", includePendingAuthorization = false)
        cancelLifecycle()
    }

    override fun onDestroy(activity: androidx.appcompat.app.AppCompatActivity) {
        UsbUnwrapWakeCoordinator.unregister(usbWakeOwner)
        cancelActive("authentication_failed")
        cancelPendingPairing()
        cancelQrScanner()
        cancelPairingResponse()
        cancelPhoneUnwrap("authentication_failed")
        cancelUnwrapResponse()
        cancelUsbSession()
        cancelWifiOperation("authentication_failed", includePendingAuthorization = false)
        cancelLifecycle()
    }

    private fun startPairingOfferScanner(invoke: Invoke) {
        synchronized(stateLock) {
            if (nativeOperationActive()) {
                invoke.resolve(pairingOfferScanReport(false, false, null, null, 0, "scan_active"))
                return
            }
            activeQrScanner = NativeQrScannerController(
                activity,
                CompletedQrMessageVerifier(::verifyPairingOfferForScan),
                onComplete = { display, framesAccepted ->
                    synchronized(stateLock) { activeQrScanner = null }
                    invoke.resolve(
                        pairingOfferScanReport(
                            true,
                            true,
                            display.desktopLabel,
                            display.offerFingerprint,
                            framesAccepted,
                            null,
                        ),
                    )
                },
                onFailure = { category ->
                    synchronized(stateLock) { activeQrScanner = null }
                    invoke.resolve(pairingOfferScanReport(true, false, null, null, 0, category))
                },
            )
            activeQrScanner?.start()
        }
    }

    private fun cancelQrScanner() {
        val scanner = synchronized(stateLock) {
            activeQrScanner.also { activeQrScanner = null }
        }
        scanner?.cancel()
    }

    private fun startPhonePairingScanner(invoke: Invoke) {
        synchronized(stateLock) {
            if (nativeOperationActive()) {
                invoke.resolve(phonePairingReport(false, null, null, "pairing_active"))
                return
            }
            activeQrScanner = NativeQrScannerController(
                activity,
                CompletedQrMessageVerifier(::preparePhonePairing),
                onComplete = { prepared, _ ->
                    synchronized(stateLock) { activeQrScanner = null }
                    showPairingResponse(prepared, invoke)
                },
                onFailure = { category ->
                    synchronized(stateLock) { activeQrScanner = null }
                    cancelPendingPairing()
                    invoke.resolve(phonePairingReport(false, null, null, category))
                },
            )
            activeQrScanner?.start()
        }
    }

    private fun runUsbPairing(token: UUID, invoke: Invoke) {
        var session: PhoneStreamSession? = null
        var request: ByteArray? = null
        try {
            session = PhoneStreamSession.connectUsb(PhoneStreamSession.Purpose.PAIRING)
            synchronized(stateLock) {
                if (activeUsbToken != token) throw StreamTransportException()
                activeUsbSession = session
            }
            request = session.receiveRequest()
            val prepared = preparePhonePairingUsb(request, session)
            synchronized(stateLock) { activeUsbSession = null }
            session = null
            activity.runOnUiThread {
                val stillActive = synchronized(stateLock) {
                    (activeUsbToken == token).also { activeUsbToken = null }
                }
                if (stillActive) {
                    showPairingResponse(prepared, invoke)
                } else {
                    cancelPendingPairing()
                    invoke.resolve(phonePairingReport(false, null, null, "usb_transport_failed"))
                }
            }
        } catch (_: Exception) {
            cancelPendingPairing()
            synchronized(stateLock) {
                if (activeUsbToken == token) activeUsbToken = null
                if (activeUsbSession === session) activeUsbSession = null
            }
            session?.close()
            invoke.resolve(phonePairingReport(false, null, null, "usb_transport_failed"))
        } finally {
            request?.fill(0)
        }
    }

    private fun preparePhonePairingUsb(
        message: ByteArray,
        session: PhoneStreamSession,
    ): PreparedPhonePairing {
        try {
            productionIdentity.open()
        } catch (error: PhoneIdentityKeyStore.KeyStoreException) {
            if (error.category != PhoneIdentityKeyStore.Category.MISSING) throw error
            productionIdentity.provision()
        }
        val signedResponse = productionIdentity.createPairingResponse(message)
        return try {
            val display = pairingConfirmation.begin(message, signedResponse)
            session.sendResponse(signedResponse)
            PreparedPhonePairing(display, emptyList())
        } finally {
            signedResponse.fill(0)
        }
    }

    private fun preparePhonePairing(message: ByteArray): PreparedPhonePairing {
        try {
            productionIdentity.open()
        } catch (error: PhoneIdentityKeyStore.KeyStoreException) {
            if (error.category != PhoneIdentityKeyStore.Category.MISSING) throw error
            productionIdentity.provision()
        }
        val signedResponse = productionIdentity.createPairingResponse(message)
        return try {
            val display = pairingConfirmation.begin(message, signedResponse)
            PreparedPhonePairing(
                display,
                QrFraming.fragment(signedResponse, RESPONSE_QR_CHUNK_BYTES),
            )
        } finally {
            signedResponse.fill(0)
        }
    }

    private fun showPairingResponse(prepared: PreparedPhonePairing, invoke: Invoke) {
        synchronized(stateLock) {
            activePairingResponse = NativePairingResponseController(
                activity,
                prepared,
                pairingConfirmation,
                onComplete = { committed ->
                    synchronized(stateLock) { activePairingResponse = null }
                    invoke.resolve(
                        phonePairingReport(
                            true,
                            committed.desktopLabel,
                            committed.transcriptFingerprint,
                            null,
                        ),
                    )
                },
                onFailure = { category ->
                    synchronized(stateLock) { activePairingResponse = null }
                    invoke.resolve(phonePairingReport(false, null, null, category))
                },
            )
            activePairingResponse?.start()
        }
    }

    private fun cancelPairingResponse() {
        val controller = synchronized(stateLock) {
            activePairingResponse.also { activePairingResponse = null }
        }
        controller?.cancel()
    }

    private fun startPhoneUnwrapScanner(invoke: Invoke) {
        synchronized(stateLock) {
            if (nativeOperationActive()) {
                invoke.resolve(phoneUnwrapReport(false, false, null, "unwrap_active"))
                return
            }
            activeQrScanner = NativeQrScannerController(
                activity,
                CompletedQrMessageVerifier(::preparePhoneUnwrap),
                onComplete = { pending, _ ->
                    pending.invoke = invoke
                    synchronized(stateLock) {
                        activeQrScanner = null
                        activePhoneUnwrap = pending
                    }
                    showPhoneUnwrapPrompt(pending, invoke)
                },
                onFailure = { category ->
                    synchronized(stateLock) { activeQrScanner = null }
                    invoke.resolve(phoneUnwrapReport(false, false, null, category))
                },
            )
            activeQrScanner?.start()
        }
    }

    private fun runUsbUnwrap(token: UUID, invoke: Invoke?) {
        var session: PhoneStreamSession? = null
        var request: ByteArray? = null
        try {
            session = PhoneStreamSession.connectUsb(PhoneStreamSession.Purpose.UNWRAP)
            synchronized(stateLock) {
                if (activeUsbToken != token) throw StreamTransportException()
                activeUsbSession = session
            }
            request = session.receiveRequest()
            val pending = preparePhoneUnwrap(request).also {
                it.invoke = invoke
                it.streamSession = session
                it.streamFailureCategory = "usb_transport_failed"
            }
            synchronized(stateLock) {
                if (activeUsbToken != token) throw StreamTransportException()
                activeUsbToken = null
                activeUsbSession = null
                activePhoneUnwrap = pending
            }
            session.watchPeerDisconnect {
                mainHandler.post {
                    finishPhoneUnwrap(
                        pending.token,
                        invoke,
                        pending.streamFailureCategory ?: "usb_transport_failed",
                        true,
                    )
                }
            }
            session = null
            activity.runOnUiThread { showPhoneUnwrapPrompt(pending, invoke) }
        } catch (_: Exception) {
            synchronized(stateLock) {
                if (activeUsbToken == token) activeUsbToken = null
                if (activeUsbSession === session) activeUsbSession = null
            }
            session?.close()
            invoke?.resolve(phoneUnwrapReport(false, false, null, "usb_transport_failed"))
        } finally {
            request?.fill(0)
        }
    }

    private fun runWifiUnwrap(token: UUID, invoke: Invoke) {
        var listener: PhoneWifiListener? = null
        var session: PhoneStreamSession? = null
        var request: ByteArray? = null
        try {
            listener = PhoneWifiListener.start()
            synchronized(stateLock) {
                if (activeWifiToken != token) throw StreamTransportException()
                activeWifiListener = listener
            }
            session = listener.acceptUnwrap()
            synchronized(stateLock) {
                if (activeWifiToken != token) throw StreamTransportException()
                if (activeWifiListener === listener) activeWifiListener = null
                activeWifiSession = session
            }
            listener = null
            request = session.receiveRequest()
            val pending = preparePhoneUnwrap(request).also {
                it.invoke = invoke
                it.streamSession = session
                it.streamFailureCategory = WIFI_TRANSPORT_FAILURE
            }
            synchronized(stateLock) {
                if (activeWifiToken != token) throw StreamTransportException()
                activeWifiToken = null
                activeWifiInvoke = null
                activeWifiSession = null
                activePhoneUnwrap = pending
            }
            session.watchPeerDisconnect {
                mainHandler.post {
                    finishPhoneUnwrap(
                        pending.token,
                        invoke,
                        pending.streamFailureCategory ?: "wifi_transport_failed",
                        true,
                    )
                }
            }
            session = null
            activity.runOnUiThread { showPhoneUnwrapPrompt(pending, invoke) }
        } catch (error: Exception) {
            val ownedInvoke = synchronized(stateLock) {
                if (activeWifiToken != token) {
                    null
                } else {
                    activeWifiToken = null
                    activeWifiInvoke.also {
                        activeWifiInvoke = null
                        if (activeWifiListener === listener) activeWifiListener = null
                        if (activeWifiSession === session) activeWifiSession = null
                    }
                }
            }
            listener?.close()
            session?.close()
            ownedInvoke?.resolve(
                phoneUnwrapReport(
                    false,
                    false,
                    null,
                    if (error is WifiListenerTimeoutException) {
                        WIFI_LISTENER_TIMEOUT
                    } else {
                        WIFI_TRANSPORT_FAILURE
                    },
                ),
            )
        } finally {
            request?.fill(0)
        }
    }

    private fun preparePhoneUnwrap(message: ByteArray): PendingPhoneUnwrap {
        val scope = OfflineEnvelopeCrypto.requestScope(message)
        var store: PairingStateStore? = null
        try {
            store = PairingStateStore.open(activity, scope.desktopId, scope.identityId)
            val verified = OfflineEnvelopeCrypto.verifyRequestAndConsume(
                message,
                store,
                System.currentTimeMillis() / 1_000,
            )
            val parsed = TaggedRecipientCrypto.parse(verified.request.stanza)
            val prepared = productionIdentity.prepareIdentityAgreement(
                verified.request.identityId,
                parsed.ephemeralPublic,
            )
            return PendingPhoneUnwrap(
                token = UUID.randomUUID(),
                cancellation = CancellationSignal(),
                agreement = prepared.agreement,
                ephemeralPublicKey = parsed.ephemeralPublic,
                identityPublicKey = prepared.identityPublicKey,
                stanza = verified.request.stanza,
                request = verified,
                requestFingerprint = verified.digest.toHex(),
                callerHint = verified.request.callerHint,
            )
        } finally {
            store?.close()
            scope.desktopId.fill(0)
            scope.identityId.fill(0)
        }
    }

    private fun showPhoneUnwrapPrompt(pending: PendingPhoneUnwrap, invoke: Invoke?) {
        if (!isPhoneUnwrapActive(pending.token)) return
        try {
            val cryptoObject = BiometricPrompt.CryptoObject::class.java
                .getConstructor(KeyAgreement::class.java)
                .newInstance(pending.agreement)
            val hint = pending.callerHint?.take(80) ?: "No caller hint"
            val prompt = BiometricPrompt.Builder(activity)
                .setTitle("Approve one file-key unwrap")
                .setSubtitle("Untrusted caller hint: $hint")
                .setDescription("Request ${pending.requestFingerprint}")
                .setAllowedAuthenticators(BiometricManagerCompat.STRONG)
                .setNegativeButton("Cancel", activity.mainExecutor) { _, _ ->
                    finishPhoneUnwrap(pending.token, invoke, "user_cancelled", true)
                }
                .build()
            pending.timeout = Runnable {
                finishPhoneUnwrap(pending.token, invoke, "authentication_timeout", true)
            }
            mainHandler.postDelayed(pending.timeout!!, AUTHENTICATION_TIMEOUT_MILLIS)
            prompt.authenticate(
                cryptoObject,
                pending.cancellation,
                activity.mainExecutor,
                phoneUnwrapAuthenticationCallback(pending, invoke),
            )
        } catch (_: Exception) {
            finishPhoneUnwrap(pending.token, invoke, "unsupported_api", true)
        }
    }

    private fun phoneUnwrapAuthenticationCallback(
        pending: PendingPhoneUnwrap,
        invoke: Invoke?,
    ) = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            if (!isPhoneUnwrapActive(pending.token)) return
            val returned = try {
                result.cryptoObject?.javaClass?.getMethod("getKeyAgreement")
                    ?.invoke(result.cryptoObject) as? KeyAgreement
            } catch (_: ReflectiveOperationException) {
                null
            }
            if (returned !== pending.agreement) {
                finishPhoneUnwrap(pending.token, invoke, "agreement_failed", true)
                return
            }
            performPhoneUnwrap(pending, returned, invoke)
        }

        override fun onAuthenticationFailed() {
            when (authenticationFailureDisposition()) {
                AuthenticationFailureDisposition.KEEP_PENDING -> Unit
                AuthenticationFailureDisposition.TERMINATE ->
                    finishPhoneUnwrap(pending.token, invoke, "authentication_failed", true)
            }
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            finishPhoneUnwrap(
                pending.token,
                invoke,
                authenticationErrorCategory(errorCode),
                false,
            )
        }
    }

    private fun performPhoneUnwrap(
        pending: PendingPhoneUnwrap,
        agreement: KeyAgreement,
        invoke: Invoke?,
    ) {
        var secret: ByteArray? = null
        var fileKey: ByteArray? = null
        var response: ByteArray? = null
        try {
            if (System.currentTimeMillis() / 1_000 > pending.request.request.expiresAtUnix) {
                throw OfflineEnvelopeCrypto.ProtocolException()
            }
            agreement.doPhase(pending.ephemeralPublicKey, true)
            secret = agreement.generateSecret()
            fileKey = TaggedRecipientCrypto.unwrapWithSharedSecret(
                pending.identityPublicKey,
                pending.stanza,
                secret,
            )
            response = productionIdentity.createUnwrapResponse(pending.request, fileKey)
            val streamSession = pending.streamSession
            if (streamSession != null) {
                val owned = takePhoneUnwrapForStreamResponse(pending.token) ?: return
                owned.timeout?.let(mainHandler::removeCallbacks)
                val report = try {
                    streamSession.sendResponse(response)
                    phoneUnwrapReport(true, true, owned.requestFingerprint, null)
                } catch (_: Exception) {
                    streamSession.close()
                    phoneUnwrapReport(
                        false,
                        false,
                        owned.requestFingerprint,
                        owned.streamFailureCategory ?: "agreement_failed",
                    )
                }
                takeStreamResponse(owned.token)?.invoke?.resolve(report)
                return
            }
            val qrInvoke = invoke ?: throw OfflineEnvelopeCrypto.ProtocolException()
            val prepared = PreparedUnwrapResponse(
                pending.requestFingerprint,
                QrFraming.fragment(response, RESPONSE_QR_CHUNK_BYTES),
            )
            takePhoneUnwrap(pending.token)?.timeout?.let(mainHandler::removeCallbacks)
            showUnwrapResponse(prepared, qrInvoke)
        } catch (_: KeyPermanentlyInvalidatedException) {
            finishPhoneUnwrap(pending.token, invoke, "key_permanently_invalidated", false)
        } catch (_: OfflineEnvelopeCrypto.ProtocolException) {
            finishPhoneUnwrap(pending.token, invoke, "request_expired", false)
        } catch (_: Exception) {
            finishPhoneUnwrap(pending.token, invoke, "agreement_failed", false)
        } finally {
            secret?.fill(0)
            fileKey?.fill(0)
            response?.fill(0)
        }
    }

    private fun showUnwrapResponse(prepared: PreparedUnwrapResponse, invoke: Invoke) {
        synchronized(stateLock) {
            activeUnwrapResponse = NativeUnwrapResponseController(
                activity,
                prepared,
                onComplete = {
                    synchronized(stateLock) { activeUnwrapResponse = null }
                    invoke.resolve(phoneUnwrapReport(true, true, prepared.requestFingerprint, null))
                },
                onFailure = { category ->
                    synchronized(stateLock) { activeUnwrapResponse = null }
                    invoke.resolve(phoneUnwrapReport(true, false, prepared.requestFingerprint, category))
                },
            )
            activeUnwrapResponse?.start()
        }
    }

    private fun finishPhoneUnwrap(token: UUID, invoke: Invoke?, error: String, cancel: Boolean) {
        val pending = takePhoneUnwrap(token) ?: return
        pending.timeout?.let(mainHandler::removeCallbacks)
        if (cancel && !pending.cancellation.isCanceled) pending.cancellation.cancel()
        pending.streamSession?.close()
        invoke?.resolve(phoneUnwrapReport(false, false, pending.requestFingerprint, error))
    }

    private fun takePhoneUnwrap(token: UUID): PendingPhoneUnwrap? = synchronized(stateLock) {
        activePhoneUnwrap?.takeIf { it.token == token }?.also { activePhoneUnwrap = null }
    }

    private fun takePhoneUnwrapForStreamResponse(token: UUID): PendingPhoneUnwrap? =
        synchronized(stateLock) {
            if (activeStreamResponse != null) return@synchronized null
            activePhoneUnwrap?.takeIf { it.token == token }?.also {
                activePhoneUnwrap = null
                activeStreamResponse = it
            }
        }

    private fun takeStreamResponse(token: UUID): PendingPhoneUnwrap? = synchronized(stateLock) {
        activeStreamResponse?.takeIf { it.token == token }?.also { activeStreamResponse = null }
    }

    private fun isPhoneUnwrapActive(token: UUID): Boolean = synchronized(stateLock) {
        activePhoneUnwrap?.token == token
    }

    private fun cancelPhoneUnwrap(error: String) {
        val pending = synchronized(stateLock) {
            activePhoneUnwrap.also { activePhoneUnwrap = null }
        } ?: return
        pending.timeout?.let(mainHandler::removeCallbacks)
        if (!pending.cancellation.isCanceled) pending.cancellation.cancel()
        pending.streamSession?.close()
        pending.invoke?.resolve(phoneUnwrapReport(false, false, pending.requestFingerprint, error))
    }

    private fun cancelUnwrapResponse() {
        val controller = synchronized(stateLock) {
            activeUnwrapResponse.also { activeUnwrapResponse = null }
        }
        controller?.cancel()
    }

    private fun cancelUsbSession() {
        val session = synchronized(stateLock) {
            activeUsbToken = null
            activeUsbSession.also { activeUsbSession = null }
        }
        session?.close()
    }

    private fun cancelWifiOperation(
        error: String,
        includePendingAuthorization: Boolean,
    ): Boolean {
        var pending: PendingPhoneUnwrap? = null
        var listener: PhoneWifiListener? = null
        var session: PhoneStreamSession? = null
        var unwrapInvoke: Invoke? = null
        var cancelled = false
        synchronized(stateLock) {
            val currentPending = activePhoneUnwrap
            if (
                includePendingAuthorization &&
                currentPending?.streamFailureCategory == WIFI_TRANSPORT_FAILURE
            ) {
                activePhoneUnwrap = null
                pending = currentPending
                cancelled = true
            } else if (
                activeWifiToken != null || activeWifiInvoke != null ||
                activeWifiListener != null || activeWifiSession != null
            ) {
                activeWifiToken = null
                unwrapInvoke = activeWifiInvoke
                activeWifiInvoke = null
                listener = activeWifiListener
                activeWifiListener = null
                session = activeWifiSession
                activeWifiSession = null
                cancelled = true
            }
        }
        pending?.let { current ->
            current.timeout?.let(mainHandler::removeCallbacks)
            if (!current.cancellation.isCanceled) current.cancellation.cancel()
            current.streamSession?.close()
            current.invoke?.resolve(
                phoneUnwrapReport(false, false, current.requestFingerprint, error),
            )
        }
        listener?.close()
        session?.close()
        unwrapInvoke?.resolve(phoneUnwrapReport(false, false, null, error))
        return cancelled
    }

    private fun wifiOperationActive(): Boolean =
        activeWifiToken != null || activeWifiInvoke != null ||
            activeWifiListener != null || activeWifiSession != null ||
            activePhoneUnwrap?.streamFailureCategory == WIFI_TRANSPORT_FAILURE

    private fun verifyPairingOfferForScan(message: ByteArray): PairingOfferScanDisplay {
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

    internal fun beginNativePairingConfirmation(
        signedOffer: ByteArray,
        signedResponse: ByteArray,
    ): PairingConfirmationDisplay = pairingConfirmation.begin(signedOffer, signedResponse)

    internal fun confirmNativePairing(
        displayedFingerprint: String,
        nowUnix: Long,
    ): CommittedPairingDisplay = pairingConfirmation.confirm(displayedFingerprint, nowUnix)

    internal fun cancelPendingPairing() {
        pairingConfirmation.cancel()
    }

    private fun prepareAgreement(invoke: Invoke): PendingAgreement? {
        if (!keys.hasTrackedProbe()) {
            invoke.resolve(agreementReport(false, false, "key_not_found"))
            return null
        }
        if (!keys.isUsableStrongBoxProbe()) {
            invoke.resolve(agreementReport(false, false, "wrong_security_level"))
            return null
        }

        val privateKey = keys.privateKey()
        val probePublicKey = keys.publicKey()
        if (privateKey == null || probePublicKey == null) {
            invoke.resolve(agreementReport(false, false, "key_not_found"))
            return null
        }

        val peerGenerator = KeyPairGenerator.getInstance("EC")
        peerGenerator.initialize(ECGenParameterSpec("secp256r1"))
        val ephemeralKeyPair = peerGenerator.generateKeyPair()
        if (!isP256PublicKey(ephemeralKeyPair.public)) {
            invoke.resolve(agreementReport(false, false, "invalid_peer_key"))
            return null
        }

        val expectedFileKey = ByteArray(TaggedRecipientCrypto.FILE_KEY_BYTES)
        SecureRandom().nextBytes(expectedFileKey)
        val identityId = ByteArray(TaggedRecipientCrypto.FILE_KEY_BYTES)
        SecureRandom().nextBytes(identityId)
        val desktopSelectionKeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val stanza = try {
            TaggedRecipientCrypto.wrapV2ForTest(
                phoneIdentityPublic = probePublicKey,
                desktopSelectionPublic = desktopSelectionKeyPair.public,
                ephemeralPrivate = ephemeralKeyPair.private,
                ephemeralPublic = ephemeralKeyPair.public,
                identityId = identityId,
                fileKey = expectedFileKey,
            )
        } catch (_: Exception) {
            expectedFileKey.fill(0)
            invoke.resolve(agreementReport(false, false, "agreement_failed"))
            return null
        } finally {
            identityId.fill(0)
        }
        val protocolGenerator = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        val desktopSigning = protocolGenerator.generateKeyPair()
        val desktopSession = protocolGenerator.generateKeyPair()
        val phoneSigning = protocolGenerator.generateKeyPair()
        val verifiedRequest = try {
            OfflineEnvelopeCrypto.createSignedRequest(
                stanza,
                desktopSigning,
                desktopSession.public,
                System.currentTimeMillis() / 1000,
                SecureRandom(),
            )
        } catch (_: Exception) {
            expectedFileKey.fill(0)
            invoke.resolve(agreementReport(false, false, "agreement_failed"))
            return null
        }

        val agreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore")
        agreement.init(privateKey)
        val pending = PendingAgreement(
            token = UUID.randomUUID(),
            invoke = invoke,
            cancellation = CancellationSignal(),
            agreement = agreement,
            ephemeralPublicKey = ephemeralKeyPair.public,
            probePublicKey = probePublicKey,
            stanza = stanza,
            expectedFileKey = expectedFileKey,
            verifiedRequest = verifiedRequest,
            phoneSigning = phoneSigning,
            desktopSession = desktopSession,
        )

        synchronized(stateLock) {
            if (nativeOperationActive()) {
                expectedFileKey.fill(0)
                invoke.resolve(agreementReport(false, false, "authentication_failed"))
                return null
            }
            active = pending
        }
        return pending
    }

    private fun showPrompt(pending: PendingAgreement) {
        if (!isActive(pending.token)) return
        try {
            val cryptoObject = BiometricPrompt.CryptoObject::class.java
                .getConstructor(KeyAgreement::class.java)
                .newInstance(pending.agreement)
            val prompt = BiometricPrompt.Builder(activity)
                .setTitle("Approve tagged-recipient probe")
                .setSubtitle("Authorizes this disposable StrongBox unwrap only")
                .setAllowedAuthenticators(BiometricManagerCompat.STRONG)
                .setNegativeButton("Cancel", activity.mainExecutor) { _, _ ->
                    complete(pending.token, false, false, "user_cancelled", true)
                }
                .build()

            pending.timeout = Runnable {
                complete(pending.token, false, false, "authentication_timeout", true)
            }
            mainHandler.postDelayed(pending.timeout!!, AUTHENTICATION_TIMEOUT_MILLIS)
            prompt.authenticate(
                cryptoObject,
                pending.cancellation,
                activity.mainExecutor,
                authenticationCallback(pending),
            )
        } catch (_: Exception) {
            complete(pending.token, false, false, "unsupported_api", true)
        }
    }

    private fun authenticationCallback(pending: PendingAgreement) =
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (!isActive(pending.token)) return
                val returnedAgreement = try {
                    result.cryptoObject?.javaClass?.getMethod("getKeyAgreement")
                        ?.invoke(result.cryptoObject) as? KeyAgreement
                } catch (_: ReflectiveOperationException) {
                    null
                }
                if (returnedAgreement !== pending.agreement) {
                    complete(pending.token, false, false, "agreement_failed", true)
                    return
                }
                performAgreement(pending, returnedAgreement)
            }

            override fun onAuthenticationFailed() {
                when (authenticationFailureDisposition()) {
                    AuthenticationFailureDisposition.KEEP_PENDING -> Unit
                    AuthenticationFailureDisposition.TERMINATE ->
                        complete(pending.token, false, false, "authentication_failed", true)
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                val category = authenticationErrorCategory(errorCode)
                complete(pending.token, false, false, category, false)
            }
        }

    private fun performAgreement(pending: PendingAgreement, agreement: KeyAgreement) {
        var phoneSecret: ByteArray? = null
        var unwrappedFileKey: ByteArray? = null
        try {
            agreement.doPhase(pending.ephemeralPublicKey, true)
            phoneSecret = agreement.generateSecret()
            unwrappedFileKey = TaggedRecipientCrypto.unwrapWithSharedSecret(
                pending.probePublicKey,
                pending.stanza,
                phoneSecret,
            )
            val matches = MessageDigest.isEqual(unwrappedFileKey, pending.expectedFileKey)
            if (!matches) {
                complete(pending.token, true, false, "agreement_mismatch", false)
                return
            }
            val response = OfflineEnvelopeCrypto.sealResponse(
                pending.verifiedRequest,
                unwrappedFileKey,
                pending.phoneSigning,
                SecureRandom(),
            )
            val returnedFileKey = OfflineEnvelopeCrypto.openResponse(
                response.encoded,
                pending.verifiedRequest,
                pending.phoneSigning.public,
                pending.desktopSession.private,
            )
            val envelopeMatches = MessageDigest.isEqual(returnedFileKey, pending.expectedFileKey)
            returnedFileKey.fill(0)
            complete(
                pending.token,
                true,
                envelopeMatches,
                if (envelopeMatches) null else "agreement_mismatch",
                false,
            )
        } catch (_: KeyPermanentlyInvalidatedException) {
            complete(pending.token, true, false, "key_permanently_invalidated", false)
        } catch (_: Exception) {
            complete(pending.token, true, false, "agreement_failed", false)
        } finally {
            phoneSecret?.fill(0)
            unwrappedFileKey?.fill(0)
        }
    }

    private fun complete(
        token: UUID,
        authenticated: Boolean,
        matches: Boolean,
        error: String?,
        cancel: Boolean,
    ) {
        val pending = synchronized(stateLock) {
            val current = active
            if (current?.token != token) null else current.also { active = null }
        } ?: return
        pending.timeout?.let(mainHandler::removeCallbacks)
        if (cancel && !pending.cancellation.isCanceled) pending.cancellation.cancel()
        pending.expectedFileKey.fill(0)
        pending.invoke.resolve(agreementReport(authenticated, matches, error))
    }

    private fun cancelActive(error: String) {
        val token = synchronized(stateLock) { active?.token } ?: return
        complete(token, false, false, error, true)
    }

    private fun isActive(token: UUID): Boolean = synchronized(stateLock) { active?.token == token }

    private fun nativeOperationActive(): Boolean =
        active != null || activeQrScanner != null || activePairingResponse != null ||
            activePhoneUnwrap != null || activeStreamResponse != null ||
            activeUnwrapResponse != null ||
            activeUsbSession != null || activeUsbToken != null ||
            activeWifiListener != null || activeWifiSession != null || activeWifiToken != null ||
            cameraPermissionPending ||
            pairingPermissionPending || unwrapPermissionPending || activeLifecycle != null ||
            activeProvisioning

    private fun startLifecycleConfirmation(
        invoke: Invoke,
        title: String,
        message: String,
        positiveLabel: String,
        operation: () -> JSObject,
    ) {
        synchronized(stateLock) {
            if (nativeOperationActive()) {
                invoke.resolve(lifecycleReport(false, "ready", "operation_active"))
                return
            }
            activeLifecycle = PendingLifecycle(invoke)
        }
        activity.runOnUiThread {
            val dialog = AlertDialog.Builder(activity)
                .setTitle(title)
                .setMessage(message)
                .setNegativeButton("Cancel") { _, _ ->
                    finishLifecycle(invoke, lifecycleReport(false, "ready", "user_cancelled"))
                }
                .setPositiveButton(positiveLabel, null)
                .create()
            dialog.setOnShowListener {
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                    val result = try {
                        operation()
                    } catch (error: PairingStateStore.PairingStateException) {
                        lifecycleReport(false, "unavailable", pairingCategory(error.category))
                    } catch (error: PhoneIdentityKeyStore.KeyStoreException) {
                        lifecycleReport(false, "unavailable", keyStoreCategory(error.category))
                    } catch (_: Exception) {
                        lifecycleReport(false, "unavailable", "storage_failed")
                    }
                    dialog.dismiss()
                    finishLifecycle(invoke, result)
                }
            }
            synchronized(stateLock) {
                activeLifecycle?.takeIf { it.invoke === invoke }?.dialog = dialog
            }
            dialog.show()
        }
    }

    private fun finishLifecycle(invoke: Invoke, report: JSObject) {
        val pending = synchronized(stateLock) {
            activeLifecycle?.takeIf { it.invoke === invoke }?.also { activeLifecycle = null }
        } ?: return
        pending.dialog?.setOnDismissListener(null)
        invoke.resolve(report)
    }

    private fun cancelLifecycle() {
        val pending = synchronized(stateLock) {
            activeLifecycle.also { activeLifecycle = null }
        } ?: return
        pending.dialog?.dismiss()
        pending.invoke.resolve(lifecycleReport(false, "ready", "lifecycle_cancelled"))
    }

    private fun identityStatusReport(forcedError: String? = null): JSObject {
        if (forcedError != null) {
            return JSObject().apply {
                put("state", "unavailable")
                put("publicRecipient", null)
                put("pairedDesktops", JSONArray())
                put("recoveryRequired", true)
                put("errorCategory", forcedError)
            }
        }
        return try {
            val provision = productionIdentity.open()
            val pairings = PairingStateStore.list(activity, provision.public.identityId)
            JSObject().apply {
                put("state", "ready")
                put("publicRecipient", provision.public.recipient)
                put("pairedDesktops", JSONArray().apply {
                    pairings.forEach { pairing ->
                        put(JSObject().apply {
                            put("handle", pairing.handle)
                            put("displayLabel", pairing.desktopLabel)
                            put("transcriptFingerprint", pairing.transcriptFingerprint)
                            put("deletionPending", pairing.deletionPending)
                        })
                    }
                })
                put("recoveryRequired", true)
                put("errorCategory", null)
            }
        } catch (error: PhoneIdentityKeyStore.KeyStoreException) {
            val state = when (error.category) {
                PhoneIdentityKeyStore.Category.MISSING -> "not_configured"
                PhoneIdentityKeyStore.Category.DELETION_PENDING -> "deletion_pending"
                else -> "unavailable"
            }
            JSObject().apply {
                put("state", state)
                put("publicRecipient", null)
                put("pairedDesktops", JSONArray())
                put("recoveryRequired", true)
                put("errorCategory", if (state == "not_configured") null else keyStoreCategory(error.category))
            }
        } catch (error: PairingStateStore.PairingStateException) {
            JSObject().apply {
                put("state", "unavailable")
                put("publicRecipient", null)
                put("pairedDesktops", JSONArray())
                put("recoveryRequired", true)
                put("errorCategory", pairingCategory(error.category))
            }
        }
    }

    private fun keyStoreCategory(category: PhoneIdentityKeyStore.Category): String = when (category) {
        PhoneIdentityKeyStore.Category.MISSING -> "identity_missing"
        PhoneIdentityKeyStore.Category.DELETION_PENDING -> "deletion_pending"
        PhoneIdentityKeyStore.Category.STRONGBOX_UNAVAILABLE -> "strongbox_unavailable"
        PhoneIdentityKeyStore.Category.UNSUPPORTED_API -> "unsupported_api"
        PhoneIdentityKeyStore.Category.ALREADY_EXISTS -> "identity_exists"
        else -> "identity_unavailable"
    }

    private fun pairingCategory(category: PairingStateStore.Category): String = when (category) {
        PairingStateStore.Category.MISSING -> "pairing_missing"
        PairingStateStore.Category.DELETION_PENDING -> "deletion_pending"
        PairingStateStore.Category.LOCKED -> "pairing_busy"
        else -> "pairing_state_failed"
    }

    private fun lifecycleReport(completed: Boolean, state: String, error: String?): JSObject =
        JSObject().apply {
            put("completed", completed)
            put("state", state)
            put("errorCategory", error)
        }

    private fun runPairingStorageDoctor(): JSObject {
        var store: PairingStateStore? = null
        var syntheticFileKey: ByteArray? = null
        var assembledOffer: ByteArray? = null
        var assembledResponse: ByteArray? = null
        var noBackupStorage = PairingStateStore.doctorRootIsNoBackup(activity)
        var qrFragmented = false
        var qrOutOfOrderReassembled = false
        var qrCorruptionRejected = false
        var qrTimeoutRejected = false
        var transcriptVerified = false
        var fingerprintMismatchRejected = false
        var cancellationRejected = false
        var confirmationCommitted = false
        var duplicateConfirmationRejected = false
        var atomicStateCreated = false
        var verifiedBeforeConsume = false
        var replayRejectedAfterReopen = false
        var wrongScopeRejected = false
        var missingStateRejectedAfterDelete = false
        var cleanupComplete: Boolean
        var errorCategory: String? = null
        try {
            if (!PairingStateStore.cleanupDoctorArtifacts(activity)) {
                throw PairingStateStore.PairingStateException(PairingStateStore.Category.STORAGE)
            }
            val generator = KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }
            val identity = generator.generateKeyPair()
            val ephemeral = generator.generateKeyPair()
            val desktopSigning = generator.generateKeyPair()
            val desktopSelection = generator.generateKeyPair()
            val desktopSession = generator.generateKeyPair()
            val phoneSigning = generator.generateKeyPair()
            val random = SecureRandom()
            val transcript = OfflineEnvelopeCrypto.createSyntheticPairingTranscript(
                identity.public,
                desktopSigning,
                desktopSelection.public,
                phoneSigning,
                random,
            )
            val offerFrames = QrFraming.fragment(transcript.signedOffer, 64, random)
            val responseFrames = QrFraming.fragment(transcript.signedResponse, 64, random)
            qrFragmented = offerFrames.size > 1 && responseFrames.size > 1
            val reconstructedOffer = reassembleDoctorFrames(offerFrames)
            val reconstructedResponse = reassembleDoctorFrames(responseFrames)
            assembledOffer = reconstructedOffer
            assembledResponse = reconstructedResponse
            qrOutOfOrderReassembled = MessageDigest.isEqual(reconstructedOffer, transcript.signedOffer) &&
                MessageDigest.isEqual(reconstructedResponse, transcript.signedResponse)
            qrCorruptionRejected = rejectsDoctorQrConflict(offerFrames.first())
            qrTimeoutRejected = rejectsDoctorQrTimeout(offerFrames)
            val creator = PairingStateCreator { record, nowUnix ->
                PairingStateStore.createDoctor(activity, record, nowUnix)
            }
            val mismatch = PairingConfirmationSession.beginWithCreator(
                reconstructedOffer,
                reconstructedResponse,
                creator,
            )
            transcriptVerified = mismatch.display.desktopLabel == "Pairing confirmation Doctor" &&
                mismatch.display.transcriptFingerprint.length == 64
            val wrongFingerprint = mismatch.display.transcriptFingerprint.let { value ->
                (if (value[0] == '0') '1' else '0') + value.drop(1)
            }
            fingerprintMismatchRejected = try {
                mismatch.confirm(wrongFingerprint, System.currentTimeMillis() / 1000)
                false
            } catch (error: PairingConfirmationSession.PairingConfirmationException) {
                error.category == PairingConfirmationSession.Category.FINGERPRINT_MISMATCH
            }
            val cancelled = PairingConfirmationSession.beginWithCreator(
                reconstructedOffer,
                reconstructedResponse,
                creator,
            )
            cancelled.cancel()
            cancellationRejected = try {
                cancelled.confirm(cancelled.display.transcriptFingerprint, System.currentTimeMillis() / 1000)
                false
            } catch (error: PairingConfirmationSession.PairingConfirmationException) {
                error.category == PairingConfirmationSession.Category.SESSION_CLOSED
            }
            val confirmation = PairingConfirmationSession.beginWithCreator(
                reconstructedOffer,
                reconstructedResponse,
                creator,
            )
            val nowUnix = System.currentTimeMillis() / 1000
            val committed = confirmation.confirm(confirmation.display.transcriptFingerprint, nowUnix)
            confirmationCommitted = committed == confirmation.display.let {
                CommittedPairingDisplay(it.desktopLabel, it.transcriptFingerprint)
            }
            duplicateConfirmationRejected = try {
                confirmation.confirm(confirmation.display.transcriptFingerprint, nowUnix)
                false
            } catch (error: PairingConfirmationSession.PairingConfirmationException) {
                error.category == PairingConfirmationSession.Category.SESSION_CLOSED
            }
            val verifiedOffer = OfflineEnvelopeCrypto.verifyPairingOffer(transcript.signedOffer)
            val verifiedResponse = OfflineEnvelopeCrypto.verifyPairingResponse(
                transcript.signedResponse,
                verifiedOffer,
            )
            val record = StoredPairingRecord.fromVerifiedTranscript(verifiedOffer, verifiedResponse)
            syntheticFileKey = ByteArray(TaggedRecipientCrypto.FILE_KEY_BYTES).also {
                random.nextBytes(it)
            }
            val stanza = TaggedRecipientCrypto.wrapForTest(
                identity.public,
                ephemeral.private,
                ephemeral.public,
                syntheticFileKey,
            )
            val request = OfflineEnvelopeCrypto.createSignedRequestForPairing(
                stanza,
                desktopSigning,
                desktopSession.public,
                record.desktopId,
                record.identityId,
                nowUnix,
                random,
            )
            store = PairingStateStore.openDoctor(activity, record.desktopId, record.identityId)
            val stored = store.pairingRecord()
            atomicStateCreated = MessageDigest.isEqual(stored.desktopId, record.desktopId) &&
                MessageDigest.isEqual(stored.identityId, record.identityId) &&
                MessageDigest.isEqual(stored.offerDigest, record.offerDigest)
            val consumed = OfflineEnvelopeCrypto.verifyRequestAndConsume(
                request.signedBytes,
                store,
                nowUnix,
            )
            verifiedBeforeConsume = MessageDigest.isEqual(consumed.digest, request.digest)
            store.close()

            wrongScopeRejected = try {
                PairingStateStore.openDoctor(
                    activity,
                    record.desktopId.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() },
                    record.identityId,
                ).close()
                false
            } catch (_: PairingStateStore.PairingStateException) {
                true
            }

            store = PairingStateStore.openDoctor(activity, record.desktopId, record.identityId)
            replayRejectedAfterReopen = try {
                OfflineEnvelopeCrypto.verifyRequestAndConsume(request.signedBytes, store, nowUnix)
                false
            } catch (error: PairingStateStore.PairingStateException) {
                error.category == PairingStateStore.Category.REPLAY
            }
            store.deleteState()
            store.close()
            store = null
            missingStateRejectedAfterDelete = try {
                PairingStateStore.openDoctor(activity, record.desktopId, record.identityId).close()
                false
            } catch (error: PairingStateStore.PairingStateException) {
                error.category == PairingStateStore.Category.MISSING
            }
        } catch (error: PairingStateStore.PairingStateException) {
            errorCategory = when (error.category) {
                PairingStateStore.Category.REPLAY -> "replay"
                PairingStateStore.Category.CLOCK_ROLLBACK -> "clock_rollback"
                PairingStateStore.Category.CAPACITY -> "replay_capacity"
                else -> "pairing_state_failed"
            }
        } catch (_: Exception) {
            errorCategory = "pairing_state_failed"
        } finally {
            try {
                store?.close()
            } catch (_: Exception) {
                errorCategory = "pairing_state_failed"
            }
            syntheticFileKey?.fill(0)
            assembledOffer?.fill(0)
            assembledResponse?.fill(0)
            cleanupComplete = PairingStateStore.cleanupDoctorArtifacts(activity)
            if (!cleanupComplete && errorCategory == null) errorCategory = "pairing_state_failed"
            noBackupStorage = noBackupStorage && PairingStateStore.doctorRootIsNoBackup(activity)
        }
        return JSObject().apply {
            put("noBackupStorage", noBackupStorage)
            put("qrFragmented", qrFragmented)
            put("qrOutOfOrderReassembled", qrOutOfOrderReassembled)
            put("qrCorruptionRejected", qrCorruptionRejected)
            put("qrTimeoutRejected", qrTimeoutRejected)
            put("transcriptVerified", transcriptVerified)
            put("fingerprintMismatchRejected", fingerprintMismatchRejected)
            put("cancellationRejected", cancellationRejected)
            put("confirmationCommitted", confirmationCommitted)
            put("duplicateConfirmationRejected", duplicateConfirmationRejected)
            put("atomicStateCreated", atomicStateCreated)
            put("verifiedBeforeConsume", verifiedBeforeConsume)
            put("replayRejectedAfterReopen", replayRejectedAfterReopen)
            put("wrongScopeRejected", wrongScopeRejected)
            put("missingStateRejectedAfterDelete", missingStateRejectedAfterDelete)
            put("cleanupComplete", cleanupComplete)
            put("errorCategory", errorCategory)
        }
    }

    private fun reassembleDoctorFrames(frames: List<EncodedQrFrame>): ByteArray {
        val reassembler = QrReassembler()
        var nowMs = 1_000L
        val order = frames.indices.reversed()
        val first = order.first()
        reassembler.push(frames[first].value, nowMs++)
        reassembler.push(frames[first].value, nowMs++)
        for (index in order.drop(1)) {
            when (val status = reassembler.push(frames[index].value, nowMs++)) {
                is QrAssemblyStatus.Complete -> return status.message
                is QrAssemblyStatus.InProgress -> Unit
            }
        }
        throw QrFraming.QrException(QrFraming.Category.MALFORMED_FRAME)
    }

    private fun rejectsDoctorQrConflict(frame: EncodedQrFrame): Boolean {
        val decoded = QrFraming.decode(frame.value)
        val changed = decoded.chunk.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val conflicting = try {
            QrFraming.encode(
                QrFraming.Frame(
                    decoded.transferId,
                    decoded.digest,
                    decoded.index,
                    decoded.count,
                    decoded.totalLength,
                    changed,
                ),
            )
        } finally {
            decoded.chunk.fill(0)
            changed.fill(0)
        }
        val reassembler = QrReassembler()
        reassembler.push(frame.value, 0)
        return try {
            reassembler.push(conflicting.value, 1)
            false
        } catch (error: QrFraming.QrException) {
            error.category == QrFraming.Category.CONFLICTING_FRAGMENT
        } finally {
            reassembler.reset()
        }
    }

    private fun rejectsDoctorQrTimeout(frames: List<EncodedQrFrame>): Boolean {
        if (frames.size < 2) return false
        val reassembler = QrReassembler()
        reassembler.push(frames[0].value, 0)
        return try {
            reassembler.push(frames[1].value, QrFraming.MAX_ASSEMBLY_AGE_MS + 1)
            false
        } catch (error: QrFraming.QrException) {
            error.category == QrFraming.Category.TIMEOUT
        } finally {
            reassembler.reset()
        }
    }

    private data class PendingAgreement(
        val token: UUID,
        val invoke: Invoke,
        val cancellation: CancellationSignal,
        val agreement: KeyAgreement,
        val ephemeralPublicKey: PublicKey,
        val probePublicKey: PublicKey,
        val stanza: TaggedRecipientCrypto.Stanza,
        val expectedFileKey: ByteArray,
        val verifiedRequest: OfflineEnvelopeCrypto.VerifiedRequest,
        val phoneSigning: KeyPair,
        val desktopSession: KeyPair,
        var timeout: Runnable? = null,
    )

    private data class PendingPhoneUnwrap(
        val token: UUID,
        val cancellation: CancellationSignal,
        val agreement: KeyAgreement,
        val ephemeralPublicKey: PublicKey,
        val identityPublicKey: PublicKey,
        val stanza: TaggedRecipientCrypto.Stanza,
        val request: OfflineEnvelopeCrypto.VerifiedRequest,
        val requestFingerprint: String,
        val callerHint: String?,
        var invoke: Invoke? = null,
        var streamSession: PhoneStreamSession? = null,
        var streamFailureCategory: String? = null,
        var timeout: Runnable? = null,
    )

    private class PendingLifecycle(
        val invoke: Invoke,
        var dialog: AlertDialog? = null,
    )

    companion object {
        private const val AUTHENTICATION_TIMEOUT_MILLIS = 60_000L
        private const val WIFI_TRANSPORT_FAILURE = "wifi_transport_failed"
        private const val WIFI_LISTENER_TIMEOUT = "wifi_listener_timeout"

        private object BiometricManagerCompat {
            const val STRONG = 0x000F
        }

        private fun hasKeyAgreementCryptoObject(): Boolean = try {
            BiometricPrompt.CryptoObject::class.java.getConstructor(KeyAgreement::class.java)
            BiometricPrompt.CryptoObject::class.java.getMethod("getKeyAgreement")
            true
        } catch (_: ReflectiveOperationException) {
            false
        }

        internal fun isP256PublicKey(key: PublicKey): Boolean {
            val ecKey = key as? ECPublicKey ?: return false
            val field = ecKey.params.curve.field as? ECFieldFp ?: return false
            val point = ecKey.w
            if (field.fieldSize != 256 || ecKey.params.cofactor != 1) return false
            if (point.affineX.signum() < 0 || point.affineX >= field.p) return false
            if (point.affineY.signum() < 0 || point.affineY >= field.p) return false
            val left = point.affineY.modPow(java.math.BigInteger.TWO, field.p)
            val right = point.affineX.modPow(java.math.BigInteger.valueOf(3), field.p)
                .add(ecKey.params.curve.a.multiply(point.affineX))
                .add(ecKey.params.curve.b)
                .mod(field.p)
            return left == right
        }

        private fun agreementReport(
            authenticated: Boolean,
            match: Boolean,
            error: String?,
        ): JSObject = JSObject().apply {
            put("recipientProtocol", TaggedRecipientCrypto.STANZA_TAG_V2)
            put("authenticated", authenticated)
            put("agreementMatch", match)
            put("responseEnvelopeMatch", match)
            put("errorCategory", error)
        }

        private fun pairingOfferScanReport(
            scannerStarted: Boolean,
            messageVerified: Boolean,
            desktopLabel: String?,
            offerFingerprint: String?,
            framesAccepted: Int,
            error: String?,
        ): JSObject = JSObject().apply {
            put("scannerStarted", scannerStarted)
            put("messageVerified", messageVerified)
            put("desktopLabel", desktopLabel)
            put("offerFingerprint", offerFingerprint)
            put("framesAccepted", framesAccepted)
            put("errorCategory", error)
        }

        private fun phonePairingReport(
            paired: Boolean,
            desktopLabel: String?,
            transcriptFingerprint: String?,
            errorCategory: String?,
        ): JSObject = JSObject().apply {
            put("paired", paired)
            put("desktopLabel", desktopLabel)
            put("transcriptFingerprint", transcriptFingerprint)
            put("errorCategory", errorCategory)
        }

        private fun phoneUnwrapReport(
            authenticated: Boolean,
            responseDisplayed: Boolean,
            requestFingerprint: String?,
            errorCategory: String?,
        ): JSObject = JSObject().apply {
            put("authenticated", authenticated)
            put("responseDisplayed", responseDisplayed)
            put("requestFingerprint", requestFingerprint)
            put("errorCategory", errorCategory)
        }

        private const val RESPONSE_QR_CHUNK_BYTES = 120

        internal fun authenticationErrorCategory(errorCode: Int): String = when (errorCode) {
            BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED,
            BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
            -> "user_cancelled"
            BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT -> "authentication_timeout"
            else -> "authentication_failed"
        }

        internal fun authenticationFailureDisposition(): AuthenticationFailureDisposition =
            AuthenticationFailureDisposition.KEEP_PENDING
    }
}

internal enum class AuthenticationFailureDisposition {
    KEEP_PENDING,
    TERMINATE,
}
