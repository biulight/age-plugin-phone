package io.github.biulight.phone_identity

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.ext.SdkExtensions
import app.tauri.plugin.JSObject
import javax.crypto.KeyAgreement

internal class StrongBoxDoctor(private val activity: Activity, private val keys: ProbeKeyStore) {
    fun strongBiometricAvailable(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
            activity.getSystemService(BiometricManager::class.java)
                .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    fun capabilities(): JSObject {
        val apiLevel = Build.VERSION.SDK_INT
        val strongBiometric = if (apiLevel >= Build.VERSION_CODES.R) {
            val manager = activity.getSystemService(BiometricManager::class.java)
            when (manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
                BiometricManager.BIOMETRIC_SUCCESS -> "available"
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "not_enrolled"
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "no_hardware"
                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "temporarily_unavailable"
                BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "security_update_required"
                else -> "unknown"
            }
        } else {
            "unsupported"
        }

        val secureLockScreen =
            (activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure
        val extensionLevel = if (apiLevel >= Build.VERSION_CODES.R) {
            SdkExtensions.getExtensionVersion(Build.VERSION_CODES.R)
        } else {
            0
        }
        val cryptoObjectAvailable = try {
            BiometricPrompt.CryptoObject::class.java.getConstructor(KeyAgreement::class.java)
            BiometricPrompt.CryptoObject::class.java.getMethod("getKeyAgreement")
            true
        } catch (_: ReflectiveOperationException) {
            false
        }

        return JSObject().apply {
            put("androidRelease", Build.VERSION.RELEASE ?: "unknown")
            put("apiLevel", apiLevel)
            put("sdkExtensionLevel", extensionLevel)
            put(
                "strongboxFeature",
                activity.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE),
            )
            put("strongBiometric", strongBiometric)
            put("secureLockScreen", secureLockScreen)
            put("keyAgreementCryptoObject", cryptoObjectAvailable)
            put("leftoverProbeKey", keys.hasTrackedProbe())
            put(
                "errorCategory",
                if (apiLevel < Build.VERSION_CODES.S || !cryptoObjectAvailable) {
                    "unsupported_api"
                } else {
                    null
                },
            )
        }
    }
}
