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
import java.security.MessageDigest
import java.security.SecureRandom
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

    fun identityCustody(): JSObject {
        if (!strongBiometricAvailable()) return emptyIdentityCustodyReport("strong_biometric_unavailable")
        val store = PhoneIdentityKeyStore.doctor(activity)
        val noBackupStorage = store.rootIsNoBackup()
        var inspection: PhoneKeyInspection? = null
        var keysDistinct = false
        var metadataBound = false
        var reopened = false
        var duplicateRejected = false
        var preparingRecovered = false
        var errorCategory: String? = null

        runCatching { store.cleanup() }
        try {
            val provisioned = store.provision()
            inspection = provisioned.inspection
            keysDistinct = !MessageDigest.isEqual(
                provisioned.public.identityPublicKey,
                provisioned.public.signingPublicKey,
            )
            val opened = store.open()
            reopened = true
            metadataBound = MessageDigest.isEqual(
                provisioned.public.identityId,
                opened.public.identityId,
            ) && provisioned.public.recipient == opened.public.recipient &&
                MessageDigest.isEqual(
                    provisioned.public.identityPublicKey,
                    opened.public.identityPublicKey,
                ) && MessageDigest.isEqual(
                    provisioned.public.signingPublicKey,
                    opened.public.signingPublicKey,
                )
            duplicateRejected = try {
                store.provision()
                false
            } catch (error: PhoneIdentityKeyStore.KeyStoreException) {
                error.category == PhoneIdentityKeyStore.Category.ALREADY_EXISTS
            }

            if (!store.cleanup()) {
                throw PhoneIdentityKeyStore.KeyStoreException(PhoneIdentityKeyStore.Category.STORAGE)
            }
            store.createPreparingStateForDoctor(ByteArray(16).also(SecureRandom()::nextBytes))
            preparingRecovered = store.provision().recoveredPreparingState
        } catch (error: PhoneIdentityKeyStore.KeyStoreException) {
            errorCategory = error.category.name.lowercase()
        } catch (_: Exception) {
            errorCategory = "identity_custody_failed"
        }
        val cleanupComplete = runCatching { store.cleanup() }.getOrDefault(false)
        if (!cleanupComplete && errorCategory == null) errorCategory = "cleanup_failed"

        return JSObject().apply {
            put("noBackupStorage", noBackupStorage)
            put("identityStrongBox", inspection?.identityStrongBox ?: false)
            put("identityAgreeOnly", inspection?.identityAgreeOnly ?: false)
            put("identityAuthPerUse", inspection?.identityAuthPerUse ?: false)
            put("identityBiometricStrong", inspection?.identityBiometricStrong ?: false)
            put("signingStrongBox", inspection?.signingStrongBox ?: false)
            put("signingPurposeSignOnly", inspection?.signingPurposeSignOnly ?: false)
            put("signingNoUserAuth", inspection?.signingNoUserAuth ?: false)
            put("privateKeysNonExportable", inspection?.privateKeysNonExportable ?: false)
            put("keysDistinct", keysDistinct)
            put("metadataBound", metadataBound)
            put("reopened", reopened)
            put("duplicateRejected", duplicateRejected)
            put("preparingRecovered", preparingRecovered)
            put("cleanupComplete", cleanupComplete)
            put("errorCategory", errorCategory)
        }
    }

    companion object {
        internal fun emptyIdentityCustodyReport(error: String): JSObject = JSObject().apply {
            put("noBackupStorage", false)
            put("identityStrongBox", false)
            put("identityAgreeOnly", false)
            put("identityAuthPerUse", false)
            put("identityBiometricStrong", false)
            put("signingStrongBox", false)
            put("signingPurposeSignOnly", false)
            put("signingNoUserAuth", false)
            put("privateKeysNonExportable", false)
            put("keysDistinct", false)
            put("metadataBound", false)
            put("reopened", false)
            put("duplicateRejected", false)
            put("preparingRecovered", false)
            put("cleanupComplete", true)
            put("errorCategory", error)
        }
    }
}
