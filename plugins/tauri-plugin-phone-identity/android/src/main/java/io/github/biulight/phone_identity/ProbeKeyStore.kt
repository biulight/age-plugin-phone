package io.github.biulight.phone_identity

import android.app.Activity
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import app.tauri.plugin.JSObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID

internal class ProbeKeyStore(activity: Activity) {
    private val preferences =
        activity.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    fun trackedAlias(): String? =
        preferences.getString(ALIAS_KEY, null)?.takeIf(::isValidProbeAlias)

    fun hasTrackedProbe(): Boolean {
        val alias = trackedAlias() ?: return false
        return runCatching { keyStore().containsAlias(alias) }.getOrDefault(false)
    }

    fun createProbe(): JSObject {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return emptyProbeReport("unsupported_api")
        }

        trackedAlias()?.let { existingAlias ->
            if (runCatching { keyStore().containsAlias(existingAlias) }.getOrDefault(false)) {
                return emptyProbeReport("key_generation_failed")
            }
            preferences.edit().remove(ALIAS_KEY).apply()
        }

        val alias = "$ALIAS_PREFIX${UUID.randomUUID()}"
        return try {
            val parameterSpec =
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec(P256_NAME))
                    .setIsStrongBoxBacked(true)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG,
                    )
                    .setInvalidatedByBiometricEnrollment(true)
                    .build()

            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEY_STORE,
            )
            generator.initialize(parameterSpec)
            generator.generateKeyPair()
            if (!preferences.edit().putString(ALIAS_KEY, alias).commit()) {
                keyStore().deleteEntry(alias)
                return emptyProbeReport("key_generation_failed")
            }
            inspect(alias)
        } catch (_: android.security.keystore.StrongBoxUnavailableException) {
            emptyProbeReport("strongbox_unavailable")
        } catch (_: Exception) {
            runCatching { keyStore().deleteEntry(alias) }
            emptyProbeReport("key_generation_failed")
        }
    }

    fun inspect(alias: String): JSObject {
        if (!isValidProbeAlias(alias)) return emptyProbeReport("key_not_found")
        val store = keyStore()
        val privateKey = store.getKey(alias, null) as? PrivateKey
            ?: return emptyProbeReport("key_not_found")
        val keyInfo = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEY_STORE)
            .getKeySpec(privateKey, KeyInfo::class.java)
        val securityLevel = when (keyInfo.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
            else -> "unknown"
        }
        val authenticationType = when (keyInfo.userAuthenticationType) {
            KeyProperties.AUTH_BIOMETRIC_STRONG -> "biometric_strong"
            KeyProperties.AUTH_DEVICE_CREDENTIAL -> "device_credential"
            else -> "other"
        }

        return JSObject().apply {
            put("generated", true)
            put("securityLevel", securityLevel)
            put("originGenerated", keyInfo.origin == KeyProperties.ORIGIN_GENERATED)
            put(
                "purposeAgreeKey",
                keyInfo.purposes and KeyProperties.PURPOSE_AGREE_KEY != 0,
            )
            put("userAuthenticationRequired", keyInfo.isUserAuthenticationRequired)
            put("authPerUse", keyInfo.userAuthenticationValidityDurationSeconds == 0)
            put("authenticationType", authenticationType)
            put(
                "authEnforcedBySecureHardware",
                keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware,
            )
            put("privateKeyFormatIsNull", privateKey.format == null)
            put("privateKeyEncodedIsNull", privateKey.encoded == null)
            put("errorCategory", null)
        }
    }

    fun privateKey(): PrivateKey? {
        val alias = trackedAlias() ?: return null
        return keyStore().getKey(alias, null) as? PrivateKey
    }

    fun publicKey() = trackedAlias()?.let { keyStore().getCertificate(it)?.publicKey }

    fun isUsableStrongBoxProbe(): Boolean {
        val alias = trackedAlias() ?: return false
        val privateKey = keyStore().getKey(alias, null) as? PrivateKey ?: return false
        val info = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEY_STORE)
            .getKeySpec(privateKey, KeyInfo::class.java)
        return info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX &&
            info.origin == KeyProperties.ORIGIN_GENERATED &&
            info.purposes and KeyProperties.PURPOSE_AGREE_KEY != 0 &&
            info.isUserAuthenticationRequired &&
            info.userAuthenticationValidityDurationSeconds == 0 &&
            info.userAuthenticationType == KeyProperties.AUTH_BIOMETRIC_STRONG &&
            info.isUserAuthenticationRequirementEnforcedBySecureHardware &&
            privateKey.format == null && privateKey.encoded == null
    }

    fun cleanup(): JSObject {
        val alias = trackedAlias()
        if (alias == null) {
            preferences.edit().remove(ALIAS_KEY).apply()
            return cleanupReport(false, false, true, null)
        }

        return try {
            val store = keyStore()
            val existed = store.containsAlias(alias)
            if (existed) store.deleteEntry(alias)
            val absent = !store.containsAlias(alias)
            if (absent) preferences.edit().remove(ALIAS_KEY).commit()
            cleanupReport(existed, existed && absent, absent, if (absent) null else "cleanup_failed")
        } catch (_: Exception) {
            cleanupReport(false, false, false, "cleanup_failed")
        }
    }

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    companion object {
        internal const val ALIAS_PREFIX = "age-plugin-phone-poc-"
        private const val ALIAS_KEY = "active_probe_alias"
        private const val PREFERENCES_NAME = "phone_identity_doctor"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val P256_NAME = "secp256r1"
        private val ALIAS_PATTERN = Regex(
            "^age-plugin-phone-poc-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )

        internal fun isValidProbeAlias(alias: String): Boolean = ALIAS_PATTERN.matches(alias)

        internal fun emptyProbeReport(error: String): JSObject = JSObject().apply {
            put("generated", false)
            put("securityLevel", "unknown")
            put("originGenerated", false)
            put("purposeAgreeKey", false)
            put("userAuthenticationRequired", false)
            put("authPerUse", false)
            put("authenticationType", "none")
            put("authEnforcedBySecureHardware", false)
            put("privateKeyFormatIsNull", false)
            put("privateKeyEncodedIsNull", false)
            put("errorCategory", error)
        }

        private fun cleanupReport(
            existed: Boolean,
            deleted: Boolean,
            absent: Boolean,
            error: String?,
        ): JSObject = JSObject().apply {
            put("probeKeyExisted", existed)
            put("probeKeyDeleted", deleted)
            put("probeKeyAbsentAfterDelete", absent)
            put("errorCategory", error)
        }
    }
}
