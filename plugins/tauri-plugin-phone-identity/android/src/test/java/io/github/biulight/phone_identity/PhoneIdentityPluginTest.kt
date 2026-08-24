package io.github.biulight.phone_identity

import android.hardware.biometrics.BiometricPrompt
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class PhoneIdentityPluginTest {
    @Test
    fun cancellationAndTimeoutRemainDistinctFailures() {
        assertEquals(
            "user_cancelled",
            PhoneIdentityPlugin.authenticationErrorCategory(
                BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED,
            ),
        )
        assertEquals(
            "user_cancelled",
            PhoneIdentityPlugin.authenticationErrorCategory(
                BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
            ),
        )
        assertEquals(
            "authentication_timeout",
            PhoneIdentityPlugin.authenticationErrorCategory(BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT),
        )
        assertEquals(
            "authentication_failed",
            PhoneIdentityPlugin.authenticationErrorCategory(BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT),
        )
    }

    @Test
    fun rejectsWrongCurveAndNonEcPeerKeys() {
        val p384 = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp384r1"))
        }.generateKeyPair()
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

        assertFalse(PhoneIdentityPlugin.isP256PublicKey(p384.public))
        assertFalse(PhoneIdentityPlugin.isP256PublicKey(rsa.public))
    }
}
