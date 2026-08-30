package io.github.biulight.phone_identity

import android.hardware.biometrics.BiometricPrompt
import app.tauri.annotation.InvokeArg
import com.fasterxml.jackson.databind.ObjectMapper
import java.lang.reflect.Modifier
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PhoneIdentityPluginTest {
    @Test
    fun revokePairingArgumentsRemainDeserializableInMinifiedBuilds() {
        val argumentClass = RevokePairingArgs::class.java
        assertTrue(Modifier.isPublic(argumentClass.modifiers))
        assertTrue(argumentClass.isAnnotationPresent(InvokeArg::class.java))

        val arguments = ObjectMapper().readValue(
            """{"handle":"synthetic-handle"}""",
            argumentClass,
        )
        assertEquals("synthetic-handle", arguments.handle)
    }

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
    fun unrecognizedBiometricKeepsTheCurrentPromptPending() {
        assertEquals(
            AuthenticationFailureDisposition.KEEP_PENDING,
            PhoneIdentityPlugin.authenticationFailureDisposition(),
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
