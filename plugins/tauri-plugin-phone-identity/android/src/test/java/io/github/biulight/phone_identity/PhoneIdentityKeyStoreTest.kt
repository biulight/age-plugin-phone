package io.github.biulight.phone_identity

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PhoneIdentityKeyStoreTest {
    @Test
    fun aliasesAreRoleSeparatedAndCanonical() {
        val id = ByteArray(16) { it.toByte() }
        val identity = PhoneIdentityKeyStore.alias("age-plugin-phone-identity-v1-", id)
        val signing = PhoneIdentityKeyStore.alias("age-plugin-phone-signing-v1-", id)

        assertEquals("age-plugin-phone-identity-v1-000102030405060708090a0b0c0d0e0f", identity)
        assertEquals("age-plugin-phone-signing-v1-000102030405060708090a0b0c0d0e0f", signing)
        assertTrue(PhoneIdentityKeyStore.isValidAlias(identity, "age-plugin-phone-identity-v1-"))
        assertFalse(
            PhoneIdentityKeyStore.isValidAlias(
                identity.uppercase(),
                "age-plugin-phone-identity-v1-",
            ),
        )
        assertThrows(PhoneIdentityKeyStore.KeyStoreException::class.java) {
            PhoneIdentityKeyStore.alias("caller-controlled-", id)
        }
    }

    @Test
    fun preparingJournalRoundTripsWithoutPublicMaterial() {
        val encoded = PhoneIdentityKeyStore.encodePreparing(ByteArray(16) { 7 })

        assertNull(PhoneIdentityKeyStore.decodeForTest(encoded))
    }

    @Test
    fun committedMetadataRoundTripsCanonically() {
        val identity = keyPair()
        val signing = keyPair()
        val public = PhoneIdentityPublic(
            ByteArray(16) { it.toByte() },
            TaggedRecipientCrypto.encodeRecipient(identity.public),
            TaggedRecipientCrypto.encodeCompressed(identity.public),
            TaggedRecipientCrypto.encodeCompressed(signing.public),
        )

        val decoded = PhoneIdentityKeyStore.decodeForTest(
            PhoneIdentityKeyStore.encodeCommitted(public),
        )!!

        assertArrayEquals(public.identityId, decoded.identityId)
        assertEquals(public.recipient, decoded.recipient)
        assertArrayEquals(public.identityPublicKey, decoded.identityPublicKey)
        assertArrayEquals(public.signingPublicKey, decoded.signingPublicKey)
    }

    @Test
    fun deletionJournalDoesNotDecodeAsUsableIdentity() {
        val identity = keyPair()
        val signing = keyPair()
        val public = PhoneIdentityPublic(
            ByteArray(16) { it.toByte() },
            TaggedRecipientCrypto.encodeRecipient(identity.public),
            TaggedRecipientCrypto.encodeCompressed(identity.public),
            TaggedRecipientCrypto.encodeCompressed(signing.public),
        )

        assertNull(PhoneIdentityKeyStore.decodeForTest(PhoneIdentityKeyStore.encodeDeleting(public)))
        val encoded = PhoneIdentityKeyStore.encodeDeleting(public)
        val malformed = encoded.copyOf(encoded.size + 1)
        assertThrows(PhoneIdentityKeyStore.KeyStoreException::class.java) {
            PhoneIdentityKeyStore.decodeForTest(malformed)
        }
    }

    @Test
    fun rejectsMalformedAndRoleConfusedMetadata() {
        val identity = keyPair()
        val compressed = TaggedRecipientCrypto.encodeCompressed(identity.public)
        val confused = PhoneIdentityPublic(
            ByteArray(16),
            TaggedRecipientCrypto.encodeRecipient(identity.public),
            compressed,
            compressed.copyOf(),
        )
        assertThrows(PhoneIdentityKeyStore.KeyStoreException::class.java) {
            PhoneIdentityKeyStore.encodeCommitted(confused)
        }

        val preparing = PhoneIdentityKeyStore.encodePreparing(ByteArray(16))
        preparing[0] = (preparing[0].toInt() xor 1).toByte()
        assertThrows(PhoneIdentityKeyStore.KeyStoreException::class.java) {
            PhoneIdentityKeyStore.decodeForTest(preparing)
        }
    }

    @Test
    fun rejectsRecipientThatDoesNotBindIdentityPublicKey() {
        val identity = keyPair()
        val other = keyPair()
        val signing = keyPair()
        val mismatched = PhoneIdentityPublic(
            ByteArray(16),
            TaggedRecipientCrypto.encodeRecipient(other.public),
            TaggedRecipientCrypto.encodeCompressed(identity.public),
            TaggedRecipientCrypto.encodeCompressed(signing.public),
        )

        assertThrows(PhoneIdentityKeyStore.KeyStoreException::class.java) {
            PhoneIdentityKeyStore.encodeCommitted(mismatched)
        }
    }

    private fun keyPair() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
}
