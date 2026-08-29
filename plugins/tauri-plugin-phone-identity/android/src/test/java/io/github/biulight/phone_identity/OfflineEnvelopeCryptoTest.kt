package io.github.biulight.phone_identity

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class OfflineEnvelopeCryptoTest {
    private val cbor = ObjectMapper(CBORFactory())
    private val vector = ObjectMapper().readTree(
        requireNotNull(javaClass.classLoader?.getResourceAsStream("offline-envelope-v2.json")),
    )
    private val pairingVector = ObjectMapper().readTree(
        requireNotNull(javaClass.classLoader?.getResourceAsStream("pairing-transcript-v2.json")),
    )

    @Test
    fun createsAndVerifiesSyntheticPairingTranscript() {
        val generator = java.security.KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        }
        val identity = generator.generateKeyPair()
        val desktopSigning = generator.generateKeyPair()
        val desktopSelection = generator.generateKeyPair()
        val phoneSigning = generator.generateKeyPair()
        val transcript = OfflineEnvelopeCrypto.createSyntheticPairingTranscript(
            identity.public,
            desktopSigning,
            desktopSelection.public,
            phoneSigning,
            java.security.SecureRandom(),
        )

        val offer = OfflineEnvelopeCrypto.verifyPairingOffer(transcript.signedOffer)
        val response = OfflineEnvelopeCrypto.verifyPairingResponse(transcript.signedResponse, offer)
        org.junit.Assert.assertEquals("Pairing confirmation Doctor", offer.offer.desktopLabel)
        org.junit.Assert.assertEquals(
            TaggedRecipientCrypto.encodeRecipient(identity.public),
            response.response.recipient,
        )
        assertArrayEquals(
            TaggedRecipientCrypto.encodeCompressed(desktopSigning.public),
            TaggedRecipientCrypto.encodeCompressed(offer.offer.desktopSigningPublicKey),
        )
        assertArrayEquals(
            TaggedRecipientCrypto.encodeCompressed(desktopSelection.public),
            TaggedRecipientCrypto.encodeCompressed(offer.offer.desktopSelectionPublicKey),
        )
        assertArrayEquals(
            TaggedRecipientCrypto.encodeCompressed(phoneSigning.public),
            TaggedRecipientCrypto.encodeCompressed(response.response.phoneSigningPublicKey),
        )
        org.junit.Assert.assertEquals(32, OfflineEnvelopeCrypto.pairingFingerprint(offer, response).size)
    }

    @Test
    fun createsResponseBoundToPersistentPublicMetadataAndOffer() {
        val generator = java.security.KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        }
        val identityKey = generator.generateKeyPair()
        val desktopSigning = generator.generateKeyPair()
        val desktopSelection = generator.generateKeyPair()
        val phoneSigning = generator.generateKeyPair()
        val first = OfflineEnvelopeCrypto.createSyntheticPairingTranscript(
            identityKey.public,
            desktopSigning,
            desktopSelection.public,
            phoneSigning,
            java.security.SecureRandom(),
        )
        val offer = OfflineEnvelopeCrypto.verifyPairingOffer(first.signedOffer)
        val metadata = PhoneIdentityPublic(
            ByteArray(16) { (it + 1).toByte() },
            TaggedRecipientCrypto.encodeRecipient(identityKey.public),
            TaggedRecipientCrypto.encodeCompressed(identityKey.public),
            TaggedRecipientCrypto.encodeCompressed(phoneSigning.public),
        )

        val response = OfflineEnvelopeCrypto.createPairingResponse(
            offer,
            metadata,
            phoneSigning.private,
            java.security.SecureRandom(),
        )
        val verified = OfflineEnvelopeCrypto.verifyPairingResponse(response.encoded, offer)

        assertArrayEquals(metadata.identityId, verified.response.identityId)
        assertArrayEquals(offer.digest, verified.response.offerDigest)
        assertArrayEquals(
            metadata.signingPublicKey,
            TaggedRecipientCrypto.encodeCompressed(verified.response.phoneSigningPublicKey),
        )
        org.junit.Assert.assertEquals(metadata.recipient, verified.response.recipient)

        val wrongOffer = OfflineEnvelopeCrypto.verifyPairingOffer(
            OfflineEnvelopeCrypto.createSyntheticPairingTranscript(
                identityKey.public,
                desktopSigning,
                desktopSelection.public,
                phoneSigning,
                java.security.SecureRandom(),
            ).signedOffer,
        )
        assertThrows(OfflineEnvelopeCrypto.ProtocolException::class.java) {
            OfflineEnvelopeCrypto.verifyPairingResponse(response.encoded, wrongOffer)
        }
    }

    @Test
    fun verifiesSharedRustPairingTranscriptVector() {
        val offer = OfflineEnvelopeCrypto.verifyPairingOffer(
            base64(pairingVector["signed_offer_base64"].asText()),
        )
        val response = OfflineEnvelopeCrypto.verifyPairingResponse(
            base64(pairingVector["signed_response_base64"].asText()),
            offer,
        )
        assertArrayEquals(hex(pairingVector["desktop_id_hex"].asText()), offer.offer.desktopId)
        assertArrayEquals(
            base64(pairingVector["desktop_signing_public_key_base64"].asText()),
            TaggedRecipientCrypto.encodeCompressed(offer.offer.desktopSigningPublicKey),
        )
        assertArrayEquals(
            base64(pairingVector["desktop_selection_public_key_base64"].asText()),
            TaggedRecipientCrypto.encodeCompressed(offer.offer.desktopSelectionPublicKey),
        )
        assertArrayEquals(base64(pairingVector["offer_digest_base64"].asText()), offer.digest)
        assertArrayEquals(hex(pairingVector["identity_id_hex"].asText()), response.response.identityId)
        assertArrayEquals(
            base64(pairingVector["phone_signing_public_key_base64"].asText()),
            TaggedRecipientCrypto.encodeCompressed(response.response.phoneSigningPublicKey),
        )
        assertArrayEquals(
            base64(pairingVector["fingerprint_base64"].asText()),
            OfflineEnvelopeCrypto.pairingFingerprint(offer, response),
        )
        org.junit.Assert.assertEquals(pairingVector["desktop_label"].asText(), offer.offer.desktopLabel)
        org.junit.Assert.assertEquals(pairingVector["recipient"].asText(), response.response.recipient)

        val record = StoredPairingRecord.fromVerifiedTranscript(offer, response)
        assertArrayEquals(offer.offer.desktopId, record.desktopId)
        assertArrayEquals(response.response.identityId, record.identityId)
        assertArrayEquals(offer.digest, record.offerDigest)
        assertArrayEquals(
            OfflineEnvelopeCrypto.pairingFingerprint(offer, response),
            record.transcriptFingerprint,
        )
        assertArrayEquals(
            TaggedRecipientCrypto.encodeCompressed(offer.offer.desktopSigningPublicKey),
            record.desktopSigningPublicKey,
        )
        assertArrayEquals(
            TaggedRecipientCrypto.encodeCompressed(offer.offer.desktopSelectionPublicKey),
            record.desktopSelectionPublicKey,
        )
        assertArrayEquals(
            TaggedRecipientCrypto.encodeCompressed(response.response.phoneSigningPublicKey),
            record.phoneSigningPublicKey,
        )
        org.junit.Assert.assertEquals(offer.offer.desktopLabel, record.desktopLabel)
        org.junit.Assert.assertEquals(response.response.recipient, record.recipient)
    }

    @Test
    fun rejectsMalformedTamperedAndWrongOfferPairingMessages() {
        val offerBytes = base64(pairingVector["signed_offer_base64"].asText())
        val responseBytes = base64(pairingVector["signed_response_base64"].asText())
        val offer = OfflineEnvelopeCrypto.verifyPairingOffer(offerBytes)

        assertProtocolFailure(offerBytes + byteArrayOf(0), true)
        assertProtocolFailure(offerBytes.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }, true)
        assertProtocolFailure(makeHighS(offerBytes), true)

        val unknownVersion = offerBytes.copyOf()
        val header = byteArrayOf(0x88.toByte(), 0x02, 0x01, 0x01)
        val headerOffset = indexOf(unknownVersion, header)
        org.junit.Assert.assertTrue(headerOffset >= 0)
        unknownVersion[headerOffset + 1] = 1
        assertProtocolFailure(unknownVersion, true)

        assertThrows(OfflineEnvelopeCrypto.ProtocolException::class.java) {
            OfflineEnvelopeCrypto.verifyPairingResponse(
                responseBytes,
                offer.copy(digest = offer.digest.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }),
            )
        }
        assertProtocolFailure(responseBytes.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }, false, offer)
        assertProtocolFailure(makeHighS(responseBytes), false, offer)

        val invalidRecipient = responseBytes.copyOf()
        val recipientOffset = indexOf(invalidRecipient, pairingVector["recipient"].asText().toByteArray())
        org.junit.Assert.assertTrue(recipientOffset >= 0)
        invalidRecipient[recipientOffset] = 'b'.code.toByte()
        assertProtocolFailure(invalidRecipient, false, offer)
    }

    @Test
    fun rejectsPairingTranscriptWithReusedLongTermKeyRoles() {
        val generator = java.security.KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        }
        val identity = generator.generateKeyPair()
        val desktopSigning = generator.generateKeyPair()
        val desktopSelection = generator.generateKeyPair()
        val phoneSigning = generator.generateKeyPair()

        val reusedRoles = listOf(
            arrayOf(phoneSigning, desktopSigning, desktopSelection, phoneSigning),
            arrayOf(desktopSigning, desktopSigning, desktopSelection, phoneSigning),
            arrayOf(desktopSelection, desktopSigning, desktopSelection, phoneSigning),
            arrayOf(identity, desktopSigning, desktopSelection, desktopSigning),
            arrayOf(identity, desktopSigning, desktopSelection, desktopSelection),
        )
        for (roles in reusedRoles) {
            val transcript = OfflineEnvelopeCrypto.createSyntheticPairingTranscript(
                roles[0].public,
                roles[1],
                roles[2].public,
                roles[3],
                java.security.SecureRandom(),
            )
            val offer = OfflineEnvelopeCrypto.verifyPairingOffer(transcript.signedOffer)
            assertThrows(OfflineEnvelopeCrypto.ProtocolException::class.java) {
                OfflineEnvelopeCrypto.verifyPairingResponse(transcript.signedResponse, offer)
            }
        }
    }

    @Test
    fun verifiesAndDecryptsSharedRustVector() {
        val desktopSigning = keyPair(vector["desktop_signing_scalar"].asInt())
        val phoneSigning = keyPair(vector["phone_signing_scalar"].asInt())
        val desktopSession = keyPair(vector["desktop_session_scalar"].asInt())
        val requestBytes = base64(vector["signed_request_base64"].asText())
        val verified = OfflineEnvelopeCrypto.verifyRequest(
            requestBytes,
            hex(vector["desktop_id_hex"].asText()),
            hex(vector["identity_id_hex"].asText()),
            desktopSigning.public,
            vector["now_unix"].asLong(),
        )
        assertArrayEquals(base64(vector["request_digest_base64"].asText()), verified.digest)
        assertArrayEquals(
            hex(vector["file_key_hex"].asText()),
            OfflineEnvelopeCrypto.openResponse(
                base64(vector["signed_response_base64"].asText()),
                verified,
                phoneSigning.public,
                desktopSession.private,
            ),
        )
    }

    @Test
    fun extractsOnlyUntrustedScopeAndSignsResponseWithSeparateKeyHandles() {
        val desktopSigning = keyPair(vector["desktop_signing_scalar"].asInt())
        val phoneSigning = keyPair(vector["phone_signing_scalar"].asInt())
        val desktopSession = keyPair(vector["desktop_session_scalar"].asInt())
        val requestBytes = base64(vector["signed_request_base64"].asText())
        val scope = OfflineEnvelopeCrypto.requestScope(requestBytes)
        assertArrayEquals(hex(vector["desktop_id_hex"].asText()), scope.desktopId)
        assertArrayEquals(hex(vector["identity_id_hex"].asText()), scope.identityId)
        val verified = OfflineEnvelopeCrypto.verifyRequest(
            requestBytes,
            scope.desktopId,
            scope.identityId,
            desktopSigning.public,
            vector["now_unix"].asLong(),
        )
        val fileKey = hex(vector["file_key_hex"].asText())
        val response = OfflineEnvelopeCrypto.sealResponse(
            verified,
            fileKey,
            phoneSigning.private,
            phoneSigning.public,
            java.security.SecureRandom(),
        )
        assertArrayEquals(
            fileKey,
            OfflineEnvelopeCrypto.openResponse(
                response.encoded,
                verified,
                phoneSigning.public,
                desktopSession.private,
            ),
        )
        assertThrows(OfflineEnvelopeCrypto.ProtocolException::class.java) {
            OfflineEnvelopeCrypto.requestScope(requestBytes + byteArrayOf(0))
        }
    }

    @Test
    fun rejectsTamperingWrongDeviceAndExpiry() {
        val desktopSigning = keyPair(vector["desktop_signing_scalar"].asInt())
        val request = base64(vector["signed_request_base64"].asText())
        assertThrows(OfflineEnvelopeCrypto.ProtocolException::class.java) {
            OfflineEnvelopeCrypto.verifyRequest(
                request,
                ByteArray(16),
                hex(vector["identity_id_hex"].asText()),
                desktopSigning.public,
                vector["now_unix"].asLong(),
            )
        }
        assertThrows(OfflineEnvelopeCrypto.ProtocolException::class.java) {
            OfflineEnvelopeCrypto.verifyRequest(
                request,
                hex(vector["desktop_id_hex"].asText()),
                hex(vector["identity_id_hex"].asText()),
                desktopSigning.public,
                vector["expires_at_unix"].asLong() + 1,
            )
        }
        val modified = request.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertThrows(OfflineEnvelopeCrypto.ProtocolException::class.java) {
            OfflineEnvelopeCrypto.verifyRequest(
                modified,
                hex(vector["desktop_id_hex"].asText()),
                hex(vector["identity_id_hex"].asText()),
                desktopSigning.public,
                vector["now_unix"].asLong(),
            )
        }
    }

    @Test
    fun rejectsTextualProtocolHeaderFieldsBeforeRouting() {
        val request = base64(vector["signed_request_base64"].asText())

        for (headerIndex in 0..2) {
            assertThrows(OfflineEnvelopeCrypto.ProtocolException::class.java) {
                OfflineEnvelopeCrypto.requestScope(
                    requestWithTextHeader(request, headerIndex),
                )
            }
        }
    }

    private fun requestWithTextHeader(encoded: ByteArray, headerIndex: Int): ByteArray {
        val signed = cbor.readTree(encoded) as ArrayNode
        val payload = cbor.readTree(signed[0].binaryValue()) as ArrayNode
        payload.set(headerIndex, payload[headerIndex].intValue().toString())
        signed.set(0, cbor.writeValueAsBytes(payload))
        return cbor.writeValueAsBytes(signed)
    }

    private fun keyPair(scalar: Int): KeyPair {
        val parameters = AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        }
        val value = BigInteger.valueOf(scalar.toLong())
        val point = multiply(parameters.generator, value, parameters.curve)
        return KeyFactory.getInstance("EC").run {
            KeyPair(
                generatePublic(ECPublicKeySpec(point, parameters)),
                generatePrivate(ECPrivateKeySpec(value, parameters)),
            )
        }
    }

    private fun multiply(point: ECPoint, scalar: BigInteger, curve: java.security.spec.EllipticCurve): ECPoint {
        val p = (curve.field as java.security.spec.ECFieldFp).p
        var result: ECPoint? = null
        var addend = point
        for (bit in 0 until scalar.bitLength()) {
            if (scalar.testBit(bit)) result = if (result == null) addend else add(result, addend, p, curve.a)
            addend = add(addend, addend, p, curve.a)
        }
        return requireNotNull(result)
    }

    private fun add(left: ECPoint, right: ECPoint, p: BigInteger, a: BigInteger): ECPoint {
        val slope = if (left == right) {
            left.affineX.pow(2).multiply(BigInteger.valueOf(3)).add(a)
                .multiply(left.affineY.multiply(BigInteger.TWO).modInverse(p))
        } else {
            right.affineY.subtract(left.affineY)
                .multiply(right.affineX.subtract(left.affineX).mod(p).modInverse(p))
        }.mod(p)
        val x = slope.pow(2).subtract(left.affineX).subtract(right.affineX).mod(p)
        return ECPoint(x, slope.multiply(left.affineX.subtract(x)).subtract(left.affineY).mod(p))
    }

    private fun assertProtocolFailure(
        encoded: ByteArray,
        offerMessage: Boolean,
        offer: OfflineEnvelopeCrypto.VerifiedPairingOffer? = null,
    ) {
        assertThrows(OfflineEnvelopeCrypto.ProtocolException::class.java) {
            if (offerMessage) {
                OfflineEnvelopeCrypto.verifyPairingOffer(encoded)
            } else {
                OfflineEnvelopeCrypto.verifyPairingResponse(encoded, requireNotNull(offer))
            }
        }
    }

    private fun makeHighS(encoded: ByteArray): ByteArray {
        val order = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
        return encoded.copyOf().also { result ->
            var borrow = 0
            for (index in 31 downTo 0) {
                val minuend = order[index].toInt() and 0xff
                val subtrahend = (result[result.size - 32 + index].toInt() and 0xff) + borrow
                if (minuend >= subtrahend) {
                    result[result.size - 32 + index] = (minuend - subtrahend).toByte()
                    borrow = 0
                } else {
                    result[result.size - 32 + index] = (minuend + 256 - subtrahend).toByte()
                    borrow = 1
                }
            }
            org.junit.Assert.assertEquals(0, borrow)
        }
    }

    private fun indexOf(value: ByteArray, needle: ByteArray): Int {
        for (offset in 0..value.size - needle.size) {
            if (needle.indices.all { value[offset + it] == needle[it] }) return offset
        }
        return -1
    }

    private fun base64(value: String): ByteArray = Base64.getDecoder().decode(value)
    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
