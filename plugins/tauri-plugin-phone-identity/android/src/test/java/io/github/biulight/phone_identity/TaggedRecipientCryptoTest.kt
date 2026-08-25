package io.github.biulight.phone_identity

import com.fasterxml.jackson.databind.ObjectMapper
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TaggedRecipientCryptoTest {
    private val vector = ObjectMapper().readTree(
        requireNotNull(javaClass.classLoader?.getResourceAsStream("p256-recipient-v1.json")),
    )
    private val vectorV2 = ObjectMapper().readTree(
        requireNotNull(javaClass.classLoader?.getResourceAsStream("p256-recipient-v2.json")),
    )

    @Test
    fun matchesSharedRustVector() {
        val identity = keyPair(vector["identity_scalar_hex"].asText())
        val ephemeral = keyPair(vector["ephemeral_scalar_hex"].asText())
        val fileKey = hex(vector["file_key_hex"].asText())
        val stanzaNode = vector["stanza"]

        assertEquals(
            vector["recipient_public_key_base64"].asText(),
            Base64.getEncoder().withoutPadding()
                .encodeToString(TaggedRecipientCrypto.encodeCompressed(identity.public)),
        )
        assertEquals(vector["recipient"].asText(), TaggedRecipientCrypto.encodeRecipient(identity.public))
        assertArrayEquals(
            TaggedRecipientCrypto.encodeCompressed(identity.public),
            TaggedRecipientCrypto.encodeCompressed(
                TaggedRecipientCrypto.decodeRecipient(vector["recipient"].asText()),
            ),
        )
        val stanza = TaggedRecipientCrypto.wrapForTest(
            identity.public,
            ephemeral.private,
            ephemeral.public,
            fileKey,
        )
        assertEquals(stanzaNode["tag"].asText(), stanza.tag)
        assertEquals(stanzaNode["args"][0].asText(), stanza.args.single())
        assertEquals(
            stanzaNode["body_base64"].asText(),
            Base64.getEncoder().withoutPadding().encodeToString(stanza.body),
        )
        assertArrayEquals(fileKey, TaggedRecipientCrypto.unwrap(identity.private, identity.public, stanza))
    }

    @Test
    fun matchesPrivateSelectionRustVector() {
        val identity = keyPair(vectorV2["identity_scalar_hex"].asText())
        val desktop = keyPair(vectorV2["desktop_scalar_hex"].asText())
        val ephemeral = keyPair(vectorV2["ephemeral_scalar_hex"].asText())
        val fileKey = hex(vectorV2["file_key_hex"].asText())
        val stanzaNode = vectorV2["stanza"]
        val stanza = TaggedRecipientCrypto.wrapV2ForTest(
            identity.public,
            desktop.public,
            ephemeral.private,
            ephemeral.public,
            hex(vectorV2["identity_id_hex"].asText()),
            fileKey,
        )
        assertEquals(stanzaNode["tag"].asText(), stanza.tag)
        assertEquals(stanzaNode["args"][0].asText(), stanza.args[0])
        assertEquals(stanzaNode["args"][1].asText(), stanza.args[1])
        assertEquals(
            stanzaNode["body_base64"].asText(),
            Base64.getEncoder().withoutPadding().encodeToString(stanza.body),
        )
        assertArrayEquals(
            fileKey,
            TaggedRecipientCrypto.unwrap(identity.private, identity.public, stanza),
        )
        val verifiedRequest = OfflineEnvelopeCrypto.createSignedRequest(
            stanza,
            desktop,
            keyPair("0000000000000000000000000000000000000000000000000000000000000005").public,
            1_000_000,
            SecureRandom(),
        )
        assertEquals(2, verifiedRequest.request.stanza.args.size)
        assertEquals(stanza.args, verifiedRequest.request.stanza.args)
        assertThrows(TaggedRecipientCrypto.InvalidStanzaException::class.java) {
            TaggedRecipientCrypto.parse(
                stanza.copy(args = listOf(stanza.args[0], stanza.args[1] + "=")),
            )
        }
        assertThrows(TaggedRecipientCrypto.InvalidStanzaException::class.java) {
            TaggedRecipientCrypto.parse(stanza.copy(args = listOf(stanza.args[0])))
        }
        val modified = stanza.body.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertThrows(TaggedRecipientCrypto.AuthenticationException::class.java) {
            TaggedRecipientCrypto.unwrap(
                identity.private,
                identity.public,
                stanza.copy(body = modified),
            )
        }
    }

    @Test
    fun rejectsMalformedStructureAndTampering() {
        val identity = keyPair(vector["identity_scalar_hex"].asText())
        val ephemeral = keyPair(vector["ephemeral_scalar_hex"].asText())
        val stanza = TaggedRecipientCrypto.wrapForTest(
            identity.public,
            ephemeral.private,
            ephemeral.public,
            hex(vector["file_key_hex"].asText()),
        )

        assertThrows(TaggedRecipientCrypto.InvalidStanzaException::class.java) {
            TaggedRecipientCrypto.parse(stanza.copy(tag = "phone-p256-v2"))
        }
        assertThrows(TaggedRecipientCrypto.InvalidStanzaException::class.java) {
            TaggedRecipientCrypto.parse(stanza.copy(args = stanza.args + "extra"))
        }
        assertThrows(TaggedRecipientCrypto.InvalidStanzaException::class.java) {
            TaggedRecipientCrypto.parse(stanza.copy(args = listOf(stanza.args.single() + "=")))
        }
        assertThrows(TaggedRecipientCrypto.InvalidStanzaException::class.java) {
            TaggedRecipientCrypto.parse(
                stanza.copy(
                    args = listOf(
                        Base64.getEncoder().withoutPadding().encodeToString(ByteArray(33)),
                    ),
                ),
            )
        }
        assertThrows(TaggedRecipientCrypto.InvalidStanzaException::class.java) {
            TaggedRecipientCrypto.parse(stanza.copy(body = stanza.body.copyOf(31)))
        }
        assertThrows(TaggedRecipientCrypto.InvalidStanzaException::class.java) {
            TaggedRecipientCrypto.decodeRecipient(vector["recipient"].asText().uppercase())
        }
        assertThrows(TaggedRecipientCrypto.InvalidStanzaException::class.java) {
            val recipient = vector["recipient"].asText()
            TaggedRecipientCrypto.decodeRecipient(recipient.dropLast(1) + if (recipient.last() == 'q') "p" else "q")
        }
        val modified = stanza.body.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertThrows(TaggedRecipientCrypto.AuthenticationException::class.java) {
            TaggedRecipientCrypto.unwrap(identity.private, identity.public, stanza.copy(body = modified))
        }
        val wrongIdentity = keyPair(
            "0000000000000000000000000000000000000000000000000000000000000003",
        )
        assertThrows(TaggedRecipientCrypto.AuthenticationException::class.java) {
            TaggedRecipientCrypto.unwrap(wrongIdentity.private, wrongIdentity.public, stanza)
        }
    }

    private fun keyPair(scalarHex: String): KeyPair {
        val parameters = AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        }
        val scalar = BigInteger(1, hex(scalarHex))
        val point = multiply(parameters.generator, scalar, parameters.curve)
        val factory = KeyFactory.getInstance("EC")
        return KeyPair(
            factory.generatePublic(ECPublicKeySpec(point, parameters)),
            factory.generatePrivate(ECPrivateKeySpec(scalar, parameters)),
        )
    }

    private fun multiply(
        point: ECPoint,
        scalar: BigInteger,
        curve: java.security.spec.EllipticCurve,
    ): ECPoint {
        val p = (curve.field as java.security.spec.ECFieldFp).p
        var result: ECPoint? = null
        var addend = point
        for (bit in 0 until scalar.bitLength()) {
            if (scalar.testBit(bit)) result = if (result == null) addend else add(result, addend, p, curve.a)
            addend = add(addend, addend, p, curve.a)
        }
        return requireNotNull(result)
    }

    private fun add(
        left: ECPoint,
        right: ECPoint,
        p: BigInteger,
        a: BigInteger,
    ): ECPoint {
        val slope = if (left == right) {
            left.affineX.pow(2).multiply(BigInteger.valueOf(3)).add(a)
                .multiply(left.affineY.multiply(BigInteger.TWO).modInverse(p))
        } else {
            right.affineY.subtract(left.affineY)
                .multiply(right.affineX.subtract(left.affineX).mod(p).modInverse(p))
        }.mod(p)
        val x = slope.pow(2).subtract(left.affineX).subtract(right.affineX).mod(p)
        val y = slope.multiply(left.affineX.subtract(x)).subtract(left.affineY).mod(p)
        return ECPoint(x, y)
    }

    private fun hex(value: String): ByteArray =
        value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
