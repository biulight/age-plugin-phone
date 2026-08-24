package io.github.biulight.phone_identity

import com.fasterxml.jackson.databind.ObjectMapper
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
    private val vector = ObjectMapper().readTree(
        requireNotNull(javaClass.classLoader?.getResourceAsStream("offline-envelope-v1.json")),
    )

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

    private fun base64(value: String): ByteArray = Base64.getDecoder().decode(value)
    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
