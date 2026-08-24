package io.github.biulight.phone_identity

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.EllipticCurve
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object TaggedRecipientCrypto {
    const val STANZA_TAG = "phone-p256-v1"
    const val FILE_KEY_BYTES = 16
    private const val POINT_BYTES = 33
    private const val BODY_BYTES = 32
    private val KDF_INFO = "age-plugin-phone/recipient/p256/v1".toByteArray(Charsets.US_ASCII)
    private val ZERO_NONCE = ByteArray(12)
    private val base64Encoder = Base64.getEncoder().withoutPadding()
    private val base64Decoder = Base64.getDecoder()

    data class Stanza(
        val tag: String,
        val args: List<String>,
        val body: ByteArray,
    )

    class InvalidStanzaException : GeneralSecurityException()

    class AuthenticationException : GeneralSecurityException()

    fun wrapForTest(
        recipientPublic: PublicKey,
        ephemeralPrivate: PrivateKey,
        ephemeralPublic: PublicKey,
        fileKey: ByteArray,
    ): Stanza {
        require(fileKey.size == FILE_KEY_BYTES)
        val recipient = encodeCompressed(recipientPublic)
        val ephemeral = encodeCompressed(ephemeralPublic)
        val secret = agree(ephemeralPrivate, recipientPublic)
        return try {
            val body = seal(secret, ephemeral, recipient, fileKey)
            Stanza(STANZA_TAG, listOf(base64Encoder.encodeToString(ephemeral)), body)
        } finally {
            secret.fill(0)
        }
    }

    fun unwrap(
        identityPrivate: PrivateKey,
        identityPublic: PublicKey,
        stanza: Stanza,
    ): ByteArray {
        val parsed = parse(stanza)
        val secret = agree(identityPrivate, parsed.ephemeralPublic)
        return try {
            open(secret, parsed.ephemeralBytes, encodeCompressed(identityPublic), parsed.body)
        } finally {
            secret.fill(0)
        }
    }

    fun unwrapWithSharedSecret(
        identityPublic: PublicKey,
        stanza: Stanza,
        sharedSecret: ByteArray,
    ): ByteArray {
        val parsed = parse(stanza)
        return open(
            sharedSecret,
            parsed.ephemeralBytes,
            encodeCompressed(identityPublic),
            parsed.body,
        )
    }

    fun parse(stanza: Stanza): ParsedStanza {
        if (stanza.tag != STANZA_TAG) throw InvalidStanzaException()
        if (stanza.args.size != 1) throw InvalidStanzaException()
        if (stanza.body.size != BODY_BYTES) throw InvalidStanzaException()
        val encoded = stanza.args.single()
        val ephemeral = try {
            base64Decoder.decode(encoded)
        } catch (_: IllegalArgumentException) {
            throw InvalidStanzaException()
        }
        if (base64Encoder.encodeToString(ephemeral) != encoded) throw InvalidStanzaException()
        val publicKey = decodeCompressed(ephemeral)
        return ParsedStanza(publicKey, ephemeral, stanza.body.copyOf())
    }

    fun encodeCompressed(key: PublicKey): ByteArray {
        val ecKey = key as? ECPublicKey ?: throw InvalidStanzaException()
        val params = p256Parameters()
        if (ecKey.params.curve != params.curve || ecKey.params.order != params.order) {
            throw InvalidStanzaException()
        }
        val x = fixedWidth(ecKey.w.affineX, 32)
        return byteArrayOf(if (ecKey.w.affineY.testBit(0)) 3 else 2) + x
    }

    fun decodeCompressed(encoded: ByteArray): PublicKey {
        if (encoded.size != POINT_BYTES || (encoded[0].toInt() and 0xff) !in 2..3) {
            throw InvalidStanzaException()
        }
        val params = p256Parameters()
        val field = params.curve.field as java.security.spec.ECFieldFp
        val p = field.p
        val x = BigInteger(1, encoded.copyOfRange(1, encoded.size))
        if (x >= p) throw InvalidStanzaException()
        val curve: EllipticCurve = params.curve
        val rhs = x.modPow(BigInteger.valueOf(3), p)
            .add(curve.a.multiply(x))
            .add(curve.b)
            .mod(p)
        var y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p)
        if (y.modPow(BigInteger.TWO, p) != rhs) throw InvalidStanzaException()
        val odd = (encoded[0].toInt() and 1) == 1
        if (y.testBit(0) != odd) y = p.subtract(y)
        val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params))
        if (!MessageDigest.isEqual(encodeCompressed(key), encoded)) throw InvalidStanzaException()
        return key
    }

    data class ParsedStanza(
        val ephemeralPublic: PublicKey,
        val ephemeralBytes: ByteArray,
        val body: ByteArray,
    )

    private fun seal(
        sharedSecret: ByteArray,
        ephemeralPublic: ByteArray,
        recipientPublic: ByteArray,
        fileKey: ByteArray,
    ): ByteArray {
        val key = deriveKey(sharedSecret, ephemeralPublic, recipientPublic)
        return try {
            val cipher = cipher(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(associatedData(ephemeralPublic, recipientPublic))
            cipher.doFinal(fileKey)
        } finally {
            key.fill(0)
        }
    }

    private fun open(
        sharedSecret: ByteArray,
        ephemeralPublic: ByteArray,
        recipientPublic: ByteArray,
        body: ByteArray,
    ): ByteArray {
        val key = deriveKey(sharedSecret, ephemeralPublic, recipientPublic)
        return try {
            val cipher = cipher(Cipher.DECRYPT_MODE, key)
            cipher.updateAAD(associatedData(ephemeralPublic, recipientPublic))
            val plaintext = try {
                cipher.doFinal(body)
            } catch (_: GeneralSecurityException) {
                throw AuthenticationException()
            }
            if (plaintext.size != FILE_KEY_BYTES) {
                plaintext.fill(0)
                throw AuthenticationException()
            }
            plaintext
        } finally {
            key.fill(0)
        }
    }

    private fun deriveKey(
        sharedSecret: ByteArray,
        ephemeralPublic: ByteArray,
        recipientPublic: ByteArray,
    ): ByteArray {
        val salt = ephemeralPublic + recipientPublic
        val extract = Mac.getInstance("HmacSHA256")
        extract.init(SecretKeySpec(salt, "HmacSHA256"))
        val pseudorandomKey = extract.doFinal(sharedSecret)
        salt.fill(0)
        return try {
            val expand = Mac.getInstance("HmacSHA256")
            expand.init(SecretKeySpec(pseudorandomKey, "HmacSHA256"))
            expand.update(KDF_INFO)
            expand.doFinal(byteArrayOf(1))
        } finally {
            pseudorandomKey.fill(0)
        }
    }

    private fun associatedData(ephemeralPublic: ByteArray, recipientPublic: ByteArray): ByteArray =
        STANZA_TAG.toByteArray(Charsets.US_ASCII) + byteArrayOf(0) +
            ephemeralPublic + recipientPublic

    private fun cipher(mode: Int, key: ByteArray): Cipher =
        Cipher.getInstance("ChaCha20-Poly1305").apply {
            init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(ZERO_NONCE))
        }

    private fun agree(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(privateKey)
        agreement.doPhase(publicKey, true)
        val raw = agreement.generateSecret()
        if (raw.size > 32) {
            raw.fill(0)
            throw InvalidStanzaException()
        }
        if (raw.size == 32) return raw
        val padded = ByteArray(32)
        raw.copyInto(padded, 32 - raw.size)
        raw.fill(0)
        return padded
    }

    private fun p256Parameters() = AlgorithmParameters.getInstance("EC").run {
        init(ECGenParameterSpec("secp256r1"))
        getParameterSpec(java.security.spec.ECParameterSpec::class.java)
    }

    private fun fixedWidth(value: BigInteger, width: Int): ByteArray {
        val encoded = value.toByteArray()
        val unsigned = if (encoded.size > width && encoded[0] == 0.toByte()) {
            encoded.copyOfRange(1, encoded.size)
        } else {
            encoded
        }
        if (unsigned.size > width) throw InvalidStanzaException()
        return ByteArray(width).also { unsigned.copyInto(it, width - unsigned.size) }
    }
}
