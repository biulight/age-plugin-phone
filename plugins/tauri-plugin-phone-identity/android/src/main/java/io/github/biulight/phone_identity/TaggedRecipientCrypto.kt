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
    const val STANZA_TAG_V2 = "phone-p256-v2"
    const val FILE_KEY_BYTES = 16
    private const val POINT_BYTES = 33
    private const val BODY_BYTES = 32
    private const val RECIPIENT_VERSION = 1
    private const val RECIPIENT_PAYLOAD_BYTES = 34
    private const val RECIPIENT_HRP = "age1phone"
    private const val BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private val KDF_INFO = "age-plugin-phone/recipient/p256/v1".toByteArray(Charsets.US_ASCII)
    private val FILE_KEY_KDF_INFO_V2 =
        "age-plugin-phone/recipient/p256/v2/file-key".toByteArray(Charsets.US_ASCII)
    private val SELECTION_KDF_INFO_V2 =
        "age-plugin-phone/recipient/p256/v2/selection".toByteArray(Charsets.US_ASCII)
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

    fun wrapV2ForTest(
        phoneIdentityPublic: PublicKey,
        desktopSelectionPublic: PublicKey,
        ephemeralPrivate: PrivateKey,
        ephemeralPublic: PublicKey,
        identityId: ByteArray,
        fileKey: ByteArray,
    ): Stanza {
        require(identityId.size == FILE_KEY_BYTES)
        require(fileKey.size == FILE_KEY_BYTES)
        val phone = encodeCompressed(phoneIdentityPublic)
        val desktop = encodeCompressed(desktopSelectionPublic)
        val ephemeral = encodeCompressed(ephemeralPublic)
        val phoneSecret = agree(ephemeralPrivate, phoneIdentityPublic)
        val desktopSecret = agree(ephemeralPrivate, desktopSelectionPublic)
        return try {
            val body = sealFile(2, phoneSecret, ephemeral, phone, fileKey)
            val selectionKey = deriveKey(
                desktopSecret,
                ephemeral,
                desktop,
                SELECTION_KDF_INFO_V2,
            )
            val selection = try {
                val cipher = cipher(Cipher.ENCRYPT_MODE, selectionKey)
                cipher.updateAAD(selectionAssociatedData(ephemeral, phone, desktop, body))
                cipher.doFinal(identityId)
            } finally {
                selectionKey.fill(0)
            }
            val encodedSelection = base64Encoder.encodeToString(selection)
            selection.fill(0)
            Stanza(
                STANZA_TAG_V2,
                listOf(
                    base64Encoder.encodeToString(ephemeral),
                    encodedSelection,
                ),
                body,
            )
        } finally {
            phoneSecret.fill(0)
            desktopSecret.fill(0)
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
            open(
                parsed.version,
                secret,
                parsed.ephemeralBytes,
                encodeCompressed(identityPublic),
                parsed.body,
            )
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
            parsed.version,
            sharedSecret,
            parsed.ephemeralBytes,
            encodeCompressed(identityPublic),
            parsed.body,
        )
    }

    fun parse(stanza: Stanza): ParsedStanza {
        val version = when {
            stanza.tag == STANZA_TAG && stanza.args.size == 1 -> 1
            stanza.tag == STANZA_TAG_V2 && stanza.args.size == 2 -> 2
            stanza.tag == STANZA_TAG || stanza.tag == STANZA_TAG_V2 ->
                throw InvalidStanzaException()
            else -> throw InvalidStanzaException()
        }
        if (stanza.body.size != BODY_BYTES) throw InvalidStanzaException()
        val encoded = stanza.args[0]
        val ephemeral = try {
            base64Decoder.decode(encoded)
        } catch (_: IllegalArgumentException) {
            throw InvalidStanzaException()
        }
        if (base64Encoder.encodeToString(ephemeral) != encoded) throw InvalidStanzaException()
        if (version == 2) {
            val selection = try {
                base64Decoder.decode(stanza.args[1])
            } catch (_: IllegalArgumentException) {
                throw InvalidStanzaException()
            }
            if (selection.size != BODY_BYTES ||
                base64Encoder.encodeToString(selection) != stanza.args[1]
            ) {
                selection.fill(0)
                throw InvalidStanzaException()
            }
            selection.fill(0)
        }
        val publicKey = decodeCompressed(ephemeral)
        return ParsedStanza(version, publicKey, ephemeral, stanza.body.copyOf())
    }

    fun encodeRecipient(publicKey: PublicKey): String {
        val payload = byteArrayOf(RECIPIENT_VERSION.toByte()) + encodeCompressed(publicKey)
        val data = convertBits(payload.map { it.toInt() and 0xff }, 8, 5, true)
        val checksumValue = bech32Polymod(bech32HrpExpand(RECIPIENT_HRP) + data + List(6) { 0 }) xor 1
        val checksum = (0 until 6).map { index ->
            (checksumValue ushr (5 * (5 - index))) and 31
        }
        return RECIPIENT_HRP + "1" + (data + checksum).joinToString("") { value ->
            BECH32_CHARSET[value].toString()
        }
    }

    fun decodeRecipient(value: String): PublicKey {
        if (value != value.lowercase() || value.length !in 8..90) throw InvalidStanzaException()
        val separator = value.lastIndexOf('1')
        if (separator <= 0 || value.substring(0, separator) != RECIPIENT_HRP) {
            throw InvalidStanzaException()
        }
        val data = value.substring(separator + 1).map { character ->
            BECH32_CHARSET.indexOf(character).also { if (it < 0) throw InvalidStanzaException() }
        }
        if (data.size < 6 || bech32Polymod(bech32HrpExpand(RECIPIENT_HRP) + data) != 1) {
            throw InvalidStanzaException()
        }
        val payload = convertBits(data.dropLast(6), 5, 8, false)
            .map(Int::toByte)
            .toByteArray()
        if (payload.size != RECIPIENT_PAYLOAD_BYTES || payload[0] != RECIPIENT_VERSION.toByte()) {
            throw InvalidStanzaException()
        }
        val publicKey = decodeCompressed(payload.copyOfRange(1, payload.size))
        if (encodeRecipient(publicKey) != value) throw InvalidStanzaException()
        return publicKey
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
        val version: Int,
        val ephemeralPublic: PublicKey,
        val ephemeralBytes: ByteArray,
        val body: ByteArray,
    )

    private fun bech32HrpExpand(value: String): List<Int> =
        value.map { it.code ushr 5 } + listOf(0) + value.map { it.code and 31 }

    private fun bech32Polymod(values: List<Int>): Int {
        val generators = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
        var checksum = 1
        for (value in values) {
            val top = checksum ushr 25
            checksum = ((checksum and 0x1ffffff) shl 5) xor value
            for (index in generators.indices) {
                if ((top ushr index) and 1 != 0) checksum = checksum xor generators[index]
            }
        }
        return checksum
    }

    private fun convertBits(values: List<Int>, from: Int, to: Int, pad: Boolean): List<Int> {
        val output = ArrayList<Int>()
        var accumulator = 0
        var bits = 0
        val maximumValue = (1 shl to) - 1
        val maximumAccumulator = (1 shl (from + to - 1)) - 1
        for (value in values) {
            if (value ushr from != 0) throw InvalidStanzaException()
            accumulator = ((accumulator shl from) or value) and maximumAccumulator
            bits += from
            while (bits >= to) {
                bits -= to
                output.add((accumulator ushr bits) and maximumValue)
            }
        }
        if (pad) {
            if (bits > 0) output.add((accumulator shl (to - bits)) and maximumValue)
        } else if (bits >= from || ((accumulator shl (to - bits)) and maximumValue) != 0) {
            throw InvalidStanzaException()
        }
        return output
    }

    private fun seal(
        sharedSecret: ByteArray,
        ephemeralPublic: ByteArray,
        recipientPublic: ByteArray,
        fileKey: ByteArray,
    ): ByteArray {
        return sealFile(1, sharedSecret, ephemeralPublic, recipientPublic, fileKey)
    }

    private fun sealFile(
        version: Int,
        sharedSecret: ByteArray,
        ephemeralPublic: ByteArray,
        recipientPublic: ByteArray,
        fileKey: ByteArray,
    ): ByteArray {
        val info = if (version == 2) FILE_KEY_KDF_INFO_V2 else KDF_INFO
        val key = deriveKey(sharedSecret, ephemeralPublic, recipientPublic, info)
        return try {
            val cipher = cipher(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(associatedData(version, ephemeralPublic, recipientPublic))
            cipher.doFinal(fileKey)
        } finally {
            key.fill(0)
        }
    }

    private fun open(
        version: Int,
        sharedSecret: ByteArray,
        ephemeralPublic: ByteArray,
        recipientPublic: ByteArray,
        body: ByteArray,
    ): ByteArray {
        val info = if (version == 2) FILE_KEY_KDF_INFO_V2 else KDF_INFO
        val key = deriveKey(sharedSecret, ephemeralPublic, recipientPublic, info)
        return try {
            val cipher = cipher(Cipher.DECRYPT_MODE, key)
            cipher.updateAAD(associatedData(version, ephemeralPublic, recipientPublic))
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
        info: ByteArray,
    ): ByteArray {
        val salt = ephemeralPublic + recipientPublic
        val extract = Mac.getInstance("HmacSHA256")
        extract.init(SecretKeySpec(salt, "HmacSHA256"))
        val pseudorandomKey = extract.doFinal(sharedSecret)
        salt.fill(0)
        return try {
            val expand = Mac.getInstance("HmacSHA256")
            expand.init(SecretKeySpec(pseudorandomKey, "HmacSHA256"))
            expand.update(info)
            expand.doFinal(byteArrayOf(1))
        } finally {
            pseudorandomKey.fill(0)
        }
    }

    private fun associatedData(
        version: Int,
        ephemeralPublic: ByteArray,
        recipientPublic: ByteArray,
    ): ByteArray =
        (if (version == 2) STANZA_TAG_V2 else STANZA_TAG).toByteArray(Charsets.US_ASCII) + byteArrayOf(0) +
            ephemeralPublic + recipientPublic

    private fun selectionAssociatedData(
        ephemeralPublic: ByteArray,
        phoneIdentityPublic: ByteArray,
        desktopSelectionPublic: ByteArray,
        body: ByteArray,
    ): ByteArray =
        STANZA_TAG_V2.toByteArray(Charsets.US_ASCII) + byteArrayOf(0) +
            "selection".toByteArray(Charsets.US_ASCII) + byteArrayOf(0) +
            ephemeralPublic + phoneIdentityPublic + desktopSelectionPublic + body

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
