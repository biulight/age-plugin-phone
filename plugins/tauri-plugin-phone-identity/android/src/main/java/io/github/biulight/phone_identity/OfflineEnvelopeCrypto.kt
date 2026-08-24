package io.github.biulight.phone_identity

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object OfflineEnvelopeCrypto {
    private const val VERSION = 1
    private const val SUITE = 1
    private const val OFFER_TYPE = 1
    private const val PAIRING_RESPONSE_TYPE = 2
    private const val REQUEST_TYPE = 3
    private const val RESPONSE_TYPE = 4
    private const val MAX_LIFETIME_SECONDS = 300L
    private val offerSignatureDomain = ascii("age-plugin-phone/pairing-offer-signature/v1")
    private val pairingSignatureDomain = ascii("age-plugin-phone/pairing-response-signature/v1")
    private val requestSignatureDomain = ascii("age-plugin-phone/unwrap-request-signature/v1")
    private val responseSignatureDomain = ascii("age-plugin-phone/unwrap-response-signature/v1")
    private val offerDigestDomain = ascii("age-plugin-phone/pairing-offer-digest/v1")
    private val fingerprintDomain = ascii("age-plugin-phone/pairing-fingerprint/v1")
    private val requestDigestDomain = ascii("age-plugin-phone/request-digest/v1")
    private val sessionInfo = ascii("age-plugin-phone/session-response/p256/v1")
    private val cbor = ObjectMapper(CBORFactory())
    private val zeroNonce = ByteArray(12)

    data class PairingOffer(
        val desktopId: ByteArray,
        val desktopLabel: String,
        val desktopSigningPublicKey: PublicKey,
        val nonce: ByteArray,
    )

    data class VerifiedPairingOffer(
        val offer: PairingOffer,
        val encoded: ByteArray,
        val digest: ByteArray,
    )

    data class PairingResponse(
        val identityId: ByteArray,
        val recipient: String,
        val phoneSigningPublicKey: PublicKey,
        val offerDigest: ByteArray,
        val nonce: ByteArray,
    )

    data class VerifiedPairingResponse(
        val response: PairingResponse,
        val encoded: ByteArray,
    )

    data class Request(
        val requestId: ByteArray,
        val identityId: ByteArray,
        val desktopId: ByteArray,
        val sessionPublicKey: PublicKey,
        val stanza: TaggedRecipientCrypto.Stanza,
        val nonce: ByteArray,
        val expiresAtUnix: Long,
        val callerHint: String?,
    )

    data class VerifiedRequest(
        val request: Request,
        val signedBytes: ByteArray,
        val digest: ByteArray,
    )

    /** Untrusted routing fields. Callers must verify the request against the opened pairing. */
    data class RequestScope(val desktopId: ByteArray, val identityId: ByteArray)

    data class Response(
        val requestId: ByteArray,
        val requestDigest: ByteArray,
        val identityId: ByteArray,
        val desktopId: ByteArray,
        val phoneSessionPublicKey: PublicKey,
        val nonce: ByteArray,
        val encryptedFileKey: ByteArray,
    )

    data class SignedResponse(val response: Response, val encoded: ByteArray)

    data class SignedPairingTranscript(
        val signedOffer: ByteArray,
        val signedResponse: ByteArray,
    )

    fun verifyPairingOffer(encoded: ByteArray): VerifiedPairingOffer {
        val (payload, signature) = decodeSigned(encoded)
        val offer = decodePairingOfferPayload(payload)
        verify(offer.desktopSigningPublicKey, offerSignatureDomain, payload, signature)
        return VerifiedPairingOffer(offer, encoded.copyOf(), digest(offerDigestDomain, encoded))
    }

    fun verifyPairingResponse(
        encoded: ByteArray,
        offer: VerifiedPairingOffer,
    ): VerifiedPairingResponse {
        val (payload, signature) = decodeSigned(encoded)
        val response = decodePairingResponsePayload(payload)
        if (!MessageDigest.isEqual(response.offerDigest, offer.digest)) throw ProtocolException()
        verify(response.phoneSigningPublicKey, pairingSignatureDomain, payload, signature)
        return VerifiedPairingResponse(response, encoded.copyOf())
    }

    /** Creates a response using an already-provisioned, non-exportable phone signing key. */
    fun createPairingResponse(
        offer: VerifiedPairingOffer,
        identity: PhoneIdentityPublic,
        phoneSigningPrivateKey: PrivateKey,
        random: SecureRandom,
    ): VerifiedPairingResponse {
        if (!MessageDigest.isEqual(
                identity.signingPublicKey,
                TaggedRecipientCrypto.encodeCompressed(
                    TaggedRecipientCrypto.decodeCompressed(identity.signingPublicKey),
                ),
            )
        ) throw ProtocolException()
        val response = PairingResponse(
            identityId = identity.identityId.copyOf(),
            recipient = identity.recipient,
            phoneSigningPublicKey = TaggedRecipientCrypto.decodeCompressed(
                identity.signingPublicKey,
            ),
            offerDigest = offer.digest.copyOf(),
            nonce = randomBytes(32, random),
        )
        val payload = encodePairingResponsePayload(response)
        val encoded = encodeSigned(
            payload,
            sign(phoneSigningPrivateKey, pairingSignatureDomain, payload),
        )
        return verifyPairingResponse(encoded, offer)
    }

    fun pairingFingerprint(
        offer: VerifiedPairingOffer,
        response: VerifiedPairingResponse,
    ): ByteArray = digest(fingerprintDomain, offer.encoded + response.encoded)

    fun createSyntheticPairingTranscript(
        identityPublicKey: PublicKey,
        desktopSigning: KeyPair,
        phoneSigning: KeyPair,
        random: SecureRandom,
    ): SignedPairingTranscript {
        val offer = PairingOffer(
            desktopId = randomBytes(16, random),
            desktopLabel = "Pairing confirmation Doctor",
            desktopSigningPublicKey = desktopSigning.public,
            nonce = randomBytes(32, random),
        )
        val offerPayload = encodePairingOfferPayload(offer)
        val signedOffer = encodeSigned(
            offerPayload,
            sign(desktopSigning.private, offerSignatureDomain, offerPayload),
        )
        val verifiedOffer = verifyPairingOffer(signedOffer)
        val response = PairingResponse(
            identityId = randomBytes(16, random),
            recipient = TaggedRecipientCrypto.encodeRecipient(identityPublicKey),
            phoneSigningPublicKey = phoneSigning.public,
            offerDigest = verifiedOffer.digest,
            nonce = randomBytes(32, random),
        )
        val responsePayload = encodePairingResponsePayload(response)
        return SignedPairingTranscript(
            signedOffer,
            encodeSigned(
                responsePayload,
                sign(phoneSigning.private, pairingSignatureDomain, responsePayload),
            ),
        )
    }

    fun createSignedRequest(
        stanza: TaggedRecipientCrypto.Stanza,
        desktopSigning: KeyPair,
        desktopSessionPublic: PublicKey,
        nowUnix: Long,
        random: SecureRandom,
    ): VerifiedRequest {
        val request = Request(
            randomBytes(16, random),
            randomBytes(16, random),
            randomBytes(16, random),
            desktopSessionPublic,
            stanza,
            randomBytes(32, random),
            nowUnix + MAX_LIFETIME_SECONDS,
            "StrongBox tagged-recipient Doctor",
        )
        val payload = encodeRequestPayload(request)
        val signature = sign(desktopSigning.private, requestSignatureDomain, payload)
        val signed = encodeSigned(payload, signature)
        return verifyRequest(
            signed,
            request.desktopId,
            request.identityId,
            desktopSigning.public,
            nowUnix,
        )
    }

    fun createSignedRequestForPairing(
        stanza: TaggedRecipientCrypto.Stanza,
        desktopSigning: KeyPair,
        desktopSessionPublic: PublicKey,
        desktopId: ByteArray,
        identityId: ByteArray,
        nowUnix: Long,
        random: SecureRandom,
    ): VerifiedRequest {
        val request = Request(
            randomBytes(16, random),
            identityId.copyOf(),
            desktopId.copyOf(),
            desktopSessionPublic,
            stanza,
            randomBytes(32, random),
            nowUnix + MAX_LIFETIME_SECONDS,
            "Pairing confirmation Doctor",
        )
        val payload = encodeRequestPayload(request)
        val signature = sign(desktopSigning.private, requestSignatureDomain, payload)
        val signed = encodeSigned(payload, signature)
        return verifyRequest(
            signed,
            request.desktopId,
            request.identityId,
            desktopSigning.public,
            nowUnix,
        )
    }

    fun verifyRequest(
        encoded: ByteArray,
        expectedDesktopId: ByteArray,
        expectedIdentityId: ByteArray,
        desktopSigningPublic: PublicKey,
        nowUnix: Long,
    ): VerifiedRequest {
        val (payload, signature) = decodeSigned(encoded)
        val request = decodeRequestPayload(payload)
        if (!MessageDigest.isEqual(request.desktopId, expectedDesktopId)) throw ProtocolException()
        if (!MessageDigest.isEqual(request.identityId, expectedIdentityId)) throw ProtocolException()
        if (request.expiresAtUnix < nowUnix || request.expiresAtUnix > nowUnix + MAX_LIFETIME_SECONDS) {
            throw ProtocolException()
        }
        verify(desktopSigningPublic, requestSignatureDomain, payload, signature)
        return VerifiedRequest(request, encoded.copyOf(), digest(requestDigestDomain, encoded))
    }

    fun requestScope(encoded: ByteArray): RequestScope {
        val (payload, _) = decodeSigned(encoded)
        val request = decodeRequestPayload(payload)
        return RequestScope(request.desktopId.copyOf(), request.identityId.copyOf())
    }

    fun verifyRequestAndConsume(
        encoded: ByteArray,
        pairingState: PairingStateStore,
        nowUnix: Long,
    ): VerifiedRequest {
        val record = pairingState.pairingRecord()
        val verified = try {
            verifyRequest(
                encoded,
                record.desktopId,
                record.identityId,
                record.desktopSigningKey(),
                nowUnix,
            )
        } catch (_: TaggedRecipientCrypto.InvalidStanzaException) {
            throw ProtocolException()
        }
        pairingState.consumeRequest(verified, nowUnix)
        return verified
    }

    fun sealResponse(
        request: VerifiedRequest,
        fileKey: ByteArray,
        phoneSigning: KeyPair,
        random: SecureRandom,
    ): SignedResponse = sealResponse(
        request,
        fileKey,
        phoneSigning.private,
        phoneSigning.public,
        random,
    )

    fun sealResponse(
        request: VerifiedRequest,
        fileKey: ByteArray,
        phoneSigningPrivate: PrivateKey,
        phoneSigningPublic: PublicKey,
        random: SecureRandom,
    ): SignedResponse {
        if (fileKey.size != 16) throw ProtocolException()
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"), random)
        val phoneSession = generator.generateKeyPair()
        val nonce = randomBytes(32, random)
        val response = Response(
            request.request.requestId,
            request.digest,
            request.request.identityId,
            request.request.desktopId,
            phoneSession.public,
            nonce,
            ByteArray(32),
        )
        val secret = agree(phoneSession.private, request.request.sessionPublicKey)
        val encrypted = try {
            encrypt(secret, request.digest, nonce, encodeResponseAad(response), fileKey)
        } finally {
            secret.fill(0)
        }
        val completed = response.copy(encryptedFileKey = encrypted)
        val payload = encodeResponsePayload(completed)
        val encoded = encodeSigned(
            payload,
            sign(phoneSigningPrivate, responseSignatureDomain, payload),
        )
        val (_, signature) = decodeSigned(encoded)
        verify(phoneSigningPublic, responseSignatureDomain, payload, signature)
        return SignedResponse(completed, encoded)
    }

    fun openResponse(
        encoded: ByteArray,
        request: VerifiedRequest,
        phoneSigningPublic: PublicKey,
        desktopSessionPrivate: PrivateKey,
    ): ByteArray {
        val (payload, signature) = decodeSigned(encoded)
        val response = decodeResponsePayload(payload)
        if (!MessageDigest.isEqual(response.requestId, request.request.requestId) ||
            !MessageDigest.isEqual(response.requestDigest, request.digest) ||
            !MessageDigest.isEqual(response.identityId, request.request.identityId) ||
            !MessageDigest.isEqual(response.desktopId, request.request.desktopId)
        ) throw ProtocolException()
        verify(phoneSigningPublic, responseSignatureDomain, payload, signature)
        val secret = agree(desktopSessionPrivate, response.phoneSessionPublicKey)
        return try {
            decrypt(
                secret,
                response.requestDigest,
                response.nonce,
                encodeResponseAad(response),
                response.encryptedFileKey,
            )
        } finally {
            secret.fill(0)
        }
    }

    private fun decodePairingOfferPayload(encoded: ByteArray): PairingOffer {
        val n = strictArray(encoded, 7)
        header(n, OFFER_TYPE)
        return PairingOffer(
            bytes(n[3], 16),
            text(n[4], 64),
            TaggedRecipientCrypto.decodeCompressed(bytes(n[5], 33)),
            bytes(n[6], 32),
        )
    }

    private fun encodePairingOfferPayload(value: PairingOffer): ByteArray = encodeArray {
        add(VERSION); add(OFFER_TYPE); add(SUITE); add(value.desktopId); add(value.desktopLabel)
        add(TaggedRecipientCrypto.encodeCompressed(value.desktopSigningPublicKey)); add(value.nonce)
    }

    private fun decodePairingResponsePayload(encoded: ByteArray): PairingResponse {
        val n = strictArray(encoded, 8)
        header(n, PAIRING_RESPONSE_TYPE)
        val recipient = text(n[4], 160)
        try {
            TaggedRecipientCrypto.decodeRecipient(recipient)
        } catch (_: TaggedRecipientCrypto.InvalidStanzaException) {
            throw ProtocolException()
        }
        return PairingResponse(
            bytes(n[3], 16),
            recipient,
            TaggedRecipientCrypto.decodeCompressed(bytes(n[5], 33)),
            bytes(n[6], 32),
            bytes(n[7], 32),
        )
    }

    private fun encodePairingResponsePayload(value: PairingResponse): ByteArray = encodeArray {
        add(VERSION); add(PAIRING_RESPONSE_TYPE); add(SUITE); add(value.identityId)
        add(value.recipient); add(TaggedRecipientCrypto.encodeCompressed(value.phoneSigningPublicKey))
        add(value.offerDigest); add(value.nonce)
    }

    private fun encodeRequestPayload(value: Request): ByteArray = encodeArray {
        add(VERSION); add(REQUEST_TYPE); add(SUITE); add(value.requestId); add(value.identityId)
        add(value.desktopId); add(TaggedRecipientCrypto.encodeCompressed(value.sessionPublicKey))
        add(encodeStanza(value.stanza)); add(value.nonce); add(value.expiresAtUnix)
        if (value.callerHint == null) addNull() else add(value.callerHint)
    }

    private fun decodeRequestPayload(encoded: ByteArray): Request {
        val n = strictArray(encoded, 11)
        header(n, REQUEST_TYPE)
        val stanzaNode = n[7] as? ArrayNode ?: throw ProtocolException()
        if (stanzaNode.size() != 3 || stanzaNode[1].size() != 1) throw ProtocolException()
        val stanza = TaggedRecipientCrypto.Stanza(
            text(stanzaNode[0], 64),
            listOf(text(stanzaNode[1][0], 128)),
            bytes(stanzaNode[2], 32),
        )
        TaggedRecipientCrypto.parse(stanza)
        val hint = if (n[10].isNull) null else text(n[10], 64)
        return Request(
            bytes(n[3], 16), bytes(n[4], 16), bytes(n[5], 16),
            TaggedRecipientCrypto.decodeCompressed(bytes(n[6], 33)), stanza,
            bytes(n[8], 32), unsignedLong(n[9]), hint,
        )
    }

    private fun encodeResponsePayload(v: Response): ByteArray = encodeArray {
        add(VERSION); add(RESPONSE_TYPE); add(SUITE); add(v.requestId); add(v.requestDigest)
        add(v.identityId); add(v.desktopId); add(TaggedRecipientCrypto.encodeCompressed(v.phoneSessionPublicKey))
        add(v.nonce); add(v.encryptedFileKey)
    }

    private fun encodeResponseAad(v: Response): ByteArray = encodeArray {
        add(VERSION); add(RESPONSE_TYPE); add(SUITE); add(v.requestId); add(v.requestDigest)
        add(v.identityId); add(v.desktopId); add(TaggedRecipientCrypto.encodeCompressed(v.phoneSessionPublicKey))
        add(v.nonce)
    }

    private fun decodeResponsePayload(encoded: ByteArray): Response {
        val n = strictArray(encoded, 10); header(n, RESPONSE_TYPE)
        return Response(
            bytes(n[3], 16), bytes(n[4], 32), bytes(n[5], 16), bytes(n[6], 16),
            TaggedRecipientCrypto.decodeCompressed(bytes(n[7], 33)), bytes(n[8], 32), bytes(n[9], 32),
        )
    }

    private fun encodeStanza(v: TaggedRecipientCrypto.Stanza): ArrayNode = cbor.createArrayNode().apply {
        add(v.tag); add(cbor.createArrayNode().add(v.args.single())); add(v.body)
    }

    private fun encodeSigned(payload: ByteArray, signature: ByteArray): ByteArray =
        encodeArray { add(payload); add(signature) }

    private fun decodeSigned(encoded: ByteArray): Pair<ByteArray, ByteArray> {
        val n = strictArray(encoded, 2)
        return bytes(n[0], null) to bytes(n[1], 64)
    }

    private fun strictArray(encoded: ByteArray, size: Int): ArrayNode {
        val node = cbor.readTree(encoded) as? ArrayNode ?: throw ProtocolException()
        if (node.size() != size || !MessageDigest.isEqual(cbor.writeValueAsBytes(node), encoded)) {
            throw ProtocolException()
        }
        return node
    }

    private fun header(node: ArrayNode, type: Int) {
        if (node[0].asInt(-1) != VERSION || node[1].asInt(-1) != type || node[2].asInt(-1) != SUITE) {
            throw ProtocolException()
        }
    }

    private fun encodeArray(build: ArrayNode.() -> Unit): ByteArray =
        cbor.writeValueAsBytes(cbor.createArrayNode().apply(build))

    private fun bytes(node: JsonNode, size: Int?): ByteArray {
        if (!node.isBinary) throw ProtocolException()
        val value = node.binaryValue()
        if (size != null && value.size != size) throw ProtocolException()
        return value
    }

    private fun text(node: JsonNode, max: Int): String {
        if (!node.isTextual || node.textValue().toByteArray().size > max) throw ProtocolException()
        return node.textValue()
    }

    private fun unsignedLong(node: JsonNode): Long {
        if (!node.isIntegralNumber || !node.canConvertToLong() || node.longValue() < 0) throw ProtocolException()
        return node.longValue()
    }

    private fun sign(key: PrivateKey, domain: ByteArray, payload: ByteArray): ByteArray {
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(key); signer.update(domainInput(domain, payload))
        return derToCompact(signer.sign())
    }

    private fun verify(key: PublicKey, domain: ByteArray, payload: ByteArray, compact: ByteArray) {
        if (compact.size != 64) throw ProtocolException()
        val order = (key as java.security.interfaces.ECPublicKey).params.order
        val s = BigInteger(1, compact.copyOfRange(32, 64))
        if (s > order.shiftRight(1)) throw ProtocolException()
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(key); verifier.update(domainInput(domain, payload))
        if (!verifier.verify(compactToDer(compact))) throw ProtocolException()
    }

    private fun derToCompact(der: ByteArray): ByteArray {
        if (der.size < 8 || der[0] != 0x30.toByte() || der[1].toInt() != der.size - 2) throw ProtocolException()
        var offset = 2
        fun integer(): ByteArray {
            if (der[offset++] != 0x02.toByte()) throw ProtocolException()
            val size = der[offset++].toInt() and 0xff
            if (size !in 1..33 || offset + size > der.size) throw ProtocolException()
            return der.copyOfRange(offset, offset + size).also { offset += size }
        }
        val r = integer(); var s = BigInteger(1, integer())
        val order = p256Order(); if (s > order.shiftRight(1)) s = order.subtract(s)
        return fixed(BigInteger(1, r), 32) + fixed(s, 32)
    }

    private fun compactToDer(compact: ByteArray): ByteArray {
        fun integer(part: ByteArray): ByteArray = BigInteger(1, part).toByteArray()
        val r = integer(compact.copyOfRange(0, 32)); val s = integer(compact.copyOfRange(32, 64))
        return byteArrayOf(0x30, (4 + r.size + s.size).toByte(), 0x02, r.size.toByte()) + r +
            byteArrayOf(0x02, s.size.toByte()) + s
    }

    private fun encrypt(secret: ByteArray, digest: ByteArray, nonce: ByteArray, aad: ByteArray, value: ByteArray): ByteArray =
        crypt(Cipher.ENCRYPT_MODE, secret, digest, nonce, aad, value)
    private fun decrypt(secret: ByteArray, digest: ByteArray, nonce: ByteArray, aad: ByteArray, value: ByteArray): ByteArray =
        crypt(Cipher.DECRYPT_MODE, secret, digest, nonce, aad, value)
    private fun crypt(mode: Int, secret: ByteArray, digest: ByteArray, nonce: ByteArray, aad: ByteArray, value: ByteArray): ByteArray {
        val key = hkdf(secret, digest + nonce)
        return try {
            Cipher.getInstance("ChaCha20-Poly1305").run {
                init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(zeroNonce)); updateAAD(aad); doFinal(value)
            }
        } finally { key.fill(0) }
    }

    private fun hkdf(secret: ByteArray, salt: ByteArray): ByteArray {
        val extract = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(salt, "HmacSHA256")) }
        val prk = extract.doFinal(secret)
        return try { Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(prk, "HmacSHA256")); update(sessionInfo); doFinal(byteArrayOf(1)) } } finally { prk.fill(0) }
    }
    private fun agree(privateKey: PrivateKey, publicKey: PublicKey): ByteArray = KeyAgreement.getInstance("ECDH").run { init(privateKey); doPhase(publicKey, true); generateSecret() }
    private fun digest(domain: ByteArray, payload: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(domainInput(domain, payload))
    private fun domainInput(domain: ByteArray, payload: ByteArray) = domain + byteArrayOf(0) + payload
    private fun randomBytes(size: Int, random: SecureRandom) = ByteArray(size).also(random::nextBytes)
    private fun ascii(value: String) = value.toByteArray(Charsets.US_ASCII)
    private fun fixed(value: BigInteger, size: Int): ByteArray = value.toByteArray().let { raw ->
        val unsigned = if (raw.size > size && raw[0] == 0.toByte()) raw.copyOfRange(1, raw.size) else raw
        if (unsigned.size > size) throw ProtocolException()
        ByteArray(size).also { unsigned.copyInto(it, size - unsigned.size) }
    }
    private fun p256Order(): BigInteger = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1")); (generateKeyPair().public as java.security.interfaces.ECPublicKey).params.order
    }

    class ProtocolException : Exception()
}
