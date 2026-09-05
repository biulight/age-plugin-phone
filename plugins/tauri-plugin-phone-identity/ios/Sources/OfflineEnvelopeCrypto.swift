import CryptoKit
import Foundation
import PhoneIdentityCore

enum OfflineProtocolError: Error { case malformed, signature, expired, wrongScope }

struct VerifiedPairingOffer {
    let desktopId: Data
    let desktopLabel: String
    let desktopSigningPublicKey: P256.Signing.PublicKey
    let desktopSelectionPublicKey: P256.KeyAgreement.PublicKey
    let nonce: Data
    let encoded: Data
    let digest: Data
}

struct VerifiedPairingResponse {
    let identityId: Data
    let recipient: String
    let phoneSigningPublicKey: P256.Signing.PublicKey
    let offerDigest: Data
    let nonce: Data
    let encoded: Data
}

struct VerifiedUnwrapRequest {
    let requestId: Data
    let identityId: Data
    let desktopId: Data
    let sessionPublicKey: P256.KeyAgreement.PublicKey
    let stanza: RecipientStanza
    let nonce: Data
    let expiresAtUnix: UInt64
    let callerHint: String?
    let signedBytes: Data
    let digest: Data
}

enum OfflineEnvelopeCrypto {
    private static let version: UInt64 = 2
    private static let suite: UInt64 = 1
    private static let offerSignatureDomain = Data("age-plugin-phone/pairing-offer-signature/v2".utf8)
    private static let pairingSignatureDomain = Data("age-plugin-phone/pairing-response-signature/v2".utf8)
    private static let requestSignatureDomain = Data("age-plugin-phone/unwrap-request-signature/v2".utf8)
    private static let responseSignatureDomain = Data("age-plugin-phone/unwrap-response-signature/v2".utf8)
    private static let offerDigestDomain = Data("age-plugin-phone/pairing-offer-digest/v2".utf8)
    private static let fingerprintDomain = Data("age-plugin-phone/pairing-fingerprint/v2".utf8)
    private static let requestDigestDomain = Data("age-plugin-phone/request-digest/v2".utf8)
    private static let responseSessionInfo = Data("age-plugin-phone/session-response/p256/v2".utf8)
    private static let zeroNonce = try! ChaChaPoly.Nonce(data: Data(repeating: 0, count: 12))
    private static let maximumLifetime: UInt64 = 300

    static func verifyPairingOffer(_ encoded: Data) throws -> VerifiedPairingOffer {
        let (payload, signature) = try decodeSigned(encoded)
        let values = try StrictCBOR.decode(payload).exactArray(8)
        try header(values, type: 1)
        let desktopId = try values[3].exactBytes(16)
        let label = try values[4].boundedText(64)
        let signingBytes = try values[5].exactBytes(33)
        let selectionBytes = try values[6].exactBytes(33)
        guard signingBytes != selectionBytes else { throw OfflineProtocolError.malformed }
        let signing = try TaggedRecipientCrypto.signingPublicKey(signingBytes)
        try verify(key: signing, domain: offerSignatureDomain, payload: payload, signature: signature)
        return VerifiedPairingOffer(
            desktopId: desktopId,
            desktopLabel: label,
            desktopSigningPublicKey: signing,
            desktopSelectionPublicKey: try TaggedRecipientCrypto.publicKey(selectionBytes),
            nonce: try values[7].exactBytes(32),
            encoded: encoded,
            digest: digest(domain: offerDigestDomain, payload: encoded)
        )
    }

    static func createPairingResponse(
        offer: VerifiedPairingOffer,
        identity: IdentityPublicMetadata,
        signingKey: SecureEnclave.P256.Signing.PrivateKey
    ) throws -> VerifiedPairingResponse {
        let signingPublic = try TaggedRecipientCrypto.compressedSigning(signingKey.publicKey)
        guard signingPublic == identity.signingPublicKey else { throw OfflineProtocolError.malformed }
        let nonce = try randomData(count: 32)
        let payload = try StrictCBOR.encode(.array([
            .unsigned(version), .unsigned(2), .unsigned(suite), .bytes(identity.identityId),
            .text(identity.recipient), .bytes(signingPublic), .bytes(offer.digest), .bytes(nonce)
        ]))
        let signature = try lowSSignature(try signingKey.signature(for: domainInput(pairingSignatureDomain, payload: payload)).rawRepresentation)
        let encoded = try encodeSigned(payload, signature: signature)
        return VerifiedPairingResponse(
            identityId: identity.identityId,
            recipient: identity.recipient,
            phoneSigningPublicKey: try TaggedRecipientCrypto.signingPublicKey(signingPublic),
            offerDigest: offer.digest,
            nonce: nonce,
            encoded: encoded
        )
    }

    static func pairingFingerprint(_ offer: VerifiedPairingOffer, _ response: VerifiedPairingResponse) -> Data {
        digest(domain: fingerprintDomain, payload: offer.encoded + response.encoded)
    }

    static func requestScope(_ encoded: Data) throws -> (desktopId: Data, identityId: Data) {
        let (payload, _) = try decodeSigned(encoded)
        let values = try StrictCBOR.decode(payload).exactArray(11)
        try header(values, type: 3)
        return (try values[5].exactBytes(16), try values[4].exactBytes(16))
    }

    static func verifyRequest(
        _ encoded: Data,
        desktopId expectedDesktopId: Data,
        identityId expectedIdentityId: Data,
        desktopSigningKey: P256.Signing.PublicKey,
        nowUnix: UInt64
    ) throws -> VerifiedUnwrapRequest {
        let (payload, signature) = try decodeSigned(encoded)
        let values = try StrictCBOR.decode(payload).exactArray(11)
        try header(values, type: 3)
        let requestId = try values[3].exactBytes(16)
        let identityId = try values[4].exactBytes(16)
        let desktopId = try values[5].exactBytes(16)
        guard identityId == expectedIdentityId, desktopId == expectedDesktopId else { throw OfflineProtocolError.wrongScope }
        let stanzaValues = try values[7].exactArray(3)
        guard case .array(let argumentValues) = stanzaValues[1], (1...2).contains(argumentValues.count) else {
            throw OfflineProtocolError.malformed
        }
        let stanza = RecipientStanza(
            tag: try stanzaValues[0].boundedText(64),
            arguments: try argumentValues.map { try $0.boundedText(128) },
            body: try stanzaValues[2].exactBytes(32)
        )
        _ = try TaggedRecipientCrypto.parse(stanza)
        let expires = try values[9].exactUnsigned()
        guard expires >= nowUnix, expires <= nowUnix + maximumLifetime else { throw OfflineProtocolError.expired }
        let hint: String?
        if values[10] == .null { hint = nil } else { hint = try values[10].boundedText(64) }
        try verify(key: desktopSigningKey, domain: requestSignatureDomain, payload: payload, signature: signature)
        return VerifiedUnwrapRequest(
            requestId: requestId,
            identityId: identityId,
            desktopId: desktopId,
            sessionPublicKey: try TaggedRecipientCrypto.publicKey(try values[6].exactBytes(33)),
            stanza: stanza,
            nonce: try values[8].exactBytes(32),
            expiresAtUnix: expires,
            callerHint: hint,
            signedBytes: encoded,
            digest: digest(domain: requestDigestDomain, payload: encoded)
        )
    }

    static func sealResponse(
        request: VerifiedUnwrapRequest,
        fileKey: Data,
        signingKey: SecureEnclave.P256.Signing.PrivateKey
    ) throws -> Data {
        guard fileKey.count == 16 else { throw OfflineProtocolError.malformed }
        let session = P256.KeyAgreement.PrivateKey(compactRepresentable: true)
        let sessionPublic = try RecipientEncoding.compressed(session.publicKey)
        let responseNonce = try randomData(count: 32)
        let aad = try StrictCBOR.encode(.array([
            .unsigned(version), .unsigned(4), .unsigned(suite), .bytes(request.requestId),
            .bytes(request.digest), .bytes(request.identityId), .bytes(request.desktopId),
            .bytes(sessionPublic), .bytes(responseNonce)
        ]))
        let secret = try session.sharedSecretFromKeyAgreement(with: request.sessionPublicKey)
        let key = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: request.digest + responseNonce,
            sharedInfo: responseSessionInfo,
            outputByteCount: 32
        )
        let box = try ChaChaPoly.seal(fileKey, using: key, nonce: zeroNonce, authenticating: aad)
        let encrypted = box.ciphertext + box.tag
        let payload = try StrictCBOR.encode(.array([
            .unsigned(version), .unsigned(4), .unsigned(suite), .bytes(request.requestId),
            .bytes(request.digest), .bytes(request.identityId), .bytes(request.desktopId),
            .bytes(sessionPublic), .bytes(responseNonce), .bytes(encrypted)
        ]))
        let signature = try lowSSignature(try signingKey.signature(for: domainInput(responseSignatureDomain, payload: payload)).rawRepresentation)
        return try encodeSigned(payload, signature: signature)
    }

    private static func header(_ values: [CBORValue], type: UInt64) throws {
        guard try values[0].exactUnsigned() == version,
              try values[1].exactUnsigned() == type,
              try values[2].exactUnsigned() == suite else { throw OfflineProtocolError.malformed }
    }

    private static func encodeSigned(_ payload: Data, signature: Data) throws -> Data {
        try StrictCBOR.encode(.array([.bytes(payload), .bytes(signature)]))
    }

    private static func decodeSigned(_ encoded: Data) throws -> (Data, Data) {
        let values = try StrictCBOR.decode(encoded).exactArray(2)
        return (try values[0].exactBytes(), try values[1].exactBytes(64))
    }

    private static func verify(
        key: P256.Signing.PublicKey,
        domain: Data,
        payload: Data,
        signature: Data
    ) throws {
        guard signature.count == 64, isLowS(signature.suffix(32)) else { throw OfflineProtocolError.signature }
        let value = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        guard key.isValidSignature(value, for: domainInput(domain, payload: payload)) else {
            throw OfflineProtocolError.signature
        }
    }

    private static func domainInput(_ domain: Data, payload: Data) -> Data { domain + Data([0]) + payload }
    private static func digest(domain: Data, payload: Data) -> Data { Data(SHA256.hash(data: domainInput(domain, payload: payload))) }

    private static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw OfflineProtocolError.malformed }
        return data
    }

    private static let order = Data([0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51])
    private static let halfOrder = Data([0x7f,0xff,0xff,0xff,0x80,0x00,0x00,0x00,0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xde,0x73,0x7d,0x56,0xd3,0x8b,0xcf,0x42,0x79,0xdc,0xe5,0x61,0x7e,0x31,0x92,0xa8])

    private static func isLowS(_ s: Data.SubSequence) -> Bool { lexicographicCompare(Data(s), halfOrder) <= 0 }

    static func lowSSignature(_ raw: Data) throws -> Data {
        guard raw.count == 64 else { throw OfflineProtocolError.signature }
        let r = raw.prefix(32), s = Data(raw.suffix(32))
        return isLowS(s[...]) ? raw : Data(r) + subtract(order, s)
    }

    private static func subtract(_ lhs: Data, _ rhs: Data) -> Data {
        var output = [UInt8](repeating: 0, count: lhs.count), borrow = 0
        let left = [UInt8](lhs), right = [UInt8](rhs)
        for index in stride(from: lhs.count - 1, through: 0, by: -1) {
            var value = Int(left[index]) - Int(right[index]) - borrow
            if value < 0 { value += 256; borrow = 1 } else { borrow = 0 }
            output[index] = UInt8(value)
        }
        return Data(output)
    }

    private static func lexicographicCompare(_ lhs: Data, _ rhs: Data) -> Int {
        for (left, right) in zip(lhs, rhs) where left != right { return left < right ? -1 : 1 }
        return lhs.count == rhs.count ? 0 : (lhs.count < rhs.count ? -1 : 1)
    }
}
