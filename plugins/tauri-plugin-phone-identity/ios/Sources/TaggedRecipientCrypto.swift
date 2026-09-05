import CryptoKit
import Foundation
import PhoneIdentityCore

struct RecipientStanza {
    let tag: String
    let arguments: [String]
    let body: Data
}

enum TaggedRecipientError: Error { case malformed, authentication }

enum TaggedRecipientCrypto {
    static let stanzaTag = "phone-p256-v1"
    static let stanzaTagV2 = "phone-p256-v2"
    private static let zeroNonce = try! ChaChaPoly.Nonce(data: Data(repeating: 0, count: 12))

    static func publicKey(_ compact: Data) throws -> P256.KeyAgreement.PublicKey {
        guard compact.count == 33 else { throw TaggedRecipientError.malformed }
        if #available(iOS 16.0, *) {
            return try P256.KeyAgreement.PublicKey(compressedRepresentation: compact)
        }
        throw TaggedRecipientError.malformed
    }

    static func signingPublicKey(_ compact: Data) throws -> P256.Signing.PublicKey {
        guard compact.count == 33 else { throw TaggedRecipientError.malformed }
        if #available(iOS 16.0, *) {
            return try P256.Signing.PublicKey(compressedRepresentation: compact)
        }
        throw TaggedRecipientError.malformed
    }

    static func compressedSigning(_ key: P256.Signing.PublicKey) throws -> Data {
        let x963 = key.x963Representation
        guard x963.count == 65, x963[0] == 4 else { throw TaggedRecipientError.malformed }
        return Data([x963[64] & 1 == 0 ? 2 : 3]) + x963[1..<33]
    }

    static func parse(_ stanza: RecipientStanza) throws -> (Int, P256.KeyAgreement.PublicKey, Data) {
        let version: Int
        if stanza.tag == stanzaTag, stanza.arguments.count == 1 { version = 1 }
        else if stanza.tag == stanzaTagV2, stanza.arguments.count == 2 { version = 2 }
        else { throw TaggedRecipientError.malformed }
        guard stanza.body.count == 32,
              let ephemeral = decodeCanonicalBase64(stanza.arguments[0]),
              ephemeral.count == 33 else { throw TaggedRecipientError.malformed }
        if version == 2 {
            guard let selection = decodeCanonicalBase64(stanza.arguments[1]), selection.count == 32 else {
                throw TaggedRecipientError.malformed
            }
        }
        return (version, try publicKey(ephemeral), ephemeral)
    }

    private static func decodeCanonicalBase64(_ value: String) -> Data? {
        guard !value.contains("=") else { return nil }
        var padded = value
        padded += String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let decoded = Data(base64Encoded: padded),
              decoded.base64EncodedString().replacingOccurrences(of: "=", with: "") == value else { return nil }
        return decoded
    }

    static func unwrap(
        stanza: RecipientStanza,
        identity: SecureEnclave.P256.KeyAgreement.PrivateKey
    ) throws -> Data {
        let (version, ephemeral, ephemeralBytes) = try parse(stanza)
        let secret = try identity.sharedSecretFromKeyAgreement(with: ephemeral)
        let recipient = try RecipientEncoding.compressed(identity.publicKey)
        let info = Data((version == 2
            ? "age-plugin-phone/recipient/p256/v2/file-key"
            : "age-plugin-phone/recipient/p256/v1").utf8)
        let salt = ephemeralBytes + recipient
        let key = secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
        let associated = Data((version == 2 ? stanzaTagV2 : stanzaTag).utf8) + Data([0]) + ephemeralBytes + recipient
        do {
            let box = try ChaChaPoly.SealedBox(
                nonce: zeroNonce,
                ciphertext: stanza.body.prefix(16),
                tag: stanza.body.suffix(16)
            )
            let opened = try ChaChaPoly.open(box, using: key, authenticating: associated)
            guard opened.count == 16 else { throw TaggedRecipientError.authentication }
            return opened
        } catch { throw TaggedRecipientError.authentication }
    }
}
