import CryptoKit
import Foundation

// C2SP age v1.1.0 / RFC 9180. The caller owns fresh hardware authentication and replay consumption.
package enum P256Tag {
    package enum Failure: Error { case malformed, authentication }
    private static let info = Data("age-encryption.org/p256tag".utf8)
    private static let kem = Data([75, 69, 77, 0, 16])
    private static let suite = Data([72, 80, 75, 69, 0, 16, 0, 1, 0, 3])

    package static func parse(arguments: [String], body: Data) throws -> P256.KeyAgreement.PublicKey {
        guard arguments.count == 2, body.count == 32 else { throw Failure.malformed }
        _ = try base64(arguments[0], count: 4)
        let enc = try base64(arguments[1], count: 65)
        guard enc.first == 4 else { throw Failure.malformed }
        let key = try P256.KeyAgreement.PublicKey(x963Representation: enc)
        guard key.x963Representation == enc else { throw Failure.malformed }
        return key
    }

    package static func matches(recipient: P256.KeyAgreement.PublicKey, arguments: [String], body: Data) throws -> Bool {
        let enc = try parse(arguments: arguments, body: body).x963Representation
        let hash = Data(SHA256.hash(data: try RecipientEncoding.compressed(recipient)))
        let tag = HMAC<SHA256>.authenticationCode(for: enc + hash.prefix(4), using: SymmetricKey(data: info))
        return Data(tag.prefix(4)) == (try base64(arguments[0], count: 4))
    }

    private static func base64(_ value: String, count: Int) throws -> Data {
        let padded = value + String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let bytes = Data(base64Encoded: padded), bytes.count == count,
              bytes.base64EncodedString().replacingOccurrences(of: "=", with: "") == value else {
            throw Failure.malformed
        }
        return bytes
    }

    private static func extract(_ suite: Data, salt: SymmetricKey, label: String, input: Data) -> SymmetricKey {
        var labeled = Data("HPKE-v1".utf8) + suite + Data(label.utf8) + input
        defer { labeled.resetBytes(in: 0..<labeled.count) }
        return SymmetricKey(data: HMAC<SHA256>.authenticationCode(for: labeled, using: salt))
    }

    private static func expand(_ suite: Data, key: SymmetricKey, label: String, info: Data, count: UInt8) -> SymmetricKey {
        // All outputs fit one HKDF-SHA256 block.
        var input = Data([0, count]) + Data("HPKE-v1".utf8) + suite + Data(label.utf8) + info + Data([1])
        defer { input.resetBytes(in: 0..<input.count) }
        var output = Data(HMAC<SHA256>.authenticationCode(for: input, using: key))
        defer { output.resetBytes(in: 0..<output.count) }
        return SymmetricKey(data: output.prefix(Int(count)))
    }

    package static func open(secret: SharedSecret, recipient: P256.KeyAgreement.PublicKey, arguments: [String], body: Data) throws -> Data {
        let enc = try parse(arguments: arguments, body: body).x963Representation
        guard try matches(recipient: recipient, arguments: arguments, body: body) else { throw Failure.authentication }
        let empty = SymmetricKey(data: Data())
        var dh = secret.withUnsafeBytes { Data($0) }
        defer { dh.resetBytes(in: 0..<dh.count) }
        guard dh.count == 32 else { throw Failure.malformed }
        let eae = extract(kem, salt: empty, label: "eae_prk", input: dh)
        let shared = expand(kem, key: eae, label: "shared_secret", info: enc + recipient.x963Representation, count: 32)
        let psk = extract(suite, salt: empty, label: "psk_id_hash", input: Data())
        let infoHash = extract(suite, salt: empty, label: "info_hash", input: info)
        var context = Data([0]) + psk.withUnsafeBytes { Data($0) } + infoHash.withUnsafeBytes { Data($0) }
        defer { context.resetBytes(in: 0..<context.count) }
        let keySecret = extract(suite, salt: shared, label: "secret", input: Data())
        let key = expand(suite, key: keySecret, label: "key", info: context, count: 32)
        let nonceKey = expand(suite, key: keySecret, label: "base_nonce", info: context, count: 12)
        var nonceBytes = nonceKey.withUnsafeBytes { Data($0) }
        defer { nonceBytes.resetBytes(in: 0..<nonceBytes.count) }
        do {
            let box = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: nonceBytes), ciphertext: body.prefix(16), tag: body.suffix(16))
            var plaintext = try ChaChaPoly.open(box, using: key)
            guard plaintext.count == 16 else {
                plaintext.resetBytes(in: 0..<plaintext.count)
                throw Failure.authentication
            }
            return plaintext
        } catch { throw Failure.authentication }
    }
}
