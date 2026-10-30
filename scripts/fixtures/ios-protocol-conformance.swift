import CryptoKit
import Foundation

// Public metadata only; no hardware operation or production software-key fallback.
struct IdentityPublicMetadata {
    let identityId: Data
    let recipient: String
    let signingPublicKey: Data
}

@main struct Harness {
    static func main() throws {
        let root = URL(fileURLWithPath: CommandLine.arguments[1])
        func json(_ name: String) throws -> [String: Any] {
            try JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent(name))) as! [String: Any]
        }
        func b64(_ text: String) -> Data { Data(base64Encoded: text + String(repeating: "=", count: (4-text.count%4)%4))! }
        func hex(_ text: String) -> Data {
            let chars = Array(text)
            return Data(stride(from: 0, to: chars.count, by: 2).map { UInt8(String(chars[$0...$0+1]), radix: 16)! })
        }
        func scalar(_ n: Int) -> Data { Data(repeating: 0, count: 31) + Data([UInt8(n)]) }
        func equal(_ left: Data, _ right: Data, _ label: String) {
            precondition(left == right, label)
        }
        func signature(_ bytes: Data, key: P256.Signing.PublicKey, domain: String) throws -> Data {
            let (payload, sig) = try ProtocolBounds.decodeEnvelope(bytes)
            equal(try OfflineEnvelopeCrypto.encodeSigned(payload, signature: sig), bytes, "signed envelope bytes")
            try OfflineEnvelopeCrypto.verify(key: key, domain: Data(domain.utf8), payload: payload, signature: sig)
            return payload
        }
        let pairing = try json("pairing-transcript-v2.json")
        let offer = try OfflineEnvelopeCrypto.verifyPairingOffer(b64(pairing["signed_offer_base64"] as! String))
        equal(offer.digest, b64(pairing["offer_digest_base64"] as! String), "offer digest")
        equal(try TaggedRecipientCrypto.compressedSigning(offer.desktopSigningPublicKey), b64(pairing["desktop_signing_public_key_base64"] as! String), "desktop signing role")
        equal(try RecipientEncoding.compressed(offer.desktopSelectionPublicKey), b64(pairing["desktop_selection_public_key_base64"] as! String), "desktop selection role")
        let phoneSigning = try P256.Signing.PrivateKey(rawRepresentation: scalar(2)).publicKey
        let identity = try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar(3))
        let identityText = try RecipientEncoding.encode(identity.publicKey)
        precondition(identityText == pairing["recipient"] as! String)
        let metadata = IdentityPublicMetadata(identityId: hex(pairing["identity_id_hex"] as! String),
            recipient: pairing["recipient"] as! String, signingPublicKey: try TaggedRecipientCrypto.compressedSigning(phoneSigning))
        let pairingBytes = b64(pairing["signed_response_base64"] as! String)
        let pairingPayload = try signature(pairingBytes, key: phoneSigning, domain: "age-plugin-phone/pairing-response-signature/v2")
        equal(try OfflineEnvelopeCrypto.pairingResponsePayload(offer: offer, identity: metadata,
            nonce: hex(pairing["response_nonce_hex"] as! String)), pairingPayload, "pairing response bytes")
        let paired = VerifiedPairingResponse(identityId: metadata.identityId, recipient: metadata.recipient,
            phoneSigningPublicKey: phoneSigning, offerDigest: offer.digest, nonce: hex(pairing["response_nonce_hex"] as! String), encoded: pairingBytes)
        equal(OfflineEnvelopeCrypto.pairingFingerprint(offer, paired), b64(pairing["fingerprint_base64"] as! String), "transcript fingerprint")

        for name in ["offline-envelope-v2.json", "p256tag-envelope-v2.json", "phone-v2-envelope.json"] {
            let vector = try json(name)
            let request = try OfflineEnvelopeCrypto.verifyRequest(b64(vector["signed_request_base64"] as! String),
                desktopId: offer.desktopId, identityId: metadata.identityId,
                desktopSigningKey: offer.desktopSigningPublicKey, nowUnix: (vector["now_unix"] as! NSNumber).uint64Value)
            equal(request.digest, b64(vector["request_digest_base64"] as! String), "request digest " + name)
            let (version, ephemeral, _) = try TaggedRecipientCrypto.parse(request.stanza)
            let secret = try identity.sharedSecretFromKeyAgreement(with: ephemeral)
            let opened: Data
            if version == 3 {
                opened = try P256Tag.open(secret: secret, recipient: identity.publicKey,
                    arguments: request.stanza.arguments, body: request.stanza.body)
            } else {
                opened = try TaggedRecipientCrypto.openPhone(stanza: request.stanza, secret: secret, recipient: identity.publicKey)
            }
            equal(opened, hex(vector["file_key_hex"] as! String), "recipient opening " + name)
            if version != 3 {
                var body = request.stanza.body; body[0] ^= 1
                let tampered = RecipientStanza(tag: request.stanza.tag, arguments: request.stanza.arguments, body: body)
                var rejected = false
                do { _ = try TaggedRecipientCrypto.openPhone(stanza: tampered, secret: secret, recipient: identity.publicKey) }
                catch { rejected = true }
                precondition(rejected, "tampered file-key AEAD")
            }
            let responsePayload = try signature(b64(vector["signed_response_base64"] as! String), key: phoneSigning,
                domain: "age-plugin-phone/unwrap-response-signature/v2")
            equal(try OfflineEnvelopeCrypto.responsePayload(request: request, fileKey: opened,
                session: P256.KeyAgreement.PrivateKey(rawRepresentation: scalar(vector["phone_session_scalar"] as! Int)),
                responseNonce: hex(vector["response_nonce_hex"] as! String)), responsePayload, "response AEAD and payload " + name)
        }
        // Only offers/requests are received by this phone implementation. Desktop response
        // rejection runs in Rust/Kotlin; Swift outgoing responses are compared byte-for-byte above.
        let negatives = try json("protocol-rejections-v2.json")
        var count = 0
        let rejectionCases = negatives["cases"] as! [[String: Any]]
        precondition(rejectionCases.count == 39)
        for test in rejectionCases {
            let target = test["target"] as! String
            precondition(["offer", "pairing_response", "request", "response"].contains(target))
            // Validate the corpus independently of production protocol rejection. High-S
            // cases must normalize to valid signatures; semantic mutations stay correctly signed.
            let name = test["name"] as! String
            var encoded = b64(test["encoded_base64"] as! String)
            if name.hasSuffix("_trailing") { encoded.removeLast() }
            let (payload, rawSignature) = try ProtocolBounds.decodeEnvelope(encoded)
            let normalized = try OfflineEnvelopeCrypto.lowSSignature(rawSignature)
            precondition((normalized != rawSignature) == name.hasSuffix("_high_s"))
            let domains = ["offer": "pairing-offer", "pairing_response": "pairing-response",
                           "request": "unwrap-request", "response": "unwrap-response"]
            let signer = target == "offer" || target == "request" ? 1 : (name == "pairing_response_reused_roles" ? 7 : 2)
            let key = try P256.Signing.PrivateKey(rawRepresentation: scalar(signer)).publicKey
            let domain = Data(("age-plugin-phone/" + domains[target]! + "-signature/v2").utf8) + Data([0])
            let sig = try P256.Signing.ECDSASignature(rawRepresentation: normalized)
            precondition(key.isValidSignature(sig, for: domain + payload), name)
            guard target == "offer" || target == "request" else { continue }
            precondition(test["accept"] as! Bool == false)
            var rejected = false
            do {
                let bytes = b64(test["encoded_base64"] as! String)
                if target == "offer" { _ = try OfflineEnvelopeCrypto.verifyPairingOffer(bytes) }
                else { _ = try OfflineEnvelopeCrypto.verifyRequest(bytes, desktopId: offer.desktopId,
                    identityId: metadata.identityId, desktopSigningKey: offer.desktopSigningPublicKey, nowUnix: 1_000_000) }
            } catch { rejected = true }
            precondition(rejected, test["name"] as! String)
            count += 1
        }
        precondition(count == 18)
        print("Swift production pairing, three envelope fixtures and \(count) inbound rejection cases passed")
    }
}
