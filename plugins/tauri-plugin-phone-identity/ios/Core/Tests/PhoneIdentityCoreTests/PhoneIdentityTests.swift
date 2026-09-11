import CryptoKit
import XCTest
@testable import PhoneIdentityCore

final class PhoneIdentityTests: XCTestCase {
    func testP256TagSharedVectorAndCryptoKitHPKE() throws {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<7 { root.deleteLastPathComponent() }
        let bytes = try Data(contentsOf: root.appendingPathComponent("crates/core/test-vectors/p256tag.json"))
        let vector = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        let stanza = vector["stanza"] as! [String: Any]
        let args = stanza["args"] as! [String]
        let encodedBody = stanza["body_base64"] as! String
        let body = try XCTUnwrap(Data(base64Encoded: encodedBody + "="))
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 0, count: 31) + Data([1]))
        let expected = Data([0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        XCTAssertEqual(try RecipientEncoding.encode(key.publicKey, tagged: true), vector["recipient"] as? String)
        let enc = try P256Tag.parse(arguments: args, body: body)
        let shared = try key.sharedSecretFromKeyAgreement(with: enc)
        XCTAssertEqual(try P256Tag.open(secret: shared, recipient: key.publicKey, arguments: args, body: body), expected)
        // Apple's independent RFC 9180 implementation also opens the fixed Rust ciphertext.
        if #available(macOS 14.0, iOS 17.0, *) {
            var native = try HPKE.Recipient(privateKey: key, ciphersuite: HPKE.Ciphersuite(kem: .P256_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .chaChaPoly), info: Data("age-encryption.org/p256tag".utf8), encapsulatedKey: enc.x963Representation)
            XCTAssertEqual(try native.open(body), expected)
        }
        for bad in [[], Array(args.prefix(1)), args + ["extra"], [args[0] + "=", args[1]], [args[0], args[1] + "="], ["AAAA", args[1]], [args[0], Data(repeating: 0, count: 65).base64EncodedString().replacingOccurrences(of: "=", with: "")]] {
            XCTAssertThrowsError(try P256Tag.parse(arguments: bad, body: body))
        }
        for size in [0, 15, 31, 33] {
            XCTAssertThrowsError(try P256Tag.parse(arguments: args, body: Data(repeating: 0, count: size)))
        }
        var modified = body; modified[0] ^= 1
        XCTAssertThrowsError(try P256Tag.open(secret: shared, recipient: key.publicKey, arguments: args, body: modified))
        XCTAssertThrowsError(try P256Tag.open(secret: shared, recipient: key.publicKey, arguments: ["AAAAAA", args[1]], body: body))
        let wrong = P256.KeyAgreement.PrivateKey()
        XCTAssertFalse(try P256Tag.matches(recipient: wrong.publicKey, arguments: args, body: body))
        XCTAssertThrowsError(try P256Tag.open(secret: wrong.sharedSecretFromKeyAgreement(with: enc), recipient: wrong.publicKey, arguments: args, body: body))
    }

    func testRealTagCollisionIsNotHpkeAuthentication() throws {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<7 { root.deleteLastPathComponent() }
        let bytes = try Data(contentsOf: root.appendingPathComponent("crates/core/test-vectors/p256tag-collision.json"))
        let v = try JSONSerialization.jsonObject(with: bytes) as! [String: String]
        func scalar(_ field: String) throws -> P256.KeyAgreement.PrivateKey {
            let chars = Array(v[field]!)
            let data = Data(stride(from: 0, to: chars.count, by: 2).map { UInt8(String(chars[$0...$0+1]), radix: 16)! })
            return try P256.KeyAgreement.PrivateKey(rawRepresentation: data)
        }
        let first = try scalar("first_scalar_hex"), second = try scalar("second_scalar_hex")
        let args = [v["tag_base64"]!, v["enc_base64"]!]
        let body = try XCTUnwrap(Data(base64Encoded: v["body_base64"]! + "="))
        let enc = try P256Tag.parse(arguments: args, body: body)
        XCTAssertTrue(try P256Tag.matches(recipient: first.publicKey, arguments: args, body: body))
        XCTAssertTrue(try P256Tag.matches(recipient: second.publicKey, arguments: args, body: body))
        XCTAssertEqual(try P256Tag.open(secret: first.sharedSecretFromKeyAgreement(with: enc), recipient: first.publicKey, arguments: args, body: body), Data(repeating: 4, count: 16))
        XCTAssertThrowsError(try P256Tag.open(secret: second.sharedSecretFromKeyAgreement(with: enc), recipient: second.publicKey, arguments: args, body: body))
    }

    func testCanonicalCBORRoundTripAndRejectsNonCanonicalInteger() throws {
        let value = CBORValue.array([.unsigned(2), .text("phone"), .bytes(Data([1, 2, 3])), .null])
        let encoded = try StrictCBOR.encode(value)
        XCTAssertEqual(try StrictCBOR.decode(encoded), value)
        XCTAssertThrowsError(try StrictCBOR.decode(Data([0x18, 0x01])))
    }

    func testPersistentReplayArrayLimitIsExplicitAndRoundTripsAcceptedState() throws {
        let protocolMaximum = CBORValue.array((0..<128).map { .unsigned(UInt64($0)) })
        XCTAssertEqual(try StrictCBOR.decode(StrictCBOR.encode(protocolMaximum)), protocolMaximum)

        for count in [129, 1_024] {
            let entries = CBORValue.array((0..<count).map { .unsigned(UInt64($0)) })
            let encoded = try StrictCBOR.encode(entries)
            XCTAssertThrowsError(try StrictCBOR.decode(encoded, maximumBytes: 1_048_576))
            XCTAssertEqual(
                try StrictCBOR.decode(
                    encoded,
                    maximumBytes: 1_048_576,
                    maximumArrayElements: 1_024
                ),
                entries
            )
        }

        let overflow = CBORValue.array((0...1_024).map { .unsigned(UInt64($0)) })
        XCTAssertThrowsError(try StrictCBOR.decode(
            StrictCBOR.encode(overflow),
            maximumBytes: 1_048_576,
            maximumArrayElements: 1_024
        ))
    }

    func testQRFramesReassembleOutOfOrderAndRejectConflict() throws {
        let message = Data((0..<1_300).map { UInt8($0 % 251) })
        let frames = try QRFraming.fragment(message, chunkBytes: 400)
        let assembler = QRReassembler()
        var completed: Data?
        for frame in frames.reversed() {
            if case .complete(let value) = try assembler.push(frame, nowMilliseconds: 10) {
                completed = value
            }
        }
        XCTAssertEqual(completed, message)

        let conflictAssembler = QRReassembler()
        _ = try conflictAssembler.push(frames[0], nowMilliseconds: 20)
        var frame = try QRFraming.decode(frames[0])
        frame = QRFrame(
            transferId: frame.transferId,
            digest: frame.digest,
            index: frame.index,
            count: frame.count,
            totalLength: frame.totalLength,
            chunk: Data(repeating: 0xaa, count: frame.chunk.count)
        )
        XCTAssertThrowsError(try conflictAssembler.push(QRFraming.encode(frame), nowMilliseconds: 21))
    }

    func testRecipientEncodingHasExpectedPrefix() throws {
        let compact = try XCTUnwrap(Data(base64Encoded: "A2sX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW"))
        let key = try P256.KeyAgreement.PublicKey(compressedRepresentation: compact)
        XCTAssertEqual(
            try RecipientEncoding.encode(key),
            "age1phone1qypkk9737tsjcsj8lz7wdetr53q0yacr0kqjm6en5r62zw29mzvv99sa27n9c"
        )
    }

    func testQRAssemblyTimeoutPoisonsTransfer() throws {
        let frames = try QRFraming.fragment(Data(repeating: 7, count: 700), chunkBytes: 400)
        let assembler = QRReassembler()
        _ = try assembler.push(frames[0], nowMilliseconds: 1)
        XCTAssertThrowsError(try assembler.push(frames[1], nowMilliseconds: 30_002))
        XCTAssertThrowsError(try assembler.push(frames[1], nowMilliseconds: 30_003))
    }
}
