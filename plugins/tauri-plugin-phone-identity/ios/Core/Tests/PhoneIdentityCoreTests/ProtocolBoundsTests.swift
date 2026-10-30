import Foundation
import XCTest
@testable import PhoneIdentityCore

final class ProtocolBoundsTests: XCTestCase {
    private func cases() throws -> [String: Any] {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<7 { root.deleteLastPathComponent() }
        return try JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("crates/core/test-vectors/protocol-boundaries-v2.json"))) as! [String: Any]
    }

    func testSharedTimeCases() throws {
        let fixture = try cases()
        for c in fixture["time_cases"] as! [[String: Any]] {
            var accepted = false
            if let now = UInt64(c["now"] as! String), let expires = UInt64(c["expires"] as! String) {
                accepted = (try? ProtocolBounds.validateTime(expires: expires, now: now)) != nil
            }
            XCTAssertEqual(accepted, c["accept"] as! Bool, c["name"] as! String)
        }
        for c in fixture["creation_cases"] as! [[String: Any]] {
            let accepted = UInt64(c["now"] as! String).flatMap { try? ProtocolBounds.requestExpiry(now: $0) } != nil
            XCTAssertEqual(accepted, c["accept"] as! Bool)
        }
    }

    func testMalformedAndSizeBoundaries() throws {
        for text in try cases()["invalid_cbor_hex"] as! [String] {
            let chars = Array(text)
            let bytes = Data(stride(from: 0, to: chars.count, by: 2).map { UInt8(String(chars[$0...$0+1]), radix: 16)! })
            XCTAssertThrowsError(try ProtocolBounds.decodeEnvelope(bytes))
        }
        for size in [65536, 65537] {
            let encoded = try StrictCBOR.encode(.array([.bytes(Data(repeating: 0, count: size - 70)), .bytes(Data(repeating: 0, count: 64))]))
            XCTAssertEqual(encoded.count, size)
            if size == 65536 { XCTAssertNoThrow(try ProtocolBounds.decodeEnvelope(encoded)) }
            else { XCTAssertThrowsError(try ProtocolBounds.decodeEnvelope(encoded)) }
        }
        XCTAssertThrowsError(try ProtocolBounds.decodeEnvelope(Data(repeating: 0x81, count: 2000) + Data([0])))
    }
}
