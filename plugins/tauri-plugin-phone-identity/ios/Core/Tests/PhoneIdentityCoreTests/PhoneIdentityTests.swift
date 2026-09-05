import CryptoKit
import XCTest
@testable import PhoneIdentityCore

final class PhoneIdentityTests: XCTestCase {
    func testCanonicalCBORRoundTripAndRejectsNonCanonicalInteger() throws {
        let value = CBORValue.array([.unsigned(2), .text("phone"), .bytes(Data([1, 2, 3])), .null])
        let encoded = try StrictCBOR.encode(value)
        XCTAssertEqual(try StrictCBOR.decode(encoded), value)
        XCTAssertThrowsError(try StrictCBOR.decode(Data([0x18, 0x01])))
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
