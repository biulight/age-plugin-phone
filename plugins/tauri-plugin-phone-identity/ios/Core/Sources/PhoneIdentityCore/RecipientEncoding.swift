import CryptoKit
import Foundation

package enum RecipientEncodingError: Error { case invalidKey, invalidEncoding }

package enum RecipientEncoding {
    private static let hrp = "age1phone"
    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
    private static let generators: [UInt32] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

    package static func compressed(_ key: P256.KeyAgreement.PublicKey) throws -> Data {
        let x963 = key.x963Representation
        guard x963.count == 65, x963[0] == 4 else {
            throw RecipientEncodingError.invalidKey
        }
        return Data([x963[64] & 1 == 0 ? 2 : 3]) + x963[1..<33]
    }

    package static func encode(_ key: P256.KeyAgreement.PublicKey) throws -> String {
        let payload = Data([1]) + (try compressed(key))
        let words = try convertBits(Array(payload), from: 8, to: 5, pad: true)
        let checksumValue = polymod(hrpExpand(hrp) + words + Array(repeating: 0, count: 6)) ^ 1
        let checksum = (0..<6).map { UInt8((checksumValue >> UInt32(5 * (5 - $0))) & 31) }
        return hrp + "1" + String((words + checksum).map { charset[Int($0)] })
    }

    private static func hrpExpand(_ value: String) -> [UInt8] {
        value.utf8.map { $0 >> 5 } + [0] + value.utf8.map { $0 & 31 }
    }

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        var checksum: UInt32 = 1
        for value in values {
            let top = checksum >> 25
            checksum = ((checksum & 0x01ff_ffff) << 5) ^ UInt32(value)
            for index in generators.indices where ((top >> UInt32(index)) & 1) != 0 {
                checksum ^= generators[index]
            }
        }
        return checksum
    }

    private static func convertBits(
        _ values: [UInt8], from: Int, to: Int, pad: Bool
    ) throws -> [UInt8] {
        var output: [UInt8] = []
        var accumulator = 0
        var bits = 0
        let maximumValue = (1 << to) - 1
        let maximumAccumulator = (1 << (from + to - 1)) - 1
        for byte in values {
            let value = Int(byte)
            guard value >> from == 0 else { throw RecipientEncodingError.invalidEncoding }
            accumulator = ((accumulator << from) | value) & maximumAccumulator
            bits += from
            while bits >= to {
                bits -= to
                output.append(UInt8((accumulator >> bits) & maximumValue))
            }
        }
        if pad, bits > 0 {
            output.append(UInt8((accumulator << (to - bits)) & maximumValue))
        } else if !pad && (bits >= from || ((accumulator << (to - bits)) & maximumValue) != 0) {
            throw RecipientEncodingError.invalidEncoding
        }
        return output
    }
}
