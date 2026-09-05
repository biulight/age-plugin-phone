import CryptoKit
import Foundation

package enum QRFramingError: Error {
    case chunkSize, clockRollback, conflictingFragment, differentTransfer, digestMismatch
    case malformedFrame, messageSize, poisoned, timeout, tooManyFragments, unsupportedType, unsupportedVersion

    package var category: String {
        switch self {
        case .chunkSize: return "chunk_size"
        case .clockRollback: return "clock_rollback"
        case .conflictingFragment: return "conflicting_fragment"
        case .differentTransfer: return "different_transfer"
        case .digestMismatch: return "digest_mismatch"
        case .malformedFrame: return "malformed_frame"
        case .messageSize: return "message_size"
        case .poisoned: return "poisoned"
        case .timeout: return "timeout"
        case .tooManyFragments: return "too_many_fragments"
        case .unsupportedType: return "unsupported_type"
        case .unsupportedVersion: return "unsupported_version"
        }
    }
}

package struct QRFrame {
    package let transferId: Data
    package let digest: Data
    package let index: Int
    package let count: Int
    package let totalLength: Int
    package let chunk: Data

    package init(transferId: Data, digest: Data, index: Int, count: Int, totalLength: Int, chunk: Data) {
        self.transferId = transferId; self.digest = digest; self.index = index
        self.count = count; self.totalLength = totalLength; self.chunk = chunk
    }
}

package enum QRFraming {
    package static let prefix = "age-phone:qr1:"
    package static let defaultChunkBytes = 600
    package static let maximumMessageBytes = 65_536
    package static let maximumFragments = 128
    package static let maximumAssemblyAgeMilliseconds: Int64 = 30_000
    private static let digestDomain = Data("age-plugin-phone/qr-message-digest/v1".utf8)

    package static func isCandidate(_ value: String) -> Bool { value.hasPrefix(prefix) }

    package static func fragment(_ message: Data, chunkBytes: Int = defaultChunkBytes) throws -> [String] {
        guard !message.isEmpty, message.count <= maximumMessageBytes else { throw QRFramingError.messageSize }
        guard (1...defaultChunkBytes).contains(chunkBytes) else { throw QRFramingError.chunkSize }
        let count = (message.count + chunkBytes - 1) / chunkBytes
        guard count <= maximumFragments else { throw QRFramingError.tooManyFragments }
        var transfer = Data(count: 16)
        guard transfer.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }) == errSecSuccess else {
            throw QRFramingError.malformedFrame
        }
        let digest = messageDigest(message)
        return try (0..<count).map { index in
            let start = index * chunkBytes, end = min(start + chunkBytes, message.count)
            return try encode(QRFrame(
                transferId: transfer,
                digest: digest,
                index: index,
                count: count,
                totalLength: message.count,
                chunk: Data(message[start..<end])
            ))
        }
    }

    package static func encode(_ frame: QRFrame) throws -> String {
        let data = try StrictCBOR.encode(.array([
            .unsigned(1), .unsigned(1), .bytes(frame.transferId), .bytes(frame.digest),
            .unsigned(UInt64(frame.index)), .unsigned(UInt64(frame.count)),
            .unsigned(UInt64(frame.totalLength)), .bytes(frame.chunk)
        ]))
        let value = prefix + base64URL(data)
        guard value.count <= 2_048 else { throw QRFramingError.chunkSize }
        return value
    }

    package static func decode(_ value: String) throws -> QRFrame {
        guard value.count <= 2_048, value.hasPrefix(prefix) else { throw QRFramingError.malformedFrame }
        let encoded = String(value.dropFirst(prefix.count))
        guard !encoded.isEmpty, !encoded.contains("="), let data = decodeBase64URL(encoded), base64URL(data) == encoded else {
            throw QRFramingError.malformedFrame
        }
        let values = try StrictCBOR.decode(data).exactArray(8)
        guard try values[0].exactUnsigned() == 1 else { throw QRFramingError.unsupportedVersion }
        guard try values[1].exactUnsigned() == 1 else { throw QRFramingError.unsupportedType }
        let index = Int(try values[4].exactUnsigned()), count = Int(try values[5].exactUnsigned())
        let total = Int(try values[6].exactUnsigned()), chunk = try values[7].exactBytes()
        guard (1...maximumFragments).contains(count), (0..<count).contains(index),
              (1...maximumMessageBytes).contains(total), !chunk.isEmpty,
              chunk.count <= defaultChunkBytes, chunk.count <= total else { throw QRFramingError.malformedFrame }
        return QRFrame(
            transferId: try values[2].exactBytes(16),
            digest: try values[3].exactBytes(32),
            index: index,
            count: count,
            totalLength: total,
            chunk: chunk
        )
    }

    package static func messageDigest(_ message: Data) -> Data {
        Data(SHA256.hash(data: digestDomain + Data([0]) + message))
    }

    package static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    package static func decodeBase64URL(_ value: String) -> Data? {
        guard value.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else { return nil }
        var standard = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.count % 4) % 4)
        return Data(base64Encoded: standard)
    }
}

package enum QRAssemblyStatus { case inProgress(received: Int, total: Int), complete(Data) }

package final class QRReassembler {
    private var active: Active?
    private var poisoned = false

    package init() {}

    package func push(_ encoded: String, nowMilliseconds: Int64) throws -> QRAssemblyStatus {
        guard !poisoned else { throw QRFramingError.poisoned }
        guard nowMilliseconds >= 0 else { throw QRFramingError.clockRollback }
        let frame = try QRFraming.decode(encoded)
        if active == nil { active = Active(frame: frame, started: nowMilliseconds) }
        guard let current = active else { throw QRFramingError.malformedFrame }
        if nowMilliseconds < current.started { try poison(.clockRollback) }
        if nowMilliseconds - current.started > QRFraming.maximumAssemblyAgeMilliseconds { try poison(.timeout) }
        guard frame.transferId == current.transferId, frame.digest == current.digest,
              frame.count == current.count, frame.totalLength == current.totalLength else {
            throw QRFramingError.differentTransfer
        }
        if let existing = current.chunks[frame.index] {
            if existing != frame.chunk { try poison(.conflictingFragment) }
        } else {
            current.receivedBytes += frame.chunk.count
            if current.receivedBytes > current.totalLength { try poison(.malformedFrame) }
            current.chunks[frame.index] = frame.chunk
            current.received += 1
        }
        guard current.received == current.count else { return .inProgress(received: current.received, total: current.count) }
        guard let first = current.chunks.first ?? nil, !first.isEmpty,
              current.chunks.dropLast().allSatisfy({ $0?.count == first.count }),
              let last = current.chunks.last ?? nil, !last.isEmpty, last.count <= first.count else {
            try poison(.malformedFrame)
        }
        let message = current.chunks.compactMap { $0 }.reduce(into: Data()) { $0.append($1) }
        guard message.count == current.totalLength else { try poison(.malformedFrame) }
        guard QRFraming.messageDigest(message) == current.digest else { try poison(.digestMismatch) }
        active = nil
        return .complete(message)
    }

    package func reset() { active = nil; poisoned = false }

    private func poison(_ error: QRFramingError) throws -> Never {
        active = nil; poisoned = true; throw error
    }

    private final class Active {
        let transferId: Data, digest: Data, count: Int, totalLength: Int, started: Int64
        var chunks: [Data?], received = 0, receivedBytes = 0
        init(frame: QRFrame, started: Int64) {
            transferId = frame.transferId; digest = frame.digest; count = frame.count
            totalLength = frame.totalLength; self.started = started
            chunks = Array(repeating: nil, count: frame.count)
        }
    }
}
