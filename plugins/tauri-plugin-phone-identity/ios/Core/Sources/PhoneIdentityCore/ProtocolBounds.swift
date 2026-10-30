import Foundation

/// Protocol bounds are independent of transport and persistent-storage limits.
package enum ProtocolBounds {
    package static let maximumTime = UInt64(Int64.max)
    package static let maximumMessageBytes = 65_536

    package static func validateTimestamp(_ value: UInt64) throws {
        guard value <= maximumTime else { throw StrictCBORError.limit }
    }

    package static func validateTime(expires: UInt64, now: UInt64) throws {
        try validateTimestamp(expires)
        try validateTimestamp(now)
        guard expires >= now, expires - now <= 300 else { throw StrictCBORError.limit }
    }

    package static func requestExpiry(now: UInt64) throws -> UInt64 {
        guard now <= maximumTime - 300 else { throw StrictCBORError.limit }
        return now + 300
    }

    package static func decodeEnvelope(_ encoded: Data) throws -> (Data, Data) {
        // StrictCBOR checks size before parsing or copying fields. Its storage callers
        // retain their independent explicit maximumBytes/maximumArrayElements.
        let values = try StrictCBOR.decode(encoded, maximumBytes: maximumMessageBytes).exactArray(2)
        return (try values[0].exactBytes(), try values[1].exactBytes(64))
    }
}
