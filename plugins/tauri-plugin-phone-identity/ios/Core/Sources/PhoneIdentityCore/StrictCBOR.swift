import Foundation

package enum CBORValue: Equatable {
    case unsigned(UInt64)
    case bytes(Data)
    case text(String)
    case array([CBORValue])
    case null
}

package enum StrictCBORError: Error { case malformed, unsupported, nonCanonical, limit }

package enum StrictCBOR {
    package static func encode(_ value: CBORValue) throws -> Data {
        var output = Data()
        try append(value, to: &output)
        return output
    }

    package static func decode(_ data: Data, maximumBytes: Int = 65_536) throws -> CBORValue {
        guard !data.isEmpty, data.count <= maximumBytes else { throw StrictCBORError.limit }
        var offset = 0
        let value = try parse(data, offset: &offset, depth: 0)
        guard offset == data.count, try encode(value) == data else {
            throw StrictCBORError.nonCanonical
        }
        return value
    }

    private static func append(_ value: CBORValue, to output: inout Data) throws {
        switch value {
        case .unsigned(let number): appendHeader(major: 0, value: number, to: &output)
        case .bytes(let bytes):
            appendHeader(major: 2, value: UInt64(bytes.count), to: &output)
            output.append(bytes)
        case .text(let text):
            guard let data = text.data(using: .utf8) else { throw StrictCBORError.malformed }
            appendHeader(major: 3, value: UInt64(data.count), to: &output)
            output.append(data)
        case .array(let values):
            appendHeader(major: 4, value: UInt64(values.count), to: &output)
            for item in values { try append(item, to: &output) }
        case .null: output.append(0xf6)
        }
    }

    private static func appendHeader(major: UInt8, value: UInt64, to output: inout Data) {
        let prefix = major << 5
        switch value {
        case 0...23: output.append(prefix | UInt8(value))
        case 24...0xff:
            output.append(prefix | 24); output.append(UInt8(value))
        case 0x100...0xffff:
            output.append(prefix | 25); appendBigEndian(UInt16(value), to: &output)
        case 0x1_0000...0xffff_ffff:
            output.append(prefix | 26); appendBigEndian(UInt32(value), to: &output)
        default:
            output.append(prefix | 27); appendBigEndian(value, to: &output)
        }
    }

    private static func appendBigEndian<T: FixedWidthInteger>(_ value: T, to output: inout Data) {
        var big = value.bigEndian
        withUnsafeBytes(of: &big) { output.append(contentsOf: $0) }
    }

    private static func parse(_ data: Data, offset: inout Int, depth: Int) throws -> CBORValue {
        guard depth <= 16, offset < data.count else { throw StrictCBORError.limit }
        let initial = data[offset]; offset += 1
        let major = initial >> 5
        let additional = initial & 31
        if major == 7, additional == 22 { return .null }
        guard major <= 4 else { throw StrictCBORError.unsupported }
        let length = try readLength(additional, data: data, offset: &offset)
        switch major {
        case 0: return .unsigned(length)
        case 2:
            guard length <= UInt64(data.count - offset) else { throw StrictCBORError.malformed }
            let end = offset + Int(length)
            let value = Data(data[offset..<end]); offset = end
            return .bytes(value)
        case 3:
            guard length <= UInt64(data.count - offset) else { throw StrictCBORError.malformed }
            let end = offset + Int(length)
            let bytes = Data(data[offset..<end]); offset = end
            guard let value = String(data: bytes, encoding: .utf8), value.data(using: .utf8) == bytes else {
                throw StrictCBORError.malformed
            }
            return .text(value)
        case 4:
            guard length <= 128 else { throw StrictCBORError.limit }
            var values: [CBORValue] = []
            values.reserveCapacity(Int(length))
            for _ in 0..<length { values.append(try parse(data, offset: &offset, depth: depth + 1)) }
            return .array(values)
        default: throw StrictCBORError.unsupported
        }
    }

    private static func readLength(_ additional: UInt8, data: Data, offset: inout Int) throws -> UInt64 {
        switch additional {
        case 0...23: return UInt64(additional)
        case 24:
            let value: UInt8 = try read(data, offset: &offset)
            guard value >= 24 else { throw StrictCBORError.nonCanonical }
            return UInt64(value)
        case 25:
            let value: UInt16 = try read(data, offset: &offset)
            guard value > 0xff else { throw StrictCBORError.nonCanonical }
            return UInt64(value)
        case 26:
            let value: UInt32 = try read(data, offset: &offset)
            guard value > 0xffff else { throw StrictCBORError.nonCanonical }
            return UInt64(value)
        case 27:
            let value: UInt64 = try read(data, offset: &offset)
            guard value > 0xffff_ffff else { throw StrictCBORError.nonCanonical }
            return value
        default: throw StrictCBORError.unsupported
        }
    }

    private static func read<T: FixedWidthInteger>(_ data: Data, offset: inout Int) throws -> T {
        let count = MemoryLayout<T>.size
        guard offset + count <= data.count else { throw StrictCBORError.malformed }
        var value: T = 0
        for byte in data[offset..<(offset + count)] { value = (value << 8) | T(byte) }
        offset += count
        return value
    }
}

package extension CBORValue {
    func exactArray(_ count: Int) throws -> [CBORValue] {
        guard case .array(let values) = self, values.count == count else { throw StrictCBORError.malformed }
        return values
    }
    func exactBytes(_ count: Int? = nil) throws -> Data {
        guard case .bytes(let value) = self, count == nil || value.count == count else { throw StrictCBORError.malformed }
        return value
    }
    func boundedText(_ maximumUTF8Bytes: Int) throws -> String {
        guard case .text(let value) = self, value.utf8.count <= maximumUTF8Bytes else { throw StrictCBORError.malformed }
        return value
    }
    func exactUnsigned() throws -> UInt64 {
        guard case .unsigned(let value) = self else { throw StrictCBORError.malformed }
        return value
    }
}
