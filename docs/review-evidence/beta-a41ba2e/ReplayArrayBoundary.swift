import Foundation

@main
struct ReplayArrayBoundary {
    static func main() throws {
        for count in [128, 129, 1024] {
            let entries: [CBORValue] = (0..<count).map { index in
                var id = Data(repeating: 0, count: 16)
                id[14] = UInt8(index >> 8); id[15] = UInt8(index & 255)
                return .array([.bytes(id), .bytes(id + id), .unsigned(1300)])
            }
            // Same 14-field layout, replay capacity and encoder used by PairingStateStore.
            let state = CBORValue.array([
                .unsigned(2), .bytes(Data(repeating: 1, count: 16)),
                .bytes(Data(repeating: 2, count: 16)), .text("synthetic"), .text("synthetic"),
                .bytes(Data(repeating: 3, count: 33)), .bytes(Data(repeating: 4, count: 33)),
                .bytes(Data(repeating: 5, count: 33)), .bytes(Data(repeating: 6, count: 32)),
                .bytes(Data(repeating: 7, count: 32)), .unsigned(1000), .unsigned(1000),
                .unsigned(1024), .array(entries)
            ])
            let encoded = try StrictCBOR.encode(state)
            do {
                _ = try StrictCBOR.decode(encoded, maximumBytes: 1_048_576)
                print("entries=\(count) encoded=\(encoded.count) decode=accepted")
            } catch {
                print("entries=\(count) encoded=\(encoded.count) decode=rejected: \(error)")
            }
        }
    }
}
