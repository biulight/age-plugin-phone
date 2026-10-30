#!/usr/bin/env python3
"""Compile production Swift envelope code with public-fixture metadata; no hardware operations."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
IOS = ROOT / "plugins/tauri-plugin-phone-identity/ios"
HARNESS = r'''import CryptoKit
import Foundation

// Only metadata is substituted. All parsing, verification and bounds are production code.
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
        func b64(_ text: String) -> Data {
            Data(base64Encoded: text + String(repeating: "=", count: (4 - text.count % 4) % 4))!
        }
        let vector = try json("offline-envelope-v2.json")
        let cases = try json("protocol-boundaries-v2.json")
        let original = b64(vector["signed_request_base64"] as! String)
        let (payload, _) = try ProtocolBounds.decodeEnvelope(original)
        let fields = try StrictCBOR.decode(payload).exactArray(11)
        let scalar = vector["desktop_signing_scalar"] as! Int
        let key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0, count: 31) + Data([UInt8(scalar)]))
        func verify(_ data: Data, _ now: UInt64) throws {
            _ = try OfflineEnvelopeCrypto.verifyRequest(data,
                desktopId: try fields[5].exactBytes(16), identityId: try fields[4].exactBytes(16),
                desktopSigningKey: key.publicKey, nowUnix: now)
        }
        for c in cases["time_cases"] as! [[String: Any]] {
            guard let now = UInt64(c["now"] as! String), let expires = UInt64(c["expires"] as! String) else { continue }
            var changed = fields; changed[9] = .unsigned(expires)
            let bytes = try StrictCBOR.encode(.array(changed))
            let signature = try OfflineEnvelopeCrypto.lowSSignature(key.signature(for: Data("age-plugin-phone/unwrap-request-signature/v2".utf8) + Data([0]) + bytes).rawRepresentation)
            let signed = try StrictCBOR.encode(.array([.bytes(bytes), .bytes(signature)]))
            var accepted = false
            do { try verify(signed, now); accepted = true } catch { }
            precondition(accepted == c["accept"] as! Bool, c["name"] as! String)
        }
        // Untrusted routing rejects invalid time types/range before private state lookup.
        for expiry in [CBORValue.text("1000300"), .unsigned(UInt64(Int64.max) + 1)] {
            var changed = fields; changed[9] = expiry
            let signed = try StrictCBOR.encode(.array([.bytes(try StrictCBOR.encode(.array(changed))), .bytes(Data(repeating: 0, count: 64))]))
            var rejected = false
            do { _ = try OfflineEnvelopeCrypto.requestScope(signed) } catch { rejected = true }
            precondition(rejected)
        }
        // StrictCBOR intentionally cannot construct negative values; inject canonical -1.
        var zeroTime = fields; zeroTime[9] = .unsigned(0); zeroTime[10] = .null
        var negativePayload = try StrictCBOR.encode(.array(zeroTime))
        precondition(negativePayload.suffix(2) == Data([0, 0xf6]))
        negativePayload.removeLast(2); negativePayload.append(contentsOf: [0x20, 0xf6])
        let negativeRequest = try StrictCBOR.encode(.array([.bytes(negativePayload), .bytes(Data(repeating: 0, count: 64))]))
        var negativeRejected = false
        do { _ = try OfflineEnvelopeCrypto.requestScope(negativeRequest) } catch { negativeRejected = true }
        precondition(negativeRejected)
        for text in cases["invalid_cbor_hex"] as! [String] {
            let chars = Array(text)
            let bytes = Data(stride(from: 0, to: chars.count, by: 2).map { UInt8(String(chars[$0...$0+1]), radix: 16)! })
            var rejected = false
            do { _ = try OfflineEnvelopeCrypto.requestScope(bytes) } catch { rejected = true }
            precondition(rejected)
            var pairingRejected = false
            do { _ = try OfflineEnvelopeCrypto.verifyPairingOffer(bytes) } catch { pairingRejected = true }
            precondition(pairingRejected)
        }
        for size in [65536, 65537] {
            let bytes = try StrictCBOR.encode(.array([.bytes(Data(repeating: 0, count: size - 70)), .bytes(Data(repeating: 0, count: 64))]))
            var rejected = false
            do { _ = try OfflineEnvelopeCrypto.requestScope(bytes) } catch { rejected = true }
            precondition(rejected)
        }
        // A malformed attempt must not alter verification of a later valid fixture.
        try verify(original, 1_000_000)
        print("Swift production request boundary checks passed")
    }
}
'''

def run(source: str) -> None:
    with tempfile.TemporaryDirectory(prefix="phone-ios-protocol-") as temporary:
        work = Path(temporary)
        sources = list((IOS / "Core/Sources/PhoneIdentityCore").glob("*.swift"))
        for name in ["OfflineEnvelopeCrypto.swift", "TaggedRecipientCrypto.swift"]:
            target = work / name
            target.write_text((IOS / "Sources" / name).read_text().replace("import PhoneIdentityCore\n", ""))
            sources.append(target)
        harness = work / "Harness.swift"
        harness.write_text(source)
        executable = work / "protocol-boundaries"
        subprocess.run(["swiftc", "-package-name", "PhoneIdentityCore", "-module-cache-path",
                        str(work / "module-cache"), *map(str, sources), str(harness),
                        "-o", str(executable)], check=True)
        subprocess.run([str(executable), str(ROOT / "crates/core/test-vectors")], check=True)

if __name__ == "__main__":
    run(HARNESS)
