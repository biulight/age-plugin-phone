import CryptoKit
import Foundation
import Security

// Synchronous, borrowed buffers only. No native error descriptions or key material are logged.
// CryptoKit accepts Digest directly: these bytes have ALREADY been hashed by the protocol.
private struct Prehash: Digest {
    static let byteCount = 32
    let bytes: [UInt8]
    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
    var description: String { "SHA256 prehash (redacted)" }
}
private enum Failure: Error { case invalid }
private func control() throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    guard let value = SecAccessControlCreateWithFlags(nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &error) else {
        throw Failure.invalid
    }
    return value
}
private func put(_ data: Data, _ output: UnsafeMutablePointer<UInt8>, _ capacity: Int,
                 _ length: UnsafeMutablePointer<Int>) throws {
    guard !data.isEmpty, data.count <= capacity else { throw Failure.invalid }
    data.copyBytes(to: output, count: data.count)
    length.pointee = data.count
}

// op: 0=create reference, 1=public x963, 2=sign prehash, 3=raw ECDH.
// role: 0=signing, 1=selection. References are hardware-encrypted, never raw scalars.
@_cdecl("age_phone_macos_key")
public func keyOperation(_ op: Int32, _ role: Int32,
    _ reference: UnsafePointer<UInt8>?, _ referenceLength: Int,
    _ input: UnsafePointer<UInt8>?, _ inputLength: Int,
    _ output: UnsafeMutablePointer<UInt8>?, _ capacity: Int,
    _ length: UnsafeMutablePointer<Int>?) -> Int32 {
    guard let output, let length, capacity > 0, capacity <= 4096 else { return 1 }
    length.pointee = 0
    do {
        guard SecureEnclave.isAvailable, role == 0 || role == 1,
              referenceLength >= 0, referenceLength <= 4096,
              inputLength >= 0, inputLength <= 65 else { throw Failure.invalid }
        if op == 0 {
            guard referenceLength == 0, inputLength == 0 else { throw Failure.invalid }
            let data: Data
            if role == 0 {
                data = try SecureEnclave.P256.Signing.PrivateKey(accessControl: control()).dataRepresentation
            } else {
                data = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: control()).dataRepresentation
            }
            try put(data, output, capacity, length)
            return 0
        }
        guard let reference, referenceLength > 0 else { throw Failure.invalid }
        let data = Data(bytes: reference, count: referenceLength)
        if role == 0 {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
            if op == 1 && inputLength == 0 {
                try put(key.publicKey.x963Representation, output, capacity, length)
            } else if op == 2, inputLength == 32, let input {
                let digest = Prehash(bytes: Array(UnsafeBufferPointer(start: input, count: 32)))
                try put(key.signature(for: digest).rawRepresentation, output, capacity, length)
            } else { throw Failure.invalid }
        } else {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data)
            if op == 1 && inputLength == 0 {
                try put(key.publicKey.x963Representation, output, capacity, length)
            } else if op == 3, inputLength == 65, let input {
                let peer = try P256.KeyAgreement.PublicKey(x963Representation: Data(bytes: input, count: 65))
                let secret = try key.sharedSecretFromKeyAgreement(with: peer)
                // Copy directly into Rust-owned Zeroizing storage, without a Data secret copy.
                try secret.withUnsafeBytes { bytes in
                    guard bytes.count == 32, capacity >= 32 else { throw Failure.invalid }
                    output.update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 32)
                    length.pointee = 32
                }
            } else { throw Failure.invalid }
        }
        return 0
    } catch {
        output.initialize(repeating: 0, count: capacity)
        length.pointee = 0
        return 1
    }
}
