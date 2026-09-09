// M0 research executable only. No product state, Keychain items, or phone keys.
// Build explicitly with swiftc; never run by ordinary Cargo tests.
import CryptoKit
import Darwin
import Foundation
import Security

enum ProbeError: String, Error {
    case arguments, directory, storage, missing, exists, malformed, binding, crypto
}
var stage = "arguments"
let names = ["signing.ref", "selection.ref", "binding"]

func directory(_ path: String) throws -> Int32 {
    let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw ProbeError.directory }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_uid == getuid(),
          info.st_mode & 0o077 == 0 else {
        close(fd); throw ProbeError.directory
    }
    // This is an isolated test directory, not an M2 ancestor/ACL implementation.
    return fd
}

func read(_ root: Int32, _ name: String) throws -> Data {
    let fd = openat(root, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else { throw errno == ENOENT ? ProbeError.missing : ProbeError.storage }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_nlink == 1,
          info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o077 == 0,
          info.st_size > 0, info.st_size <= 8192 else { throw ProbeError.malformed }
    var data = Data(count: Int(info.st_size))
    let count = data.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
    guard count == data.count else { throw ProbeError.storage }
    var tail: UInt8 = 0
    guard Darwin.read(fd, &tail, 1) == 0 else { throw ProbeError.storage }
    return data
}

func write(_ root: Int32, _ name: String, _ data: Data) throws {
    let fd = openat(root, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard fd >= 0 else { throw errno == EEXIST ? ProbeError.exists : ProbeError.storage }
    defer { close(fd) }
    let count = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
    guard count == data.count, fsync(fd) == 0, fsync(root) == 0 else { throw ProbeError.storage }
}

func requireEmpty(_ root: Int32) throws {
    for name in names {
        var info = stat()
        if fstatat(root, name, &info, AT_SYMLINK_NOFOLLOW) == 0 { throw ProbeError.exists }
        guard errno == ENOENT else { throw ProbeError.storage }
    }
}

func control() throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    guard let value = SecAccessControlCreateWithFlags(nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &error) else {
        throw ProbeError.crypto
    }
    return value
}

func compressed(_ x963: Data) throws -> Data {
    guard x963.count == 65, x963.first == 4 else { throw ProbeError.malformed }
    return Data([2 | (x963[64] & 1)]) + x963[1...32]
}

func binding(_ signing: SecureEnclave.P256.Signing.PrivateKey,
             _ selection: SecureEnclave.P256.KeyAgreement.PrivateKey) throws -> Data {
    let first = try compressed(signing.publicKey.x963Representation)
    let second = try compressed(selection.publicKey.x963Representation)
    guard first != second else { throw ProbeError.binding }
    return Data(SHA256.hash(data: first + second))
}

func create(_ root: Int32) throws {
    try requireEmpty(root)
    stage = "create_signing"
    let signing = try SecureEnclave.P256.Signing.PrivateKey(accessControl: control())
    stage = "create_selection"
    let selection = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: control())
    stage = "persist"
    // Opaque hardware-wrapped references, NOT exportable software private scalars.
    // Partial state is left intact on error; explicit isolated-directory cleanup only.
    try write(root, names[0], signing.dataRepresentation)
    try write(root, names[1], selection.dataRepresentation)
    try write(root, names[2], binding(signing, selection))
}

func verify(_ root: Int32) throws {
    stage = "reopen_signing"
    let signing = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: read(root, names[0]))
    stage = "reopen_selection"
    let selection = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: read(root, names[1]))
    stage = "binding"
    let publicBinding = try binding(signing, selection)
    guard try read(root, names[2]) == publicBinding else { throw ProbeError.binding }
    stage = "sign"
    let digest = SHA256.hash(data: Data("age-plugin-phone M0 synthetic digest".utf8))
    let signature = try signing.signature(for: digest)
    guard signing.publicKey.isValidSignature(signature, for: digest),
          !signing.publicKey.isValidSignature(signature, for: SHA256.hash(data: Data())) else {
        throw ProbeError.crypto
    }
    stage = "ecdh"
    // Public, fixed synthetic peer only. Never a long-term identity or file key.
    let peer = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32))
    let native = try selection.sharedSecretFromKeyAgreement(with: peer.publicKey)
    let reference = try peer.sharedSecretFromKeyAgreement(with: selection.publicKey)
    guard native == reference else { throw ProbeError.crypto }
    let resultHash = native.withUnsafeBytes { Data(SHA256.hash(data: $0)) }
    // Only public verification material and a digest of the synthetic ECDH result.
    // Never serialize either wrapped reference, a private scalar or the shared result.
    let report: [String: String] = [
        "public_binding": publicBinding.base64EncodedString(),
        "signing_public": try compressed(signing.publicKey.x963Representation).base64EncodedString(),
        "selection_public": try compressed(selection.publicKey.x963Representation).base64EncodedString(),
        "signature_der": signature.derRepresentation.base64EncodedString(),
        "synthetic_ecdh_sha256": resultHash.base64EncodedString(),
    ]
    let encoded = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
    FileHandle.standardOutput.write(encoded + Data([10]))
}

// Lock-session measurements test both roles independently, including handles opened
// before locking. Only public-key digests and coarse outcomes leave this process.
func observe(_ root: Int32,
             heldSigning: SecureEnclave.P256.Signing.PrivateKey? = nil,
             heldSelection: SecureEnclave.P256.KeyAgreement.PrivateKey? = nil) throws {
    func operation(_ body: () throws -> Data) -> [String: String] {
        do {
            return ["outcome": "success", "public_key_sha256": try body().base64EncodedString()]
        } catch {
            let category = (error as? ProbeError)?.rawValue ?? "native_code_\((error as NSError).code)"
            return ["outcome": "error", "category": category]
        }
    }
    let signing = operation {
        let key = try heldSigning ?? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: read(root, names[0]))
        let digest = SHA256.hash(data: Data("age-plugin-phone M0 synthetic digest".utf8))
        let signature = try key.signature(for: digest)
        guard key.publicKey.isValidSignature(signature, for: digest) else { throw ProbeError.crypto }
        return Data(SHA256.hash(data: try compressed(key.publicKey.x963Representation)))
    }
    let selection = operation {
        let key = try heldSelection ?? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: read(root, names[1]))
        let peer = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32))
        let native = try key.sharedSecretFromKeyAgreement(with: peer.publicKey)
        let reference = try peer.sharedSecretFromKeyAgreement(with: key.publicKey)
        guard native == reference else { throw ProbeError.crypto }
        return Data(SHA256.hash(data: try compressed(key.publicKey.x963Representation)))
    }
    let encoded = try JSONSerialization.data(withJSONObject: ["signing": signing, "selection": selection], options: [.sortedKeys])
    FileHandle.standardOutput.write(encoded + Data([10]))
}

func hold(_ root: Int32) throws {
    stage = "hold_open"
    let signing = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: read(root, names[0]))
    let selection = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: read(root, names[1]))
    guard try binding(signing, selection) == read(root, names[2]) else { throw ProbeError.binding }
    FileHandle.standardOutput.write(Data("{\"ready\":true}\n".utf8))
    while let input = readLine() {
        if input == "quit" { return }
        guard input == "sample" else { throw ProbeError.arguments }
        try observe(root, heldSigning: signing, heldSelection: selection)
    }
}

func probeMain(_ args: [String]) -> Int32 {
do {
    guard args.count == 3, ["create", "verify", "observe", "hold"].contains(args[1]) else { throw ProbeError.arguments }
    let root = try directory(args[2])
    defer { close(root) }
    stage = "capability"
    guard SecureEnclave.isAvailable else { throw ProbeError.crypto }
    if args[1] == "observe" { try observe(root); return 0 }
    if args[1] == "hold" { try hold(root); return 0 }
    if args[1] == "create" { try create(root) }
    try verify(root)
    return 0
} catch {
    // Native localized descriptions may contain untrusted data; emit codes only.
    let category = (error as? ProbeError)?.rawValue ?? "native_code_\((error as NSError).code)"
    FileHandle.standardError.write(Data("FAIL \(stage):\(category)\n".utf8))
    return 1
}
}

// A deliberately narrow experimental C ABI: no keys, blobs or shared secrets cross it.
@_cdecl("age_phone_m0_cryptokit_probe")
public func probeEntry(_ argc: Int32, _ argv: UnsafePointer<UnsafePointer<CChar>?>?) -> Int32 {
    guard argc == 3, let argv else { return 1 }
    var args: [String] = []
    for index in 0..<Int(argc) {
        guard let value = argv[index], let text = String(validatingCString: value) else { return 1 }
        args.append(text)
    }
    return probeMain(args)
}
