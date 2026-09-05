import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import PhoneIdentityCore
import Security

enum IdentityStoreError: Error {
    case unsupported, alreadyExists, missing, deletionPending, malformed, storage, wrongKeyRole

    var category: String {
        switch self {
        case .unsupported: return "unsupported_api"
        case .alreadyExists: return "already_exists"
        case .missing: return "identity_missing"
        case .deletionPending: return "deletion_pending"
        case .malformed: return "malformed_state"
        case .storage: return "storage_unavailable"
        case .wrongKeyRole: return "wrong_key_role"
        }
    }
}

struct IdentityPublicMetadata: Codable {
    let version: UInt8
    let identityId: Data
    let recipient: String
    let identityPublicKey: Data
    let signingPublicKey: Data
    let state: String
}

final class IdentityKeyStore {
    static let shared = IdentityKeyStore(namespace: "production-v1")
    private let namespace: String
    private let service = "io.github.biulight.age-plugin-phone.identity"
    private let root: URL
    private let metadataURL: URL
    private let queue = DispatchQueue(label: "io.github.biulight.phone-identity.keys")

    init(namespace: String) {
        self.namespace = namespace
        let support = try! FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        root = support.appendingPathComponent("phone-identity", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.complete]
        )
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableRoot = root
        try? mutableRoot.setResourceValues(values)
        metadataURL = root.appendingPathComponent("identity-\(namespace).json")
    }

    func status() -> Result<IdentityPublicMetadata, IdentityStoreError> {
        queue.sync { Result { try openLocked() }.mapError(mapError) }
    }

    func provision() -> Result<IdentityPublicMetadata, IdentityStoreError> {
        queue.sync { Result { try provisionLocked() }.mapError(mapError) }
    }

    func beginDeletion() -> Result<IdentityPublicMetadata, IdentityStoreError> {
        queue.sync {
            Result {
                let current = try readMetadata()
                if current.state == "deleting" { return current }
                guard current.state == "committed" else { throw IdentityStoreError.malformed }
                let deleting = IdentityPublicMetadata(
                    version: current.version,
                    identityId: current.identityId,
                    recipient: current.recipient,
                    identityPublicKey: current.identityPublicKey,
                    signingPublicKey: current.signingPublicKey,
                    state: "deleting"
                )
                try writeMetadata(deleting, createOnly: false)
                return deleting
            }.mapError(mapError)
        }
    }

    func finishDeletion(_ metadata: IdentityPublicMetadata) -> Result<Void, IdentityStoreError> {
        queue.sync {
            Result {
                try deleteKey(account: identityAccount(metadata.identityId))
                try deleteKey(account: signingAccount(metadata.identityId))
                if FileManager.default.fileExists(atPath: metadataURL.path) {
                    try FileManager.default.removeItem(at: metadataURL)
                    try syncDirectory()
                }
            }.mapError(mapError)
        }
    }

    func freshIdentityKey(reason: String) throws -> (SecureEnclave.P256.KeyAgreement.PrivateKey, LAContext) {
        try queue.sync {
            let metadata = try openLocked()
            let context = LAContext()
            context.localizedReason = reason
            context.touchIDAuthenticationAllowableReuseDuration = 0
            let representation = try readKey(account: identityAccount(metadata.identityId))
            do {
                let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: representation,
                    authenticationContext: context
                )
                guard try RecipientEncoding.compressed(key.publicKey) == metadata.identityPublicKey else {
                    context.invalidate()
                    throw IdentityStoreError.malformed
                }
                return (key, context)
            } catch {
                context.invalidate()
                throw error
            }
        }
    }

    func signingKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        try queue.sync {
            let metadata = try openLocked()
            let representation = try readKey(account: signingAccount(metadata.identityId))
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: representation)
            guard try TaggedRecipientCrypto.compressedSigning(key.publicKey) == metadata.signingPublicKey else {
                throw IdentityStoreError.malformed
            }
            return key
        }
    }

    private func provisionLocked() throws -> IdentityPublicMetadata {
        guard SecureEnclave.isAvailable else { throw IdentityStoreError.unsupported }
        if FileManager.default.fileExists(atPath: metadataURL.path) {
            let existing = try readMetadata()
            if existing.state == "preparing" {
                try? deleteKey(account: identityAccount(existing.identityId))
                try? deleteKey(account: signingAccount(existing.identityId))
                try FileManager.default.removeItem(at: metadataURL)
            } else if existing.state == "deleting" {
                throw IdentityStoreError.deletionPending
            } else {
                throw IdentityStoreError.alreadyExists
            }
        }

        var identityId = Data(count: 16)
        let randomStatus = identityId.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
        }
        guard randomStatus == errSecSuccess else { throw IdentityStoreError.storage }
        let preparing = IdentityPublicMetadata(
            version: 1,
            identityId: identityId,
            recipient: "",
            identityPublicKey: Data(),
            signingPublicKey: Data(),
            state: "preparing"
        )
        try writeMetadata(preparing, createOnly: true)

        do {
            let identityControl = try accessControl(flags: [.privateKeyUsage, .biometryCurrentSet])
            let signingControl = try accessControl(flags: [.privateKeyUsage])
            let identity = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                compactRepresentable: true,
                accessControl: identityControl
            )
            let signing = try SecureEnclave.P256.Signing.PrivateKey(
                compactRepresentable: true,
                accessControl: signingControl
            )
            let identityPublic = try RecipientEncoding.compressed(identity.publicKey)
            let signingPublic = try TaggedRecipientCrypto.compressedSigning(signing.publicKey)
            guard signingPublic.count == 33, identityPublic != signingPublic else {
                throw IdentityStoreError.wrongKeyRole
            }
            try storeKey(identity.dataRepresentation, account: identityAccount(identityId))
            try storeKey(signing.dataRepresentation, account: signingAccount(identityId))
            let committed = IdentityPublicMetadata(
                version: 1,
                identityId: identityId,
                recipient: try RecipientEncoding.encode(identity.publicKey),
                identityPublicKey: identityPublic,
                signingPublicKey: signingPublic,
                state: "committed"
            )
            try writeMetadata(committed, createOnly: false)
            return committed
        } catch {
            try? deleteKey(account: identityAccount(identityId))
            try? deleteKey(account: signingAccount(identityId))
            try? FileManager.default.removeItem(at: metadataURL)
            throw error
        }
    }

    private func openLocked() throws -> IdentityPublicMetadata {
        guard SecureEnclave.isAvailable else { throw IdentityStoreError.unsupported }
        let metadata = try readMetadata()
        if metadata.state == "deleting" { throw IdentityStoreError.deletionPending }
        guard metadata.version == 1, metadata.state == "committed", metadata.identityId.count == 16,
              metadata.identityPublicKey.count == 33, metadata.signingPublicKey.count == 33,
              metadata.identityPublicKey != metadata.signingPublicKey else {
            throw IdentityStoreError.malformed
        }
        let identity = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: readKey(account: identityAccount(metadata.identityId))
        )
        let signing = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: readKey(account: signingAccount(metadata.identityId))
        )
        guard try RecipientEncoding.compressed(identity.publicKey) == metadata.identityPublicKey,
              try TaggedRecipientCrypto.compressedSigning(signing.publicKey) == metadata.signingPublicKey,
              try RecipientEncoding.encode(identity.publicKey) == metadata.recipient else {
            throw IdentityStoreError.malformed
        }
        return metadata
    }

    private func readMetadata() throws -> IdentityPublicMetadata {
        guard FileManager.default.fileExists(atPath: metadataURL.path) else {
            throw IdentityStoreError.missing
        }
        let data = try Data(contentsOf: metadataURL, options: [.mappedIfSafe])
        guard data.count <= 4096 else { throw IdentityStoreError.malformed }
        return try JSONDecoder().decode(IdentityPublicMetadata.self, from: data)
    }

    private func writeMetadata(_ metadata: IdentityPublicMetadata, createOnly: Bool) throws {
        if createOnly && FileManager.default.fileExists(atPath: metadataURL.path) {
            throw IdentityStoreError.alreadyExists
        }
        let data = try JSONEncoder().encode(metadata)
        let temporary = root.appendingPathComponent(".identity-\(UUID().uuidString).tmp")
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { throw IdentityStoreError.storage }
        var installed = false
        defer { close(descriptor); if !installed { unlink(temporary.path) } }
        let written = data.withUnsafeBytes { pointer -> Bool in
            guard var base = pointer.baseAddress else { return false }
            var remaining = pointer.count
            while remaining > 0 {
                let count = Darwin.write(descriptor, base, remaining)
                if count <= 0 { return false }
                base = base.advanced(by: count); remaining -= count
            }
            return true
        }
        guard written, fcntl(descriptor, F_FULLFSYNC) == 0 || fsync(descriptor) == 0 else {
            throw IdentityStoreError.storage
        }
        let result = createOnly
            ? renamex_np(temporary.path, metadataURL.path, UInt32(RENAME_EXCL))
            : rename(temporary.path, metadataURL.path)
        if result != 0 {
            if createOnly && errno == EEXIST { throw IdentityStoreError.alreadyExists }
            throw IdentityStoreError.storage
        }
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: metadataURL.path)
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        var url = metadataURL; try url.setResourceValues(values)
        try syncDirectory(); installed = true
    }

    private func syncDirectory() throws {
        let descriptor = open(root.path, O_RDONLY)
        guard descriptor >= 0 else { throw IdentityStoreError.storage }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else { throw IdentityStoreError.storage }
    }

    private func accessControl(flags: SecAccessControlCreateFlags) throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &error
        ) else { throw error!.takeRetainedValue() }
        return control
    }

    private func identityAccount(_ id: Data) -> String { "\(namespace).identity.\(id.hex)" }
    private func signingAccount(_ id: Data) -> String { "\(namespace).signing.\(id.hex)" }

    private func storeKey(_ data: Data, account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data
        ]
        guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else {
            throw IdentityStoreError.storage
        }
    }

    private func readKey(account: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { throw IdentityStoreError.missing }
        return data
    }

    private func deleteKey(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw IdentityStoreError.storage
        }
    }

    private func mapError(_ error: Error) -> IdentityStoreError {
        error as? IdentityStoreError ?? .storage
    }
}
