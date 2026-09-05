import CryptoKit
import Darwin
import Foundation
import PhoneIdentityCore

enum PairingStoreError: Error { case malformed, missing, exists, replay, expired, capacity, clockRollback, storage, locked, wrongScope }

struct PairingRecord {
    let desktopId: Data
    let identityId: Data
    let desktopLabel: String
    let recipient: String
    let desktopSigningPublicKey: Data
    let desktopSelectionPublicKey: Data
    let phoneSigningPublicKey: Data
    let offerDigest: Data
    let transcriptFingerprint: Data
}

private struct ReplayEntry: Equatable {
    let requestId: Data
    let nonce: Data
    let expiresAt: UInt64
}

private struct PairingState {
    let record: PairingRecord
    let createdAt: UInt64
    let lastSeen: UInt64
    let capacity: Int
    var entries: [ReplayEntry]
}

final class PairingStateStore {
    static let shared = PairingStateStore()
    private let root: URL
    private let queue = DispatchQueue(label: "io.github.biulight.phone-identity.pairings")
    private let stateDomain = Data("age-plugin-phone/ios-pairing-state-scope/v2".utf8)
    private let managementDomain = Data("age-plugin-phone/ios-pairing-management/v1".utf8)

    init() {
        let support = try! FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true
        )
        root = support.appendingPathComponent("phone-identity/pairings-v2", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.complete, .posixPermissions: 0o700]
        )
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        var mutableRoot = root; try? mutableRoot.setResourceValues(values)
    }

    func create(offer: VerifiedPairingOffer, response: VerifiedPairingResponse, nowUnix: UInt64) throws -> String {
        try queue.sync {
            let desktopSigning = try TaggedRecipientCrypto.compressedSigning(offer.desktopSigningPublicKey)
            let desktopSelection = try RecipientEncoding.compressed(offer.desktopSelectionPublicKey)
            let phoneSigning = try TaggedRecipientCrypto.compressedSigning(response.phoneSigningPublicKey)
            guard response.offerDigest == offer.digest,
                  desktopSigning.count == 33, desktopSelection.count == 33, phoneSigning.count == 33 else {
                throw PairingStoreError.malformed
            }
            let record = PairingRecord(
                desktopId: offer.desktopId, identityId: response.identityId,
                desktopLabel: offer.desktopLabel, recipient: response.recipient,
                desktopSigningPublicKey: desktopSigning, desktopSelectionPublicKey: desktopSelection,
                phoneSigningPublicKey: phoneSigning, offerDigest: offer.digest,
                transcriptFingerprint: OfflineEnvelopeCrypto.pairingFingerprint(offer, response)
            )
            let url = stateURL(desktopId: record.desktopId, identityId: record.identityId)
            return try withLock(for: url) {
                guard !FileManager.default.fileExists(atPath: url.path) else { throw PairingStoreError.exists }
                try durableReplace(encode(PairingState(record: record, createdAt: nowUnix, lastSeen: nowUnix, capacity: 1_024, entries: [])), at: url, createOnly: true)
                return handle(record)
            }
        }
    }

    func verifyAndConsume(_ encoded: Data, nowUnix: UInt64) throws -> VerifiedUnwrapRequest {
        try queue.sync {
            let scope = try OfflineEnvelopeCrypto.requestScope(encoded)
            let url = stateURL(desktopId: scope.desktopId, identityId: scope.identityId)
            return try withLock(for: url) {
                var state = try decode(Data(contentsOf: url, options: [.mappedIfSafe]))
                let signing = try TaggedRecipientCrypto.signingPublicKey(state.record.desktopSigningPublicKey)
                let request = try OfflineEnvelopeCrypto.verifyRequest(
                    encoded, desktopId: state.record.desktopId, identityId: state.record.identityId,
                    desktopSigningKey: signing, nowUnix: nowUnix
                )
                guard nowUnix >= state.lastSeen else { throw PairingStoreError.clockRollback }
                guard request.expiresAtUnix >= nowUnix, request.expiresAtUnix <= nowUnix + 300 else { throw PairingStoreError.expired }
                state.entries.removeAll { $0.expiresAt < nowUnix }
                guard !state.entries.contains(where: { $0.requestId == request.requestId || $0.nonce == request.nonce }) else { throw PairingStoreError.replay }
                guard state.entries.count < state.capacity else { throw PairingStoreError.capacity }
                state.entries.append(ReplayEntry(requestId: request.requestId, nonce: request.nonce, expiresAt: request.expiresAtUnix))
                state.entries.sort(by: entryLess)
                let next = PairingState(record: state.record, createdAt: state.createdAt, lastSeen: nowUnix, capacity: state.capacity, entries: state.entries)
                try durableReplace(encode(next), at: url, createOnly: false)
                return request
            }
        }
    }

    func record(desktopId: Data, identityId: Data) throws -> PairingRecord {
        try queue.sync {
            let url = stateURL(desktopId: desktopId, identityId: identityId)
            return try withLock(for: url) { try decode(Data(contentsOf: url)).record }
        }
    }

    func summaries(identityId: Data) throws -> [PairedDesktopSummary] {
        try queue.sync {
            let urls: [URL]
            do {
                urls = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles])
            } catch { throw PairingStoreError.storage }
            return try urls.filter { $0.pathExtension == "cbor" || $0.pathExtension == "deleting" }.compactMap { url in
                let data: Data
                do { data = try Data(contentsOf: url, options: [.mappedIfSafe]) }
                catch { throw PairingStoreError.storage }
                let state = try decode(data)
                guard state.record.identityId == identityId else { return nil }
                return PairedDesktopSummary(
                    handle: handle(state.record), displayLabel: state.record.desktopLabel,
                    transcriptFingerprint: state.record.transcriptFingerprint.hex,
                    deletionPending: url.pathExtension == "deleting"
                )
            }.sorted { $0.handle < $1.handle }
        }
    }

    func revoke(handle requestedHandle: String, identityId: Data) throws {
        try queue.sync {
            guard requestedHandle.count == 64, requestedHandle.allSatisfy({ $0.isLowercaseHex }) else { throw PairingStoreError.malformed }
            guard let url = try matchingURL(handle: requestedHandle, identityId: identityId) else { throw PairingStoreError.missing }
            try withLock(for: url) {
                let state = try decode(Data(contentsOf: url))
                guard handle(state.record) == requestedHandle else { throw PairingStoreError.wrongScope }
                let pending: URL
                if url.pathExtension == "deleting" {
                    pending = url
                } else {
                    pending = url.deletingPathExtension().appendingPathExtension("deleting")
                    guard rename(url.path, pending.path) == 0 else { throw PairingStoreError.storage }
                    try syncDirectory()
                }
                guard unlink(pending.path) == 0 else { throw PairingStoreError.storage }
                try syncDirectory()
            }
        }
    }

    func revokeAll(identityId: Data) throws {
        for summary in try summaries(identityId: identityId) { try revoke(handle: summary.handle, identityId: identityId) }
    }

    private func matchingURL(handle: String, identityId: Data) throws -> URL? {
        let urls: [URL]
        do { urls = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) }
        catch { throw PairingStoreError.storage }
        for url in urls where url.pathExtension == "cbor" || url.pathExtension == "deleting" {
            let data: Data
            do { data = try Data(contentsOf: url, options: [.mappedIfSafe]) }
            catch { throw PairingStoreError.storage }
            let state = try decode(data)
            if state.record.identityId == identityId && self.handle(state.record) == handle { return url }
        }
        return nil
    }

    private func stateURL(desktopId: Data, identityId: Data) -> URL {
        let digest = SHA256.hash(data: stateDomain + Data([0]) + desktopId + identityId)
        return root.appendingPathComponent(Data(digest).hex).appendingPathExtension("cbor")
    }

    private func handle(_ record: PairingRecord) -> String {
        Data(SHA256.hash(data: managementDomain + Data([0]) + record.identityId + record.desktopId + record.transcriptFingerprint)).hex
    }

    private func encode(_ state: PairingState) throws -> Data {
        try StrictCBOR.encode(.array([
            .unsigned(2), .bytes(state.record.desktopId), .bytes(state.record.identityId),
            .text(state.record.desktopLabel), .text(state.record.recipient),
            .bytes(state.record.desktopSigningPublicKey), .bytes(state.record.desktopSelectionPublicKey),
            .bytes(state.record.phoneSigningPublicKey), .bytes(state.record.offerDigest),
            .bytes(state.record.transcriptFingerprint), .unsigned(state.createdAt), .unsigned(state.lastSeen),
            .unsigned(UInt64(state.capacity)), .array(state.entries.map {
                .array([.bytes($0.requestId), .bytes($0.nonce), .unsigned($0.expiresAt)])
            })
        ]))
    }

    private func decode(_ data: Data) throws -> PairingState {
        guard data.count <= 1_048_576 else { throw PairingStoreError.capacity }
        let n = try StrictCBOR.decode(data, maximumBytes: 1_048_576).exactArray(14)
        guard try n[0].exactUnsigned() == 2 else { throw PairingStoreError.malformed }
        let record = PairingRecord(
            desktopId: try n[1].exactBytes(16), identityId: try n[2].exactBytes(16),
            desktopLabel: try n[3].boundedText(64), recipient: try n[4].boundedText(160),
            desktopSigningPublicKey: try n[5].exactBytes(33), desktopSelectionPublicKey: try n[6].exactBytes(33),
            phoneSigningPublicKey: try n[7].exactBytes(33), offerDigest: try n[8].exactBytes(32),
            transcriptFingerprint: try n[9].exactBytes(32)
        )
        guard record.desktopSigningPublicKey != record.desktopSelectionPublicKey,
              record.desktopSigningPublicKey != record.phoneSigningPublicKey,
              record.desktopSelectionPublicKey != record.phoneSigningPublicKey else { throw PairingStoreError.malformed }
        _ = try TaggedRecipientCrypto.signingPublicKey(record.desktopSigningPublicKey)
        _ = try TaggedRecipientCrypto.publicKey(record.desktopSelectionPublicKey)
        _ = try TaggedRecipientCrypto.signingPublicKey(record.phoneSigningPublicKey)
        let created = try n[10].exactUnsigned(), lastSeen = try n[11].exactUnsigned()
        let capacity = Int(try n[12].exactUnsigned())
        guard lastSeen >= created, (1...16_384).contains(capacity), case .array(let entryValues) = n[13], entryValues.count <= capacity else { throw PairingStoreError.malformed }
        let entries = try entryValues.map { value -> ReplayEntry in
            let entry = try value.exactArray(3)
            return ReplayEntry(requestId: try entry[0].exactBytes(16), nonce: try entry[1].exactBytes(32), expiresAt: try entry[2].exactUnsigned())
        }
        guard entries.allSatisfy({ $0.expiresAt >= lastSeen }), entries == entries.sorted(by: entryLess),
              Set(entries.map(\.requestId)).count == entries.count, Set(entries.map(\.nonce)).count == entries.count else { throw PairingStoreError.malformed }
        return PairingState(record: record, createdAt: created, lastSeen: lastSeen, capacity: capacity, entries: entries)
    }

    private func entryLess(_ lhs: ReplayEntry, _ rhs: ReplayEntry) -> Bool {
        if lhs.requestId != rhs.requestId { return lhs.requestId.lexicographicallyPrecedes(rhs.requestId) }
        if lhs.nonce != rhs.nonce { return lhs.nonce.lexicographicallyPrecedes(rhs.nonce) }
        return lhs.expiresAt < rhs.expiresAt
    }

    private func withLock<T>(for stateURL: URL, operation: () throws -> T) throws -> T {
        let lockURL = URL(fileURLWithPath: stateURL.path + ".lock")
        let descriptor = open(lockURL.path, O_RDWR | O_CREAT | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { throw PairingStoreError.storage }
        defer { close(descriptor) }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else { throw PairingStoreError.locked }
        defer { flock(descriptor, LOCK_UN) }
        return try operation()
    }

    private func durableReplace(_ data: Data, at url: URL, createOnly: Bool) throws {
        if createOnly && FileManager.default.fileExists(atPath: url.path) { throw PairingStoreError.exists }
        let temporary = root.appendingPathComponent(".\(UUID().uuidString).tmp")
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { throw PairingStoreError.storage }
        var succeeded = false
        defer { close(descriptor); if !succeeded { unlink(temporary.path) } }
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
            throw PairingStoreError.storage
        }
        let renameResult = createOnly
            ? renamex_np(temporary.path, url.path, UInt32(RENAME_EXCL))
            : rename(temporary.path, url.path)
        if renameResult != 0 {
            if createOnly && errno == EEXIST { throw PairingStoreError.exists }
            throw PairingStoreError.storage
        }
        do {
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
            var values = URLResourceValues(); values.isExcludedFromBackup = true
            var persisted = url; try persisted.setResourceValues(values)
            try syncDirectory(); succeeded = true
        } catch {
            throw PairingStoreError.storage
        }
    }

    private func syncDirectory() throws {
        let descriptor = open(root.path, O_RDONLY)
        guard descriptor >= 0 else { throw PairingStoreError.storage }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else { throw PairingStoreError.storage }
    }
}

private extension Character {
    var isLowercaseHex: Bool { ("0"..."9").contains(self) || ("a"..."f").contains(self) }
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
