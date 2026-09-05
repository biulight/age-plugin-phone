import Foundation

struct PairedDesktopSummary: Codable {
    let handle: String
    let displayLabel: String
    let transcriptFingerprint: String
    let deletionPending: Bool
}

struct IdentityStatusReport: Codable {
    let state: String
    let publicRecipient: String?
    let pairedDesktops: [PairedDesktopSummary]
    let recoveryRequired: Bool
    let errorCategory: String?
}

struct LifecycleReport: Codable {
    let completed: Bool
    let state: String
    let errorCategory: String?
}

struct PhonePairingReport: Codable {
    let paired: Bool
    let desktopLabel: String?
    let transcriptFingerprint: String?
    let errorCategory: String?
}

struct PhoneUnwrapReport: Codable {
    let authenticated: Bool
    let responseDisplayed: Bool
    let requestFingerprint: String?
    let errorCategory: String?
}

struct PairingOfferScanReport: Codable {
    let scannerStarted: Bool
    let messageVerified: Bool
    let desktopLabel: String?
    let offerFingerprint: String?
    let framesAccepted: UInt32
    let errorCategory: String?
}

struct WifiAutoListenStatusReport: Codable {
    let enabled: Bool
    let state: String
    let errorCategory: String?
}

struct CapabilityReport: Codable {
    let platform: String
    let osVersion: String
    let hardwareKeyAvailable: Bool
    let strongUserVerification: String
    let secureLockScreen: Bool
    let authBoundKeyAgreement: Bool
    let leftoverProbeKey: Bool
    let errorCategory: String?
}

struct IdentityCustodyReport: Codable {
    let noBackupStorage: Bool
    let identityHardwareBacked: Bool
    let identityAgreeOnly: Bool
    let identityAuthPerUse: Bool
    let identityStrongUserVerification: Bool
    let signingHardwareBacked: Bool
    let signingSignOnly: Bool
    let signingNoUserAuth: Bool
    let privateKeysNonExportable: Bool
    let keysDistinct: Bool
    let metadataBound: Bool
    let reopened: Bool
    let duplicateRejected: Bool
    let preparingRecovered: Bool
    let cleanupComplete: Bool
    let errorCategory: String?
}

struct ProbeKeyReport: Codable {
    let generated: Bool
    let securityLevel: String
    let originGenerated: Bool
    let purposeAgreeKey: Bool
    let userAuthenticationRequired: Bool
    let authPerUse: Bool
    let authenticationType: String
    let authEnforcedBySecureHardware: Bool
    let privateKeyFormatIsNull: Bool
    let privateKeyEncodedIsNull: Bool
    let errorCategory: String?
}

struct AgreementReport: Codable {
    let recipientProtocol: String
    let authenticated: Bool
    let agreementMatch: Bool
    let responseEnvelopeMatch: Bool
    let errorCategory: String?
}

struct CleanupReport: Codable {
    let probeKeyExisted: Bool
    let probeKeyDeleted: Bool
    let probeKeyAbsentAfterDelete: Bool
    let errorCategory: String?
}

struct PairingStorageReport: Codable {
    let noBackupStorage: Bool
    let qrFragmented: Bool
    let qrOutOfOrderReassembled: Bool
    let qrCorruptionRejected: Bool
    let qrTimeoutRejected: Bool
    let transcriptVerified: Bool
    let fingerprintMismatchRejected: Bool
    let cancellationRejected: Bool
    let confirmationCommitted: Bool
    let duplicateConfirmationRejected: Bool
    let atomicStateCreated: Bool
    let verifiedBeforeConsume: Bool
    let replayRejectedAfterReopen: Bool
    let wrongScopeRejected: Bool
    let missingStateRejectedAfterDelete: Bool
    let cleanupComplete: Bool
    let errorCategory: String?
}

struct SetWifiAutoListenArgs: Decodable { let enabled: Bool }
struct RevokePairingArgs: Decodable { let handle: String }
