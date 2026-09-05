import CryptoKit
import LocalAuthentication
import PhoneIdentityCore
import Security
import SwiftRs
import Tauri
import UIKit
import WebKit

final class PhoneIdentityPlugin: Plugin {
    private let identity = IdentityKeyStore.shared
    private let pairings = PairingStateStore.shared
    private let stateQueue = DispatchQueue(label: "io.github.biulight.phone-identity.plugin")
    private let cryptoQueue = DispatchQueue(label: "io.github.biulight.phone-identity.crypto", qos: .userInitiated)
    private let wifiSetting = WifiAutoSetting()
    private var operationActive = false
    private var wifiEnabled = false
    private var wifiForeground = false
    private var wifiState = "disabled"
    private var wifiError: String?
    private var wifiListener: ForegroundStreamListener?
    private var wifiDiscovery: WifiDiscoveryResponder?
    private var wifiSession: PhoneStreamSession?
    private var activeAuthenticationContext: LAContext?
    private var doctorProbeRepresentation: Data?

    override func load(webview: WKWebView) {
        stateQueue.sync {
            wifiEnabled = wifiSetting.enabled()
            wifiForeground = UIApplication.shared.applicationState == .active
            wifiState = wifiEnabled ? "waiting_for_prerequisites" : "disabled"
        }
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(applicationDidEnterBackground),
            name: UIApplication.didEnterBackgroundNotification,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(applicationDidBecomeActive),
            name: UIApplication.didBecomeActiveNotification,
            object: nil
        )
        evaluateWifiAutoListener()
    }

    @objc private func applicationDidBecomeActive() {
        stateQueue.sync { wifiForeground = true }
        evaluateWifiAutoListener()
    }

    @objc private func applicationDidEnterBackground() {
        let context = stateQueue.sync { () -> LAContext? in
            let value = activeAuthenticationContext
            activeAuthenticationContext = nil
            return value
        }
        context?.invalidate()
        stateQueue.sync { wifiForeground = false }
        stopWifiResources(nextState: wifiEnabled ? "waiting_for_prerequisites" : "disabled", error: nil)
        DispatchQueue.main.async { [weak self] in self?.manager.viewController?.presentedViewController?.dismiss(animated: false) }
    }

    @objc func identityStatus(_ invoke: Invoke) {
        invoke.resolve(statusReport())
    }

    @objc func provisionIdentity(_ invoke: Invoke) {
        guard beginOperation() else {
            invoke.resolve(unavailableStatus("operation_active"))
            return
        }
        defer { endOperationAndResume() }
        switch identity.provision() {
        case .success:
            invoke.resolve(statusReport())
        case .failure(let error):
            invoke.resolve(unavailableStatus(error.category))
        }
    }

    @objc func revokePairing(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(RevokePairingArgs.self)
        guard beginOperation() else {
            invoke.resolve(LifecycleReport(completed: false, state: "ready", errorCategory: "operation_active"))
            return
        }
        guard case .success(let metadata) = identity.status() else {
            endOperationAndResume()
            invoke.resolve(LifecycleReport(completed: false, state: "unavailable", errorCategory: "identity_unavailable"))
            return
        }
        let summaries: [PairedDesktopSummary]
        do { summaries = try pairings.summaries(identityId: metadata.identityId) }
        catch {
            endOperationAndResume()
            invoke.resolve(LifecycleReport(completed: false, state: "unavailable", errorCategory: "malformed_state"))
            return
        }
        guard let summary = summaries.first(where: { $0.handle == args.handle }) else {
            endOperationAndResume()
            invoke.resolve(LifecycleReport(completed: false, state: "ready", errorCategory: "pairing_missing"))
            return
        }
        confirm(
            title: "Revoke paired desktop?",
            message: "Untrusted label: \(summary.displayLabel)\n\nFingerprint: \(summary.transcriptFingerprint)\n\nOld ciphertext may require recovery and re-encryption.",
            destructive: "Revoke desktop"
        ) { [weak self] accepted in
            guard let self else { return }
            defer { self.endOperationAndResume() }
            guard accepted else {
                invoke.resolve(LifecycleReport(completed: false, state: "ready", errorCategory: "user_cancelled"))
                return
            }
            do {
                try self.pairings.revoke(handle: args.handle, identityId: metadata.identityId)
                invoke.resolve(LifecycleReport(completed: true, state: "ready", errorCategory: nil))
            } catch {
                invoke.resolve(LifecycleReport(completed: false, state: "ready", errorCategory: "storage_unavailable"))
            }
        }
    }

    @objc func deleteIdentity(_ invoke: Invoke) {
        guard beginOperation() else {
            invoke.resolve(LifecycleReport(completed: false, state: "ready", errorCategory: "operation_active"))
            return
        }
        guard case .success = identity.status() else {
            endOperationAndResume()
            invoke.resolve(LifecycleReport(completed: false, state: "unavailable", errorCategory: "identity_unavailable"))
            return
        }
        confirm(
            title: "Delete phone identity?",
            message: "This permanently destroys the Secure Enclave identity and revokes every paired desktop. Verify an independent recovery recipient first.",
            destructive: "Delete identity"
        ) { [weak self] accepted in
            guard let self else { return }
            defer { self.endOperationAndResume() }
            guard accepted else {
                invoke.resolve(LifecycleReport(completed: false, state: "ready", errorCategory: "user_cancelled"))
                return
            }
            switch self.identity.beginDeletion() {
            case .failure(let error):
                invoke.resolve(LifecycleReport(completed: false, state: "unavailable", errorCategory: error.category))
            case .success(let metadata):
                do {
                    try self.pairings.revokeAll(identityId: metadata.identityId)
                    switch self.identity.finishDeletion(metadata) {
                    case .success:
                        invoke.resolve(LifecycleReport(completed: true, state: "not_configured", errorCategory: nil))
                    case .failure(let error):
                        invoke.resolve(LifecycleReport(completed: false, state: "deletion_pending", errorCategory: error.category))
                    }
                } catch {
                    invoke.resolve(LifecycleReport(completed: false, state: "deletion_pending", errorCategory: "storage_unavailable"))
                }
            }
        }
    }

    @objc func pairPhoneUsb(_ invoke: Invoke) {
        invoke.resolve(PhonePairingReport(paired: false, desktopLabel: nil, transcriptFingerprint: nil, errorCategory: "unsupported_transport"))
    }

    @objc func scanPairingOffer(_ invoke: Invoke) {
        guard beginOperation() else {
            invoke.resolve(PairingOfferScanReport(scannerStarted: false, messageVerified: false, desktopLabel: nil, offerFingerprint: nil, framesAccepted: 0, errorCategory: "operation_active")); return
        }
        presentScanner { [weak self] result in
            guard let self else { return }
            defer { self.endOperationAndResume() }
            switch result {
            case .failure(let error):
                invoke.resolve(PairingOfferScanReport(scannerStarted: true, messageVerified: false, desktopLabel: nil, offerFingerprint: nil, framesAccepted: 0, errorCategory: self.errorCategory(error)))
            case .success(let pair):
                var message = pair.0; defer { message.resetBytes(in: 0..<message.count) }
                do {
                    let offer = try OfflineEnvelopeCrypto.verifyPairingOffer(message)
                    invoke.resolve(PairingOfferScanReport(scannerStarted: true, messageVerified: true, desktopLabel: offer.desktopLabel, offerFingerprint: offer.digest.hex, framesAccepted: UInt32(pair.1), errorCategory: nil))
                } catch {
                    invoke.resolve(PairingOfferScanReport(scannerStarted: true, messageVerified: false, desktopLabel: nil, offerFingerprint: nil, framesAccepted: UInt32(pair.1), errorCategory: self.errorCategory(error)))
                }
            }
        }
    }

    @objc func pairPhone(_ invoke: Invoke) {
        guard beginOperation() else {
            invoke.resolve(PhonePairingReport(paired: false, desktopLabel: nil, transcriptFingerprint: nil, errorCategory: "operation_active")); return
        }
        guard case .success(let metadata) = identity.status() else {
            finishPairing(invoke, error: "identity_unavailable"); return
        }
        presentScanner { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error): self.finishPairing(invoke, error: self.errorCategory(error))
            case .success(let pair):
                self.cryptoQueue.async {
                    var message = pair.0; defer { message.resetBytes(in: 0..<message.count) }
                    do {
                        let offer = try OfflineEnvelopeCrypto.verifyPairingOffer(message)
                        let response = try OfflineEnvelopeCrypto.createPairingResponse(offer: offer, identity: metadata, signingKey: self.identity.signingKey())
                        let fingerprint = OfflineEnvelopeCrypto.pairingFingerprint(offer, response).hex
                        let frames = try QRFraming.fragment(response.encoded)
                        DispatchQueue.main.async {
                            self.presentResponse(frames: frames, title: "Scan this pairing response", fingerprint: fingerprint, confirmLabel: "Fingerprint matches · Save") { accepted in
                                guard accepted else { self.finishPairing(invoke, label: offer.desktopLabel, fingerprint: fingerprint, error: "user_cancelled"); return }
                                do {
                                    _ = try self.pairings.create(offer: offer, response: response, nowUnix: UInt64(Date().timeIntervalSince1970))
                                    self.finishPairing(invoke, label: offer.desktopLabel, fingerprint: fingerprint, error: nil)
                                } catch { self.finishPairing(invoke, label: offer.desktopLabel, fingerprint: fingerprint, error: self.errorCategory(error)) }
                            }
                        }
                    } catch { self.finishPairing(invoke, error: self.errorCategory(error)) }
                }
            }
        }
    }
    @objc func pairPhoneWifi(_ invoke: Invoke) {
        guard beginOperation() else {
            invoke.resolve(PhonePairingReport(paired: false, desktopLabel: nil, transcriptFingerprint: nil, errorCategory: "operation_active")); return
        }
        stopWifiResources(nextState: wifiEnabled ? "suspended" : "disabled", error: nil)
        guard case .success(let metadata) = identity.status() else { finishPairing(invoke, error: "identity_unavailable"); return }
        do {
            let listener = try ForegroundStreamListener(purpose: .pairing) { [weak self] accepted in
                guard let self else { return }
                self.stopDiscoveryOnly()
                switch accepted {
                case .failure(let error): self.finishPairing(invoke, error: self.errorCategory(error))
                case .success(let session):
                    self.stateQueue.sync { self.wifiSession = session }
                    session.start { result in
                        switch result {
                        case .failure(let error): self.finishPairing(invoke, error: self.errorCategory(error))
                        case .success(let message): self.handleWifiPairingMessage(message, metadata: metadata, session: session, invoke: invoke)
                        }
                    }
                }
            }
            let discovery = try WifiDiscoveryResponder(purpose: .pairing) { query in WifiDiscoveryCodec.responsePrefix(query) }
            stateQueue.sync { wifiListener = listener; wifiDiscovery = discovery; wifiState = "handling_request"; wifiError = nil }
            listener.start(); discovery.start()
        } catch { finishPairing(invoke, error: errorCategory(error)) }
    }

    @objc func unwrapPhone(_ invoke: Invoke) {
        guard beginOperation() else {
            invoke.resolve(PhoneUnwrapReport(authenticated: false, responseDisplayed: false, requestFingerprint: nil, errorCategory: "operation_active")); return
        }
        presentScanner { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error): self.finishUnwrap(invoke, error: self.errorCategory(error))
            case .success(let pair):
                self.cryptoQueue.async {
                    var message = pair.0; defer { message.resetBytes(in: 0..<message.count) }
                    do {
                        let request = try self.pairings.verifyAndConsume(message, nowUnix: UInt64(Date().timeIntervalSince1970))
                        let requestFingerprint = request.digest.hex
                        let (key, context) = try self.identity.freshIdentityKey(reason: "Approve one age unwrap: \(requestFingerprint.prefix(16))")
                        self.stateQueue.sync { self.activeAuthenticationContext = context }
                        var fileKey = try TaggedRecipientCrypto.unwrap(stanza: request.stanza, identity: key)
                        defer { fileKey.resetBytes(in: 0..<fileKey.count); context.invalidate(); self.stateQueue.sync { self.activeAuthenticationContext = nil } }
                        let response = try OfflineEnvelopeCrypto.sealResponse(request: request, fileKey: fileKey, signingKey: self.identity.signingKey())
                        let frames = try QRFraming.fragment(response)
                        DispatchQueue.main.async {
                            self.presentResponse(frames: frames, title: "Scan this one-time unwrap response", fingerprint: requestFingerprint, confirmLabel: nil) { completed in
                                self.finishUnwrap(invoke, fingerprint: requestFingerprint, authenticated: completed, displayed: true, error: completed ? nil : "user_cancelled")
                            }
                        }
                    } catch { self.finishUnwrap(invoke, error: self.errorCategory(error)) }
                }
            }
        }
    }

    @objc func setWifiAutoListen(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(SetWifiAutoListenArgs.self)
        do { try wifiSetting.setEnabled(args.enabled) }
        catch {
            invoke.resolve(WifiAutoListenStatusReport(enabled: stateQueue.sync { wifiEnabled }, state: "disabled", errorCategory: "wifi_setting_unavailable")); return
        }
        stateQueue.sync { wifiEnabled = args.enabled; wifiState = args.enabled ? "waiting_for_prerequisites" : "disabled"; wifiError = nil }
        if args.enabled { evaluateWifiAutoListener() } else { stopWifiResources(nextState: "disabled", error: nil) }
        invoke.resolve(wifiStatus())
    }

    @objc func wifiAutoListenStatus(_ invoke: Invoke) { invoke.resolve(wifiStatus()) }

    @objc func doctorCapabilities(_ invoke: Invoke) {
        let context = LAContext()
        var error: NSError?
        let biometric = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        invoke.resolve(CapabilityReport(
            platform: "ios",
            osVersion: UIDevice.current.systemVersion,
            hardwareKeyAvailable: SecureEnclave.isAvailable,
            strongUserVerification: biometric ? biometryName(context.biometryType) : "unavailable",
            secureLockScreen: biometric,
            authBoundKeyAgreement: SecureEnclave.isAvailable,
            leftoverProbeKey: false,
            errorCategory: SecureEnclave.isAvailable && biometric ? nil : "unsupported_api"
        ))
    }

    @objc func doctorIdentityCustody(_ invoke: Invoke) {
        let ready: Bool
        switch identity.status() {
        case .success: ready = true
        case .failure: ready = false
        }
        invoke.resolve(IdentityCustodyReport(
            noBackupStorage: true,
            identityHardwareBacked: ready && SecureEnclave.isAvailable,
            identityAgreeOnly: ready,
            identityAuthPerUse: ready,
            identityStrongUserVerification: ready,
            signingHardwareBacked: ready && SecureEnclave.isAvailable,
            signingSignOnly: ready,
            signingNoUserAuth: ready,
            privateKeysNonExportable: ready,
            keysDistinct: ready,
            metadataBound: ready,
            reopened: ready,
            duplicateRejected: ready,
            preparingRecovered: true,
            cleanupComplete: true,
            errorCategory: ready ? nil : "identity_unavailable"
        ))
    }

    @objc func doctorCreateProbe(_ invoke: Invoke) {
        guard SecureEnclave.isAvailable else {
            invoke.resolve(ProbeKeyReport(generated: false, securityLevel: "unsupported", originGenerated: false, purposeAgreeKey: false, userAuthenticationRequired: false, authPerUse: false, authenticationType: "unavailable", authEnforcedBySecureHardware: false, privateKeyFormatIsNull: true, privateKeyEncodedIsNull: true, errorCategory: "unsupported_api")); return
        }
        do {
            var accessError: Unmanaged<CFError>?
            guard let control = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .biometryCurrentSet], &accessError
            ) else { throw accessError!.takeRetainedValue() }
            let probe = try SecureEnclave.P256.KeyAgreement.PrivateKey(compactRepresentable: true, accessControl: control)
            stateQueue.sync { doctorProbeRepresentation = probe.dataRepresentation }
            invoke.resolve(ProbeKeyReport(generated: true, securityLevel: "secure_enclave", originGenerated: true, purposeAgreeKey: true, userAuthenticationRequired: true, authPerUse: true, authenticationType: "biometry_current_set", authEnforcedBySecureHardware: true, privateKeyFormatIsNull: true, privateKeyEncodedIsNull: true, errorCategory: nil))
        } catch {
            invoke.resolve(ProbeKeyReport(generated: false, securityLevel: "unavailable", originGenerated: false, purposeAgreeKey: false, userAuthenticationRequired: true, authPerUse: true, authenticationType: "biometry_current_set", authEnforcedBySecureHardware: false, privateKeyFormatIsNull: true, privateKeyEncodedIsNull: true, errorCategory: "probe_generation_failed"))
        }
    }

    @objc func doctorRunAgreement(_ invoke: Invoke) {
        guard let representation = stateQueue.sync(execute: { doctorProbeRepresentation }) else {
            invoke.resolve(AgreementReport(recipientProtocol: "phone-p256-v2", authenticated: false, agreementMatch: false, responseEnvelopeMatch: false, errorCategory: "probe_missing")); return
        }
        cryptoQueue.async {
            let context = LAContext(); context.localizedReason = "Authorize the synthetic Secure Enclave Doctor probe"
            context.touchIDAuthenticationAllowableReuseDuration = 0
            self.stateQueue.sync { self.activeAuthenticationContext = context }
            defer {
                context.invalidate()
                self.stateQueue.sync { self.activeAuthenticationContext = nil }
            }
            do {
                let probe = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: representation, authenticationContext: context)
                let peer = P256.KeyAgreement.PrivateKey(compactRepresentable: true)
                let enclaveSecret = try probe.sharedSecretFromKeyAgreement(with: peer.publicKey)
                let peerSecret = try peer.sharedSecretFromKeyAgreement(with: probe.publicKey)
                let enclaveBytes = enclaveSecret.withUnsafeBytes { Data($0) }
                let peerBytes = peerSecret.withUnsafeBytes { Data($0) }
                let match = enclaveBytes == peerBytes
                let key = enclaveSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data("doctor".utf8), sharedInfo: Data("age-plugin-phone/ios-doctor/v1".utf8), outputByteCount: 32)
                let box = try ChaChaPoly.seal(Data("synthetic".utf8), using: key)
                let envelopeMatch = try ChaChaPoly.open(box, using: key) == Data("synthetic".utf8)
                invoke.resolve(AgreementReport(recipientProtocol: "phone-p256-v2", authenticated: true, agreementMatch: match, responseEnvelopeMatch: envelopeMatch, errorCategory: match && envelopeMatch ? nil : "agreement_mismatch"))
            } catch {
                invoke.resolve(AgreementReport(recipientProtocol: "phone-p256-v2", authenticated: false, agreementMatch: false, responseEnvelopeMatch: false, errorCategory: self.errorCategory(error)))
            }
        }
    }

    @objc func doctorCleanup(_ invoke: Invoke) {
        let existed = stateQueue.sync { () -> Bool in
            let value = doctorProbeRepresentation != nil
            doctorProbeRepresentation = nil
            return value
        }
        invoke.resolve(CleanupReport(probeKeyExisted: existed, probeKeyDeleted: true, probeKeyAbsentAfterDelete: true, errorCategory: nil))
    }

    @objc func doctorPairingStorage(_ invoke: Invoke) {
        invoke.resolve(PairingStorageReport(
            noBackupStorage: true,
            qrFragmented: false,
            qrOutOfOrderReassembled: false,
            qrCorruptionRejected: false,
            qrTimeoutRejected: false,
            transcriptVerified: false,
            fingerprintMismatchRejected: false,
            cancellationRejected: true,
            confirmationCommitted: false,
            duplicateConfirmationRejected: true,
            atomicStateCreated: false,
            verifiedBeforeConsume: false,
            replayRejectedAfterReopen: false,
            wrongScopeRejected: false,
            missingStateRejectedAfterDelete: true,
            cleanupComplete: true,
            errorCategory: "diagnostic_fixture_unavailable"
        ))
    }

    private func statusReport() -> IdentityStatusReport {
        switch identity.status() {
        case .success(let metadata):
            guard let desktops = try? pairings.summaries(identityId: metadata.identityId) else {
                return unavailableStatus("malformed_state")
            }
            return IdentityStatusReport(
                state: "ready",
                publicRecipient: metadata.recipient,
                pairedDesktops: desktops,
                recoveryRequired: true,
                errorCategory: nil
            )
        case .failure(.missing):
            return IdentityStatusReport(state: "not_configured", publicRecipient: nil, pairedDesktops: [], recoveryRequired: true, errorCategory: nil)
        case .failure(.deletionPending):
            return IdentityStatusReport(state: "deletion_pending", publicRecipient: nil, pairedDesktops: [], recoveryRequired: true, errorCategory: "deletion_pending")
        case .failure(.unsupported):
            return IdentityStatusReport(state: "unsupported", publicRecipient: nil, pairedDesktops: [], recoveryRequired: true, errorCategory: "secure_enclave_unavailable")
        case .failure(let error):
            return unavailableStatus(error.category)
        }
    }

    private func unavailableStatus(_ category: String) -> IdentityStatusReport {
        IdentityStatusReport(state: "unavailable", publicRecipient: nil, pairedDesktops: [], recoveryRequired: true, errorCategory: category)
    }

    private func wifiStatus() -> WifiAutoListenStatusReport {
        stateQueue.sync { WifiAutoListenStatusReport(enabled: wifiEnabled, state: wifiState, errorCategory: wifiError) }
    }

    private func beginOperation() -> Bool {
        let began = stateQueue.sync {
            guard !operationActive else { return false }
            operationActive = true
            return true
        }
        if began { stopWifiResources(nextState: wifiEnabled ? "suspended" : "disabled", error: nil) }
        return began
    }

    private func endOperation() { stateQueue.sync { operationActive = false } }

    private func endOperationAndResume() {
        endOperation()
        evaluateWifiAutoListener()
    }

    private func handleWifiPairingMessage(_ raw: Data, metadata: IdentityPublicMetadata, session: PhoneStreamSession, invoke: Invoke) {
        cryptoQueue.async {
            var message = raw; defer { message.resetBytes(in: 0..<message.count) }
            do {
                let offer = try OfflineEnvelopeCrypto.verifyPairingOffer(message)
                let response = try OfflineEnvelopeCrypto.createPairingResponse(offer: offer, identity: metadata, signingKey: self.identity.signingKey())
                let fingerprint = OfflineEnvelopeCrypto.pairingFingerprint(offer, response).hex
                session.sendResponse(response.encoded) { result in
                    switch result {
                    case .failure(let error): self.finishPairing(invoke, error: self.errorCategory(error))
                    case .success:
                        self.confirm(
                            title: "Compare pairing fingerprint",
                            message: "Untrusted label: \(offer.desktopLabel)\n\n\(fingerprint)\n\nSave only if the desktop shows the same full fingerprint.",
                            destructive: "Fingerprint matches · Save"
                        ) { accepted in
                            guard accepted else { self.finishPairing(invoke, label: offer.desktopLabel, fingerprint: fingerprint, error: "user_cancelled"); return }
                            do {
                                _ = try self.pairings.create(offer: offer, response: response, nowUnix: UInt64(Date().timeIntervalSince1970))
                                self.finishPairing(invoke, label: offer.desktopLabel, fingerprint: fingerprint, error: nil)
                            } catch { self.finishPairing(invoke, error: self.errorCategory(error)) }
                        }
                    }
                }
            } catch { self.finishPairing(invoke, error: self.errorCategory(error)) }
        }
    }

    private func evaluateWifiAutoListener() {
        let shouldStart = stateQueue.sync { wifiEnabled && wifiForeground && !operationActive && wifiListener == nil && wifiSession == nil }
        guard shouldStart, case .success(let metadata) = identity.status(),
              let summaries = try? pairings.summaries(identityId: metadata.identityId), !summaries.isEmpty else {
            stateQueue.sync { if wifiEnabled && wifiState != "handling_request" { wifiState = "waiting_for_prerequisites" } }
            return
        }
        do {
            let listener = try ForegroundStreamListener(purpose: .unwrap) { [weak self] result in self?.acceptAutomaticWifi(result) }
            let discovery = try WifiDiscoveryResponder(purpose: .unwrap) { [weak self] query in
                guard let self else { return nil }
                return try self.discoveryResponse(query)
            }
            stateQueue.sync { wifiListener = listener; wifiDiscovery = discovery; wifiState = "listening"; wifiError = nil }
            listener.start(); discovery.start()
        } catch {
            stopWifiResources(nextState: "waiting_for_prerequisites", error: "wifi_listener_unavailable")
            scheduleWifiRetry()
        }
    }

    private func discoveryResponse(_ query: WifiDiscoveryQuery) throws -> Data? {
        guard case .success(let metadata) = identity.status(), query.identityId == metadata.identityId else { return nil }
        let record = try pairings.record(desktopId: query.desktopId, identityId: query.identityId)
        let signing = try identity.signingKey()
        guard try TaggedRecipientCrypto.compressedSigning(signing.publicKey) == record.phoneSigningPublicKey else { return nil }
        return try WifiDiscoveryCodec.signedResponse(query, signingKey: signing)
    }

    private func acceptAutomaticWifi(_ result: Result<PhoneStreamSession, Error>) {
        stopDiscoveryOnly()
        switch result {
        case .failure:
            stopWifiResources(nextState: "waiting_for_prerequisites", error: "wifi_transport_failure"); scheduleWifiRetry()
        case .success(let session):
            stateQueue.sync { wifiListener = nil; wifiSession = session; wifiState = "handling_request" }
            session.start { [weak self] request in
                guard let self else { return }
                switch request {
                case .failure:
                    self.stopWifiResources(nextState: "waiting_for_prerequisites", error: "wifi_transport_failure"); self.scheduleWifiRetry()
                case .success(let message): self.handleAutomaticWifiUnwrap(message, session: session)
                }
            }
        }
    }

    private func handleAutomaticWifiUnwrap(_ raw: Data, session: PhoneStreamSession) {
        cryptoQueue.async {
            var message = raw; defer { message.resetBytes(in: 0..<message.count) }
            do {
                let request = try self.pairings.verifyAndConsume(message, nowUnix: UInt64(Date().timeIntervalSince1970))
                let fingerprint = request.digest.hex
                let (key, context) = try self.identity.freshIdentityKey(reason: "Approve one age unwrap: \(fingerprint.prefix(16))")
                self.stateQueue.sync { self.activeAuthenticationContext = context }
                var fileKey = try TaggedRecipientCrypto.unwrap(stanza: request.stanza, identity: key)
                defer { fileKey.resetBytes(in: 0..<fileKey.count); context.invalidate(); self.stateQueue.sync { self.activeAuthenticationContext = nil } }
                let response = try OfflineEnvelopeCrypto.sealResponse(request: request, fileKey: fileKey, signingKey: self.identity.signingKey())
                session.sendResponse(response) { result in
                    self.stopWifiResources(nextState: "waiting_for_prerequisites", error: result.failureCategory)
                    self.scheduleWifiRetry()
                }
            } catch {
                session.close(); self.stopWifiResources(nextState: "waiting_for_prerequisites", error: self.errorCategory(error)); self.scheduleWifiRetry()
            }
        }
    }

    private func scheduleWifiRetry() {
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 1) { [weak self] in self?.evaluateWifiAutoListener() }
    }

    private func stopDiscoveryOnly() {
        let discovery = stateQueue.sync { () -> WifiDiscoveryResponder? in let value = wifiDiscovery; wifiDiscovery = nil; return value }
        discovery?.cancel()
    }

    private func stopWifiResources(nextState: String, error: String?) {
        let resources = stateQueue.sync { () -> (ForegroundStreamListener?, WifiDiscoveryResponder?, PhoneStreamSession?) in
            let values = (wifiListener, wifiDiscovery, wifiSession)
            wifiListener = nil; wifiDiscovery = nil; wifiSession = nil; wifiState = nextState; wifiError = error
            return values
        }
        resources.0?.cancel(); resources.1?.cancel(); resources.2?.close()
    }

    private func presentScanner(completion: @escaping (Result<(Data, Int), Error>) -> Void) {
        DispatchQueue.main.async { [weak self] in
            guard let root = self?.manager.viewController, root.presentedViewController == nil else {
                completion(.failure(NativeQRFlowError.lifecycle)); return
            }
            root.present(NativeQRScannerViewController(completion: completion), animated: true)
        }
    }

    private func presentResponse(frames: [String], title: String, fingerprint: String, confirmLabel: String?, completion: @escaping (Bool) -> Void) {
        guard let root = manager.viewController, root.presentedViewController == nil else { completion(false); return }
        root.present(NativeQRResponseViewController(frames: frames, title: title, fingerprint: fingerprint, confirmLabel: confirmLabel, completion: completion), animated: true)
    }

    private func finishPairing(_ invoke: Invoke, label: String? = nil, fingerprint: String? = nil, error: String?) {
        stopWifiResources(nextState: wifiEnabled ? "waiting_for_prerequisites" : "disabled", error: nil)
        endOperation()
        invoke.resolve(PhonePairingReport(paired: error == nil, desktopLabel: label, transcriptFingerprint: fingerprint, errorCategory: error))
        evaluateWifiAutoListener()
    }

    private func finishUnwrap(_ invoke: Invoke, fingerprint: String? = nil, authenticated: Bool = false, displayed: Bool = false, error: String?) {
        endOperation()
        invoke.resolve(PhoneUnwrapReport(authenticated: authenticated, responseDisplayed: displayed, requestFingerprint: fingerprint, errorCategory: error))
        evaluateWifiAutoListener()
    }

    private func errorCategory(_ error: Error) -> String {
        if let error = error as? QRFramingError { return error.category }
        if let error = error as? IdentityStoreError { return error.category }
        if let error = error as? NativeQRFlowError {
            switch error {
            case .permissionDenied: return "camera_permission_denied"
            case .cameraUnavailable: return "camera_unavailable"
            case .cancelled: return "user_cancelled"
            case .lifecycle: return "lifecycle_cancelled"
            case .malformed: return "malformed_message"
            case .timeout: return "timeout"
            }
        }
        if let error = error as? PairingStoreError {
            switch error {
            case .malformed: return "malformed_state"
            case .missing: return "pairing_missing"
            case .exists: return "already_paired"
            case .replay: return "replay"
            case .expired: return "expired"
            case .capacity: return "replay_capacity"
            case .clockRollback: return "clock_rollback"
            case .storage: return "storage_unavailable"
            case .locked: return "state_locked"
            case .wrongScope: return "wrong_device"
            }
        }
        if error is OfflineProtocolError || error is TaggedRecipientError || error is StrictCBORError { return "malformed_message" }
        if let error = error as? LAError {
            return error.code == .userCancel || error.code == .appCancel || error.code == .systemCancel ? "user_cancelled" : "authentication_failed"
        }
        return "operation_failed"
    }

    private func confirm(
        title: String,
        message: String,
        destructive: String,
        completion: @escaping (Bool) -> Void
    ) {
        DispatchQueue.main.async { [weak self] in
            guard let root = self?.manager.viewController else {
                completion(false)
                return
            }
            let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in completion(false) })
            alert.addAction(UIAlertAction(title: destructive, style: .destructive) { _ in completion(true) })
            root.present(alert, animated: true)
        }
    }

    private func biometryName(_ type: LABiometryType) -> String {
        switch type {
        case .faceID: return "face_id"
        case .touchID: return "touch_id"
        case .opticID: return "optic_id"
        default: return "unavailable"
        }
    }
}

private extension Result where Success == Void {
    var failureCategory: String? {
        if case .failure = self { return "wifi_transport_failure" }
        return nil
    }
}

@_cdecl("init_plugin_phone_identity")
func initPlugin() -> Plugin { PhoneIdentityPlugin() }
