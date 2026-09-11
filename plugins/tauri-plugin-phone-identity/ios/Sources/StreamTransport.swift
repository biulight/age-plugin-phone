import CryptoKit
import Foundation
import Network

enum StreamTransportError: Error { case malformed, timeout, disconnected, unavailable }
enum StreamPurpose: UInt8 { case pairing = 1, unwrap = 2 }

struct StreamMessage { let sessionId: Data; let body: Data }

enum StreamTransportCodec {
    private static let magic = Data([0x41, 0x50, 0x54, 0x53])
    static let maximumBodyBytes = 65_536

    static func decodeHeader(_ header: Data, purpose: StreamPurpose, direction: UInt8) throws -> (Data, Int) {
        guard header.count == 28, header.prefix(4) == magic,
              header[4] == 0, header[5] == 1, header[6] == purpose.rawValue, header[7] == direction else {
            throw StreamTransportError.malformed
        }
        let session = Data(header[8..<24])
        let length = Int(header[24]) << 24 | Int(header[25]) << 16 | Int(header[26]) << 8 | Int(header[27])
        guard session.count == 16, (0...maximumBodyBytes).contains(length) else { throw StreamTransportError.malformed }
        return (session, length)
    }

    static func encode(purpose: StreamPurpose, direction: UInt8, sessionId: Data, body: Data) throws -> Data {
        guard sessionId.count == 16, body.count <= maximumBodyBytes else { throw StreamTransportError.malformed }
        let length = UInt32(body.count)
        return magic + Data([0, 1, purpose.rawValue, direction]) + sessionId + Data([
            UInt8((length >> 24) & 0xff), UInt8((length >> 16) & 0xff), UInt8((length >> 8) & 0xff), UInt8(length & 0xff)
        ]) + body
    }
}

final class PhoneStreamSession {
    private let connection: NWConnection
    private let purpose: StreamPurpose
    private let queue = DispatchQueue(label: "io.github.biulight.phone-identity.stream")
    private let stateLock = NSLock()
    private var sessionId: Data?
    private var terminal = false
    private var requestDelivered = false
    private var remoteDisconnectedAfterDelivery = false
    private var disconnectHandler: (() -> Void)?

    init(connection: NWConnection, purpose: StreamPurpose) { self.connection = connection; self.purpose = purpose }

    func start(completion: @escaping (Result<Data, Error>) -> Void) {
        func finish(_ result: Result<Data, Error>, close: Bool, peerClosed: Bool = false) {
            self.stateLock.lock()
            guard !self.requestDelivered, !self.terminal else {
                self.stateLock.unlock()
                return
            }
            self.requestDelivered = true
            if close {
                self.terminal = true
                self.sessionId = nil
            }
            self.stateLock.unlock()
            if close {
                self.connection.cancel()
            } else if peerClosed {
                self.handlePeerDisconnectAfterDelivery()
            } else {
                self.monitorPeerDisconnect()
            }
            completion(result)
        }
        func disconnected(_ error: Error) {
            var initialFailure = false
            var handler: (() -> Void)?
            self.stateLock.lock()
            guard !self.terminal else {
                self.stateLock.unlock()
                return
            }
            self.terminal = true
            self.sessionId = nil
            if self.requestDelivered {
                self.remoteDisconnectedAfterDelivery = true
                handler = self.disconnectHandler
                self.disconnectHandler = nil
            } else {
                self.requestDelivered = true
                initialFailure = true
            }
            self.stateLock.unlock()
            self.connection.cancel()
            if initialFailure { completion(.failure(error)) }
            handler?()
        }
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.receiveExactly(28) { result, peerClosed in
                    switch result {
                    case .failure(let error):
                        finish(.failure(error), close: true)
                    case .success(let header):
                        do {
                            let (id, length) = try StreamTransportCodec.decodeHeader(header, purpose: self.purpose, direction: 1)
                            self.stateLock.lock()
                            guard !self.terminal else {
                                self.stateLock.unlock()
                                return
                            }
                            self.sessionId = id
                            self.stateLock.unlock()
                            if peerClosed, length > 0 {
                                finish(.failure(StreamTransportError.disconnected), close: true)
                                return
                            }
                            self.receiveExactly(length) { body, bodyPeerClosed in
                                switch body {
                                case .success(let data): finish(.success(data), close: false, peerClosed: peerClosed || bodyPeerClosed)
                                case .failure(let error): finish(.failure(error), close: true)
                                }
                            }
                        } catch {
                            finish(.failure(error), close: true)
                        }
                    }
                }
            case .failed(let error):
                disconnected(error)
            case .cancelled:
                disconnected(StreamTransportError.disconnected)
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 90) { [weak self] in
            guard self != nil else { return }
            finish(.failure(StreamTransportError.timeout), close: true)
        }
    }

    func watchPeerDisconnect(_ handler: @escaping () -> Void) {
        var callImmediately = false
        stateLock.lock()
        if remoteDisconnectedAfterDelivery {
            callImmediately = true
        } else if !terminal {
            disconnectHandler = handler
        }
        stateLock.unlock()
        if callImmediately { handler() }
    }

    func sendResponse(_ body: Data, completion: @escaping (Result<Void, Error>) -> Void) {
        do {
            stateLock.lock()
            let activeSessionId = terminal ? nil : sessionId
            stateLock.unlock()
            guard let activeSessionId else { throw StreamTransportError.disconnected }
            let message = try StreamTransportCodec.encode(purpose: purpose, direction: 2, sessionId: activeSessionId, body: body)
            connection.send(content: message, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { [weak self] error in
                self?.close(); error == nil ? completion(.success(())) : completion(.failure(error!))
            })
        } catch { close(); completion(.failure(error)) }
    }

    func close() {
        stateLock.lock()
        guard !terminal else {
            stateLock.unlock()
            return
        }
        terminal = true
        sessionId = nil
        disconnectHandler = nil
        stateLock.unlock()
        connection.cancel()
    }

    private func monitorPeerDisconnect() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1) { [weak self] data, _, complete, error in
            guard let self else { return }
            if error != nil || complete || !(data?.isEmpty ?? true) {
                self.handlePeerDisconnectAfterDelivery()
                return
            }
            self.monitorPeerDisconnect()
        }
    }

    private func handlePeerDisconnectAfterDelivery() {
        var handler: (() -> Void)?
        stateLock.lock()
        if !terminal, requestDelivered {
            terminal = true
            sessionId = nil
            remoteDisconnectedAfterDelivery = true
            handler = disconnectHandler
            disconnectHandler = nil
        }
        stateLock.unlock()
        connection.cancel()
        handler?()
    }

    private func receiveExactly(_ count: Int, completion: @escaping (Result<Data, Error>, Bool) -> Void) {
        if count == 0 { completion(.success(Data()), false); return }
        var accumulated = Data()
        func receive() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: count - accumulated.count) { data, _, complete, error in
                if let data { accumulated.append(data) }
                if let error { completion(.failure(error), false); return }
                if accumulated.count == count { completion(.success(accumulated), complete); return }
                if complete { completion(.failure(StreamTransportError.disconnected), false); return }
                receive()
            }
        }
        receive()
    }
}

final class ForegroundStreamListener {
    private let listener: NWListener
    private let purpose: StreamPurpose
    private let completion: (Result<PhoneStreamSession, Error>) -> Void
    private let queue = DispatchQueue(label: "io.github.biulight.phone-identity.listener")
    private var terminal = false

    init(purpose: StreamPurpose, completion: @escaping (Result<PhoneStreamSession, Error>) -> Void) throws {
        self.purpose = purpose; self.completion = completion
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        listener = try NWListener(using: parameters, on: 47_140)
    }

    func start() {
        listener.newConnectionHandler = { [weak self] connection in
            guard let self, !self.terminal else { connection.cancel(); return }
            self.terminal = true; self.listener.cancel()
            self.completion(.success(PhoneStreamSession(connection: connection, purpose: self.purpose)))
        }
        listener.stateUpdateHandler = { [weak self] state in
            guard let self, !self.terminal else { return }
            if case .failed(let error) = state {
                self.terminal = true
                self.completion(.failure(error))
            }
        }
        listener.start(queue: queue)
    }

    func cancel() { terminal = true; listener.cancel() }
}

struct WifiDiscoveryQuery {
    let purpose: StreamPurpose
    let nonce: Data
    let desktopId: Data
    let identityId: Data
}

enum WifiDiscoveryCodec {
    static let port: NWEndpoint.Port = 47_141
    private static let magic = Data([0x41, 0x50, 0x57, 0x44])
    private static let signatureDomain = Data("age-plugin-phone/wifi-discovery-response/v1".utf8)

    static func parse(_ data: Data, purpose: StreamPurpose) throws -> WifiDiscoveryQuery {
        guard data.count == 72, data.prefix(4) == magic, data[4] == 0, data[5] == 1,
              data[6] == 1, data[7] == purpose.rawValue else { throw StreamTransportError.malformed }
        let query = WifiDiscoveryQuery(purpose: purpose, nonce: Data(data[8..<40]), desktopId: Data(data[40..<56]), identityId: Data(data[56..<72]))
        if purpose == .pairing, query.identityId.contains(where: { $0 != 0 }) { throw StreamTransportError.malformed }
        return query
    }

    static func responsePrefix(_ query: WifiDiscoveryQuery) -> Data {
        magic + Data([0, 1, 2, query.purpose.rawValue]) + query.nonce + query.desktopId + query.identityId
    }

    static func signedResponse(_ query: WifiDiscoveryQuery, signingKey: SecureEnclave.P256.Signing.PrivateKey) throws -> Data {
        let prefix = responsePrefix(query)
        let signature = try OfflineEnvelopeCrypto.lowSSignature(
            try signingKey.signature(for: signatureDomain + Data([0]) + prefix).rawRepresentation
        )
        return prefix + signature
    }
}

final class WifiDiscoveryResponder {
    private let listener: NWListener
    private let purpose: StreamPurpose
    private let response: (WifiDiscoveryQuery) throws -> Data?
    private let queue = DispatchQueue(label: "io.github.biulight.phone-identity.discovery")

    init(purpose: StreamPurpose, response: @escaping (WifiDiscoveryQuery) throws -> Data?) throws {
        self.purpose = purpose; self.response = response
        let parameters = NWParameters.udp; parameters.allowLocalEndpointReuse = false
        listener = try NWListener(using: parameters, on: WifiDiscoveryCodec.port)
    }

    func start() {
        listener.newConnectionHandler = { [weak self] connection in self?.handle(connection) }
        listener.start(queue: queue)
    }

    func cancel() { listener.cancel() }

    private func handle(_ connection: NWConnection) {
        connection.start(queue: queue)
        connection.receiveMessage { [weak self] data, context, _, _ in
            guard let self, let data, let query = try? WifiDiscoveryCodec.parse(data, purpose: self.purpose),
                  let response = try? self.response(query) else { connection.cancel(); return }
            connection.send(content: response, contentContext: context ?? .defaultMessage, isComplete: true, completion: .contentProcessed { _ in connection.cancel() })
        }
    }
}
