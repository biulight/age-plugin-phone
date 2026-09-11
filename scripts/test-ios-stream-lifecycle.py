#!/usr/bin/env python3
"""Compile the iOS stream session with a callback test double and verify disconnect closure."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "plugins/tauri-plugin-phone-identity/ios/Sources/StreamTransport.swift"
HARNESS = r'''
import Foundation

enum TestError: Error { case disconnected }
final class NWConnection {
    enum State { case ready, failed(Error), cancelled, waiting }
    struct ContentContext { static let finalMessage = ContentContext() }
    enum SendCompletion { case contentProcessed((Error?) -> Void) }
    var stateUpdateHandler: ((State) -> Void)?
    var bytes = Data()
    var sends = 0
    var cancels = 0
    var stateOnStart: State = .ready
    var pendingReceive: ((Data?, ContentContext?, Bool, Error?) -> Void)?
    var completeWithLastBytes = false
    func start(queue: DispatchQueue) { stateUpdateHandler?(stateOnStart) }
    func receive(minimumIncompleteLength: Int, maximumLength: Int,
                 completion: @escaping (Data?, ContentContext?, Bool, Error?) -> Void) {
        guard !bytes.isEmpty else {
            pendingReceive = completion
            return
        }
        let data = Data(bytes.prefix(maximumLength)); bytes.removeFirst(data.count)
        completion(data, nil, completeWithLastBytes && bytes.isEmpty, nil)
    }
    func send(content: Data, contentContext: ContentContext, isComplete: Bool,
              completion: SendCompletion) {
        sends += 1
        if case .contentProcessed(let callback) = completion { callback(nil) }
    }
    func cancel() { cancels += 1; stateUpdateHandler?(.cancelled) }
    func peerCloses() {
        let callback = pendingReceive
        pendingReceive = nil
        callback?(nil, nil, true, nil)
    }
}

@main struct Harness {
    static func main() throws {
        let connection = NWConnection()
        connection.bytes = try StreamTransportCodec.encode(
            purpose: .unwrap, direction: 1,
            sessionId: Data(repeating: 1, count: 16), body: Data([42]))
        let session = PhoneStreamSession(connection: connection, purpose: .unwrap)
        var requestCallbacks = 0
        var disconnectCallbacks = 0
        session.watchPeerDisconnect { disconnectCallbacks += 1 }
        session.start { _ in requestCallbacks += 1 }
        connection.peerCloses()
        var lateSendFailed = false
        session.sendResponse(Data([43])) { result in
            if case .failure = result { lateSendFailed = true }
        }
        precondition(requestCallbacks == 1)
        precondition(disconnectCallbacks == 1)
        precondition(lateSendFailed)
        precondition(connection.sends == 0)

        let lateWatch = NWConnection()
        lateWatch.bytes = try StreamTransportCodec.encode(
            purpose: .unwrap, direction: 1,
            sessionId: Data(repeating: 3, count: 16), body: Data([45]))
        let lateWatchSession = PhoneStreamSession(connection: lateWatch, purpose: .unwrap)
        var lateWatchCallbacks = 0
        lateWatchSession.start { _ in }
        lateWatch.peerCloses()
        lateWatchSession.watchPeerDisconnect { lateWatchCallbacks += 1 }
        precondition(lateWatchCallbacks == 1)

        let coalescedClose = NWConnection()
        coalescedClose.bytes = try StreamTransportCodec.encode(
            purpose: .unwrap, direction: 1,
            sessionId: Data(repeating: 4, count: 16), body: Data([46]))
        coalescedClose.completeWithLastBytes = true
        let coalescedSession = PhoneStreamSession(connection: coalescedClose, purpose: .unwrap)
        var coalescedRequestCallbacks = 0
        var coalescedDisconnectCallbacks = 0
        coalescedSession.watchPeerDisconnect { coalescedDisconnectCallbacks += 1 }
        coalescedSession.start { _ in coalescedRequestCallbacks += 1 }
        precondition(coalescedRequestCallbacks == 1)
        precondition(coalescedDisconnectCallbacks == 1)

        let initialFailure = NWConnection()
        initialFailure.stateOnStart = .failed(TestError.disconnected)
        let failedSession = PhoneStreamSession(connection: initialFailure, purpose: .unwrap)
        var initialFailureCallbacks = 0
        var initialDisconnectCallbacks = 0
        failedSession.watchPeerDisconnect { initialDisconnectCallbacks += 1 }
        failedSession.start { result in
            if case .failure = result { initialFailureCallbacks += 1 }
        }
        precondition(initialFailureCallbacks == 1)
        precondition(initialDisconnectCallbacks == 0)

        let localClose = NWConnection()
        localClose.bytes = try StreamTransportCodec.encode(
            purpose: .unwrap, direction: 1,
            sessionId: Data(repeating: 2, count: 16), body: Data([44]))
        let localSession = PhoneStreamSession(connection: localClose, purpose: .unwrap)
        var localDisconnectCallbacks = 0
        localSession.start { _ in }
        localSession.watchPeerDisconnect { localDisconnectCallbacks += 1 }
        localSession.close()
        precondition(localDisconnectCallbacks == 0)
    }
}
'''

with tempfile.TemporaryDirectory(prefix="phone-ios-stream-test-") as temporary:
    work = Path(temporary)
    session_source = work / "StreamSession.swift"
    session_source.write_text(
        SOURCE.read_text().split("final class ForegroundStreamListener")[0]
        .replace("import Network\n", "")
    )
    harness = work / "Harness.swift"
    harness.write_text(HARNESS)
    executable = work / "stream-lifecycle"
    subprocess.run([
        "swiftc", "-module-cache-path", str(work / "module-cache"),
        str(session_source), str(harness), "-o", str(executable)
    ], check=True)
    subprocess.run([str(executable)], check=True)
