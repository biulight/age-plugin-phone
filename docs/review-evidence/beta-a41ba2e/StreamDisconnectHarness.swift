import Foundation

// Test double for deterministic delivery of Network.framework callbacks.
// The production PhoneStreamSession and StreamTransportCodec are compiled unchanged.
enum TestError: Error { case disconnected }
final class NWConnection {
    enum State { case ready, failed(Error), cancelled }
    struct ContentContext { static let finalMessage = ContentContext() }
    enum SendCompletion { case contentProcessed((Error?) -> Void) }
    var stateUpdateHandler: ((State) -> Void)?
    var bytes = Data()
    var sends = 0
    var cancels = 0
    func start(queue: DispatchQueue) { stateUpdateHandler?(.ready) }
    func receive(minimumIncompleteLength: Int, maximumLength: Int,
                 completion: (Data?, ContentContext?, Bool, Error?) -> Void) {
        let data = Data(bytes.prefix(maximumLength)); bytes.removeFirst(data.count)
        completion(data, nil, false, nil)
    }
    func send(content: Data, contentContext: ContentContext, isComplete: Bool,
              completion: SendCompletion) {
        sends += 1
        if case .contentProcessed(let callback) = completion { callback(nil) }
    }
    func cancel() { cancels += 1; stateUpdateHandler?(.cancelled) }
}

@main struct StreamDisconnectHarness {
    static func main() throws {
        let connection = NWConnection()
        connection.bytes = try StreamTransportCodec.encode(
            purpose: .unwrap, direction: 1, sessionId: Data(repeating: 1, count: 16), body: Data([42]))
        let session = PhoneStreamSession(connection: connection, purpose: .unwrap)
        var requestCallbacks = 0
        session.start { _ in requestCallbacks += 1 }
        connection.stateUpdateHandler?(.failed(TestError.disconnected))
        print("after delivered request + failed callback: requestCallbacks=\(requestCallbacks) cancelCalls=\(connection.cancels)")
        session.sendResponse(Data([43])) { result in print("late response result: \(result)") }
        print("late response sendCalls=\(connection.sends)")
        precondition(requestCallbacks == 1 && connection.sends == 1)
    }
}
