import Foundation

/// A single native operation's monotonic deadline, independent of transport reads.
/// The callback must revoke only the context belonging to this operation.
package final class AuthenticationDeadline: @unchecked Sendable {
    private enum State { case active, completed, invalidated }
    private let lock = NSLock()
    private var state: State = .active
    private let started: TimeInterval
    private let deadline: TimeInterval
    private let now: () -> TimeInterval
    private let revoke: () -> Void
    private var timer: DispatchWorkItem?

    package init(timeout: TimeInterval, now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }, revoke: @escaping () -> Void) {
        precondition(timeout.isFinite && timeout > 0)
        self.now = now
        self.started = now()
        self.deadline = started + timeout
        self.revoke = revoke
        let timer = DispatchWorkItem { [weak self] in self?.invalidate() }
        self.timer = timer
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + timeout, execute: timer)
    }

    /// Fails even if the timer queue has not yet delivered an expired deadline.
    package func complete() -> Bool {
        lock.lock()
        guard state == .active else { lock.unlock(); return false }
        let current = now()
        let accepted = current.isFinite && current >= started && current < deadline
        state = accepted ? .completed : .invalidated
        timer?.cancel()
        lock.unlock()
        if !accepted { revoke() }
        return accepted
    }

    package func invalidate() {
        lock.lock()
        guard state == .active else { lock.unlock(); return }
        state = .invalidated
        timer?.cancel()
        lock.unlock()
        revoke()
    }

    deinit { timer?.cancel() }
}
