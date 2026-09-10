import Foundation
import XCTest
@testable import PhoneIdentityCore

final class AuthenticationDeadlineTests: XCTestCase {
    func testTimerRevokesPendingAuthorization() {
        let revoked = expectation(description: "pending native context revoked")
        let deadline = AuthenticationDeadline(timeout: 0.02) { revoked.fulfill() }
        wait(for: [revoked], timeout: 2)
        XCTAssertFalse(deadline.complete())
        deadline.invalidate()
    }

    func testLateCompletionCannotBeatAnUndeliveredTimer() {
        var clock: TimeInterval = 10
        var revocations = 0
        let deadline = AuthenticationDeadline(timeout: 60, now: { clock }) { revocations += 1 }
        clock = 70
        XCTAssertFalse(deadline.complete())
        XCTAssertFalse(deadline.complete())
        deadline.invalidate()
        XCTAssertEqual(revocations, 1)
    }

    func testCancellationIsTerminalAndNextOperationIsIndependent() {
        var revocations = 0
        let cancelled = AuthenticationDeadline(timeout: 60) { revocations += 1 }
        cancelled.invalidate()
        XCTAssertFalse(cancelled.complete())
        let next = AuthenticationDeadline(timeout: 60) { XCTFail("new operation was revoked") }
        XCTAssertTrue(next.complete())
        XCTAssertFalse(next.complete())
        cancelled.invalidate()
        next.invalidate()
        XCTAssertEqual(revocations, 1)
    }

    func testClockRollbackAndNonfiniteClockFailClosed() {
        for invalid in [9.0, Double.nan, Double.infinity] {
            var clock: TimeInterval = 10
            var revocations = 0
            let deadline = AuthenticationDeadline(timeout: 60, now: { clock }) { revocations += 1 }
            clock = invalid
            XCTAssertFalse(deadline.complete())
            XCTAssertEqual(revocations, 1)
        }
    }

    func testRacingCompletionAndInvalidationHaveOnlyOneWinner() {
        let lock = NSLock()
        var completed = 0
        var revoked = 0
        let deadline = AuthenticationDeadline(timeout: 60) {
            lock.lock(); revoked += 1; lock.unlock()
        }
        DispatchQueue.concurrentPerform(iterations: 32) { index in
            if index.isMultiple(of: 2) {
                if deadline.complete() { lock.lock(); completed += 1; lock.unlock() }
            } else { deadline.invalidate() }
        }
        XCTAssertEqual(completed + revoked, 1)
        XCTAssertFalse(deadline.complete())
    }
}
