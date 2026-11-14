import Foundation

/// Injectable time source (scans, edits, and the vault's cache, lockout and audit).
public protocol TimeSource: Sendable {
    var now: Date { get }
}
public struct SystemClock: TimeSource {
    public init() {}
    public var now: Date { Date() }
}
/// Manual clock for tests.
public final class ManualClock: TimeSource, @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date
    public init(_ start: Date = Date(timeIntervalSince1970: 1_700_000_000)) { current = start }
    public var now: Date { lock.withLock { current } }
    public func advance(by seconds: TimeInterval) { lock.withLock { current = current.addingTimeInterval(seconds) } }
}
