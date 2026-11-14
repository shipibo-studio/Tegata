import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// A byte buffer for a secret. Zeroed on deinit, `mlock`ed best-effort, never printed by `description`.
/// Immutable after init, so it is safe to share across tasks.
public final class SecretBytes: @unchecked Sendable, CustomStringConvertible {
    private let storage: UnsafeMutableRawBufferPointer
    public let count: Int

    public init(_ bytes: some Collection<UInt8>) {
        count = bytes.count
        storage = UnsafeMutableRawBufferPointer.allocate(byteCount: max(bytes.count, 1), alignment: 1)
        _ = storage.initializeMemory(as: UInt8.self, from: bytes)
        if bytes.isEmpty { storage[0] = 0 }
        #if canImport(Darwin)
        _ = mlock(storage.baseAddress, storage.count)
        #endif
    }

    public convenience init(utf8 string: String) { self.init(Array(string.utf8)) }

    deinit {
        Self.zero(storage)
        #if canImport(Darwin)
        _ = munlock(storage.baseAddress, storage.count)
        #endif
        storage.deallocate()
    }

    /// Runs `body` over the bytes. Do not let the pointer escape.
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: storage.baseAddress, count: count))
    }

    /// Constant-time comparison.
    public func isEqual(to other: SecretBytes) -> Bool {
        guard count == other.count else { return false }
        var diff: UInt8 = 0
        withUnsafeBytes { a in other.withUnsafeBytes { b in for i in 0..<count { diff |= a[i] ^ b[i] } } }
        return diff == 0
    }

    public var description: String { "SecretBytes(\(count) bytes)" }

    /// Overwrites a buffer so the compiler cannot elide the store.
    public static func zero(_ buffer: UnsafeMutableRawBufferPointer) {
        guard let base = buffer.baseAddress, buffer.count > 0 else { return }
        #if canImport(Darwin)
        _ = memset_s(base, buffer.count, 0, buffer.count)
        #else
        let p = base.assumingMemoryBound(to: UInt8.self)
        for i in 0..<buffer.count { (p + i).pointee = 0 }
        #endif
    }
}
