import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Shared encoding for everything Tegata seals or authenticates: the integrity baseline, its index,
/// quarantine records, and the private login vault. One definition, so the bytes stay identical
/// wherever a format is read back (sorted keys make the HMAC over an index reproducible).
public enum SealedCoding {
    /// Content encryption: ChaCha20-Poly1305 with a fresh 256-bit key per sealed file.
    public static let dekAlgorithm = "chacha20poly1305"

    public static func makeEncoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        e.dateEncodingStrategy = .iso8601
        return e
    }
    public static func makeDecoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }

    /// Generates a fresh 256-bit data-encryption key.
    public static func newDEK() -> SymmetricKey { SymmetricKey(size: .bits256) }
}

/// Big-endian length and version fields of the sealed file prefixes.
extension FixedWidthInteger {
    public var bigEndianBytes: [UInt8] { withUnsafeBytes(of: bigEndian) { Array($0) } }
    public init(bigEndianBytes: some Collection<UInt8>) {
        precondition(bigEndianBytes.count == MemoryLayout<Self>.size)
        self = bigEndianBytes.reduce(0) { ($0 << 8) | Self($1) }
    }
}
