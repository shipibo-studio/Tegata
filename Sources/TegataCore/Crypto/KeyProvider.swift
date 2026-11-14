import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public enum KeyState: String, Sendable, Equatable, Codable {
    case absent, present
    /// The key exists in name only: the platform invalidated it (biometry set changed).
    case invalidated
}

public enum KeyProviderError: Error, Equatable, Sendable {
    case keyAlreadyExists
    case keyNotFound
    case keyInvalidated
    case userCancelled
    case biometryLockout
    case authorizationRequired
    case wrapFailed(String)
    case unwrapFailed(String)
}

/// Opaque platform authorization handed to `unwrap` (an `LAContext` on Darwin, nothing in tests).
public protocol UnlockAuthorization: Sendable {}

/// Owns the key that wraps the vault's data-encryption key. `wrap` needs no user presence;
/// `unwrap` does. Implementations: `SecureEnclaveKeyProvider` (tegatad), `InMemoryKeyProvider` (tests).
public protocol KeyProvider: Sendable {
    /// Recorded in the vault header as `provider`, e.g. `secure-enclave-p256`.
    var providerID: String { get }
    /// Recorded in the vault header as `wrap_alg`.
    var wrapAlgorithm: String { get }

    func createKey(tag: String) async throws
    func wrap(_ dek: SymmetricKey, tag: String) async throws -> Data
    func unwrap(_ wrapped: Data, tag: String, authorization: (any UnlockAuthorization)?) async throws -> SymmetricKey
    func destroyKey(tag: String) async throws
    func state(tag: String) async -> KeyState
}

extension SymmetricKey {
    /// Copies the key material into a `SecretBytes`; the caller owns the copy.
    public var secretBytes: SecretBytes { withUnsafeBytes { SecretBytes($0) } }
}
