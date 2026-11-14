import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Software P-256 stand-in for the Secure Enclave. ECDH with an ephemeral key, HKDF-SHA256, AES-GCM.
/// Wire format of a wrapped DEK: ephemeral public key (X9.63, 65 bytes) || AES.GCM combined box.
/// Test hooks: `simulateBiometryChange` invalidates a key; `requireAuthorization` makes `unwrap`
/// demand a non-nil authorization; `unwrapCount` counts unwraps (for coalescing tests).
public actor InMemoryKeyProvider: KeyProvider {
    public nonisolated let providerID = "in-memory-p256"
    public nonisolated let wrapAlgorithm = "p256-ecdh-hkdf-sha256-aes-gcm"

    private var keys: [String: P256.KeyAgreement.PrivateKey] = [:]
    private var invalidated: Set<String> = []
    public var requireAuthorization = false
    public private(set) var unwrapCount = 0
    /// Optional delay inside `unwrap`, to widen the window in concurrency tests.
    public var unwrapDelay: Duration = .zero

    public init() {}

    public func setRequireAuthorization(_ v: Bool) { requireAuthorization = v }
    public func setUnwrapDelay(_ d: Duration) { unwrapDelay = d }

    public func createKey(tag: String) throws {
        guard keys[tag] == nil else { throw KeyProviderError.keyAlreadyExists }
        keys[tag] = P256.KeyAgreement.PrivateKey()
        invalidated.remove(tag)
    }

    public func wrap(_ dek: SymmetricKey, tag: String) throws -> Data {
        guard let priv = keys[tag] else { throw KeyProviderError.keyNotFound }
        let eph = P256.KeyAgreement.PrivateKey()
        let kek = try Self.derive(eph.sharedSecretFromKeyAgreement(with: priv.publicKey), salt: eph.publicKey.x963Representation)
        let box = try AES.GCM.seal(dek.withUnsafeBytes { Data($0) }, using: kek)
        guard let combined = box.combined else { throw KeyProviderError.wrapFailed("no combined box") }
        return eph.publicKey.x963Representation + combined
    }

    public func unwrap(_ wrapped: Data, tag: String, authorization: (any UnlockAuthorization)?) async throws -> SymmetricKey {
        if unwrapDelay > .zero { try? await Task.sleep(for: unwrapDelay) }
        unwrapCount += 1
        guard keys[tag] != nil else { throw KeyProviderError.keyNotFound }
        if invalidated.contains(tag) { throw KeyProviderError.keyInvalidated }
        if requireAuthorization, authorization == nil { throw KeyProviderError.authorizationRequired }
        guard wrapped.count > 65 else { throw KeyProviderError.unwrapFailed("too short") }
        let priv = keys[tag]!
        let ephData = wrapped.prefix(65)
        do {
            let eph = try P256.KeyAgreement.PublicKey(x963Representation: ephData)
            let kek = try Self.derive(priv.sharedSecretFromKeyAgreement(with: eph), salt: ephData)
            let box = try AES.GCM.SealedBox(combined: wrapped.dropFirst(65))
            return SymmetricKey(data: try AES.GCM.open(box, using: kek))
        } catch {
            throw KeyProviderError.unwrapFailed(String(describing: error))
        }
    }

    public func destroyKey(tag: String) throws {
        keys.removeValue(forKey: tag)
        invalidated.remove(tag)
    }

    public func state(tag: String) -> KeyState {
        guard keys[tag] != nil else { return .absent }
        return invalidated.contains(tag) ? .invalidated : .present
    }

    /// Mimics what `biometryCurrentSet` does after the enrolled set changes.
    public func simulateBiometryChange(tag: String) { if keys[tag] != nil { invalidated.insert(tag) } }

    private static func derive(_ shared: SharedSecret, salt: Data) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data("tegata-dek-wrap-v1".utf8), outputByteCount: 32)
    }
}
