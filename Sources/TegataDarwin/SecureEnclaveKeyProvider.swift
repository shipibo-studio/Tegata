import Foundation
import Security
import CryptoKit
import LocalAuthentication
import TegataCore

/// Authorization handed to `unwrap`: a pre-evaluated LAContext.
public struct LAAuthorization: UnlockAuthorization, @unchecked Sendable {
    public let context: LAContext
    public init(context: LAContext) { self.context = context }
}

/// P-256 key in the Secure Enclave, stored in the Data Protection keychain (needs the app's
/// `keychain-access-groups` entitlement, so a signed app bundle with a provisioning profile), ACL `[.privateKeyUsage,
/// .biometryCurrentSet]`. Wrapping uses the public half (no prompt); unwrapping needs the LAContext.
public actor SecureEnclaveKeyProvider: KeyProvider {
    public init() {}
    public nonisolated let providerID = "secure-enclave-p256"
    public nonisolated let wrapAlgorithm = "eciesEncryptionCofactorVariableIVX963SHA256AESGCM"
    private let alg: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    private var knownInvalidated: Set<String> = []

    private func tagData(_ tag: String) -> Data { Data(tag.utf8) }

    private func query(tag: String, context: LAContext?, returnRef: Bool) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData(tag),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if returnRef { q[kSecReturnRef as String] = true } else { q[kSecReturnAttributes as String] = true }
        if let c = context { q[kSecUseAuthenticationContext as String] = c }
        return q
    }

    private static func describe(_ e: Unmanaged<CFError>?) -> String {
        guard let e = e?.takeRetainedValue() else { return "unknown" }
        let ns = e as Error as NSError
        return "\(ns.domain) \(ns.code): \(ns.localizedDescription)"
    }

    public func createKey(tag: String) throws {
        if case .present = state(tag: tag) { throw KeyProviderError.keyAlreadyExists }
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                       [.privateKeyUsage, .biometryCurrentSet], &err) else {
            throw KeyProviderError.wrapFailed("SecAccessControlCreateWithFlags: \(Self.describe(err))")
        }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tagData(tag),
                kSecAttrAccessControl as String: ac,
            ] as [String: Any],
        ]
        guard SecKeyCreateRandomKey(attrs as CFDictionary, &err) != nil else {
            throw KeyProviderError.wrapFailed("SecKeyCreateRandomKey: \(Self.describe(err))")
        }
        knownInvalidated.remove(tag)
    }

    private func loadKey(tag: String, context: LAContext?) throws -> SecKey {
        var item: CFTypeRef?
        let st = SecItemCopyMatching(query(tag: tag, context: context, returnRef: true) as CFDictionary, &item)
        guard st == errSecSuccess, let key = item else {
            if st == errSecItemNotFound { throw KeyProviderError.keyNotFound }
            if st == errSecUserCanceled { throw KeyProviderError.userCancelled }
            throw KeyProviderError.unwrapFailed("SecItemCopyMatching: \(st)")
        }
        return key as! SecKey
    }

    public func wrap(_ dek: SymmetricKey, tag: String) throws -> Data {
        let priv = try loadKey(tag: tag, context: nil)
        guard let pub = SecKeyCopyPublicKey(priv) else { throw KeyProviderError.wrapFailed("no public key") }
        var err: Unmanaged<CFError>?
        let plain = dek.withUnsafeBytes { Data($0) }
        guard let sealed = SecKeyCreateEncryptedData(pub, alg, plain as CFData, &err) else {
            throw KeyProviderError.wrapFailed("SecKeyCreateEncryptedData: \(Self.describe(err))")
        }
        return sealed as Data
    }

    public func unwrap(_ wrapped: Data, tag: String, authorization: (any UnlockAuthorization)?) throws -> SymmetricKey {
        if knownInvalidated.contains(tag) { throw KeyProviderError.keyInvalidated }
        guard let auth = authorization as? LAAuthorization else { throw KeyProviderError.authorizationRequired }
        let priv = try loadKey(tag: tag, context: auth.context)
        var err: Unmanaged<CFError>?
        guard let plain = SecKeyCreateDecryptedData(priv, alg, wrapped as CFData, &err) else {
            let e = err?.takeRetainedValue()
            let code = e.map { ($0 as Error as NSError).code } ?? 0
            switch Int32(code) {
            case errSecUserCanceled: throw KeyProviderError.userCancelled
            case errSecAuthFailed, errSecItemNotFound:
                // With a successfully evaluated context, an ACL failure means the biometry set changed.
                knownInvalidated.insert(tag)
                throw KeyProviderError.keyInvalidated
            default:
                throw KeyProviderError.unwrapFailed("SecKeyCreateDecryptedData: \(Self.describe(err))")
            }
        }
        defer { var p = plain as Data; p.withUnsafeMutableBytes { SecretBytes.zero($0) } }
        return SymmetricKey(data: plain as Data)
    }

    public func destroyKey(tag: String) throws {
        var q = query(tag: tag, context: nil, returnRef: false)
        q.removeValue(forKey: kSecReturnAttributes as String)
        let st = SecItemDelete(q as CFDictionary)
        knownInvalidated.remove(tag)
        guard st == errSecSuccess || st == errSecItemNotFound else { throw KeyProviderError.unwrapFailed("SecItemDelete: \(st)") }
    }

    public func state(tag: String) -> KeyState {
        var item: CFTypeRef?
        let st = SecItemCopyMatching(query(tag: tag, context: nil, returnRef: false) as CFDictionary, &item)
        guard st == errSecSuccess else { return .absent }
        return knownInvalidated.contains(tag) ? .invalidated : .present
    }
}
