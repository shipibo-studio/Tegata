import Foundation
import Security
import CryptoKit
import LocalAuthentication
import TegataCore

/// Whether this process carries a keychain access group: true for the CLI shipped in its signed bundle (launched
/// directly or through a symlink), false for a plain build. Decides where `tegata watch` keeps its secrets.
public enum ProcessEntitlements {
    public static var keychainAccessGroup: String? {
        guard let task = SecTaskCreateFromSelf(nil),
              let groups = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil) as? [String] else { return nil }
        return groups.first
    }
}

/// Option B for plain builds: the integrity secrets in the login keychain. Other apps that ask for these items get a
/// macOS prompt naming the item, which the user could approve; weaker than an access group and said so in `watch status`.
public struct LoginKeychainIntegritySecrets: IntegritySecrets {
    let service: String
    public init(service: String) { self.service = service }

    private func base(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    }
    func read(_ account: String) -> Data? {
        var q = base(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
    }
    func write(_ account: String, _ data: Data) throws {
        SecItemDelete(base(account) as CFDictionary)
        var q = base(account)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw IntegrityMonitorError("keychain write \(account): \(status)") }
    }
    public func hmacKey() throws -> SymmetricKey {
        if let d = read("index-hmac-key"), d.count == 32 { return SymmetricKey(data: d) }
        let k = SymmetricKey(size: .bits256)
        try write("index-hmac-key", k.withUnsafeBytes { Data($0) })
        return k
    }
    public var established: Date? {
        read("baseline-established").flatMap { String(data: $0, encoding: .utf8) }.flatMap { ISO8601DateFormatter().date(from: $0) }
    }
    public func setEstablished(_ date: Date) throws { try write("baseline-established", Data(ISO8601DateFormatter().string(from: date).utf8)) }
    public func forget() {
        SecItemDelete(base("index-hmac-key") as CFDictionary)
        SecItemDelete(base("baseline-established") as CFDictionary)
    }
}

/// Option B's key-encryption key: a Secure Enclave key made with CryptoKit, kept as the wrapped blob only this Mac's
/// Secure Enclave can use, in a 0600 file. Wrapping needs only its public half; unwrapping needs the key and, when
/// `requireBiometry`, a context the user unlocked with Touch ID. Any process of this user could ask the Secure Enclave
/// to use the blob without that flag, which is why the baseline's key is always made with it outside tests.
public actor SecureEnclaveBlobKeyProvider: KeyProvider {
    public nonisolated let providerID = "secure-enclave-blob-p256"
    public nonisolated let wrapAlgorithm = "p256-ecdh-hkdf-sha256-chachapoly"
    let directory: URL
    let requireBiometry: Bool

    public init(directory: URL, requireBiometry: Bool = true) { self.directory = directory; self.requireBiometry = requireBiometry }

    func blobURL(_ tag: String) -> URL { directory.appendingPathComponent(tag.replacingOccurrences(of: "/", with: "_") + ".se-key") }

    public func createKey(tag: String) throws {
        guard SecureEnclave.isAvailable else { throw KeyProviderError.wrapFailed("no Secure Enclave on this Mac") }
        if FileManager.default.fileExists(atPath: blobURL(tag).path) { throw KeyProviderError.keyAlreadyExists }
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if requireBiometry { flags.insert(.biometryCurrentSet) }
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil) else {
            throw KeyProviderError.wrapFailed("access control")
        }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try key.dataRepresentation.write(to: blobURL(tag), options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: blobURL(tag).path)
    }

    func load(_ tag: String, context: LAContext?) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        guard let blob = FileManager.default.contents(atPath: blobURL(tag).path) else { throw KeyProviderError.keyNotFound }
        do { return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: context) }
        catch { throw KeyProviderError.keyInvalidated }
    }

    static func derive(_ shared: SharedSecret, ephemeral: Data) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeral, sharedInfo: Data("tegata-kek-v1".utf8), outputByteCount: 32)
    }

    /// ephemeral public key (65 bytes, x9.63) || ChaChaPoly box of the DEK.
    public func wrap(_ dek: SymmetricKey, tag: String) throws -> Data {
        let pub = try load(tag, context: nil).publicKey
        let eph = P256.KeyAgreement.PrivateKey()
        let shared = try eph.sharedSecretFromKeyAgreement(with: pub)
        let ephPub = eph.publicKey.x963Representation
        let box = try ChaChaPoly.seal(dek.withUnsafeBytes { Data($0) }, using: Self.derive(shared, ephemeral: ephPub))
        return ephPub + box.combined
    }

    public func unwrap(_ wrapped: Data, tag: String, authorization: (any UnlockAuthorization)?) throws -> SymmetricKey {
        let context = (authorization as? LAAuthorization)?.context
        if requireBiometry && context == nil { throw KeyProviderError.authorizationRequired }
        guard wrapped.count > 65 else { throw KeyProviderError.unwrapFailed("short") }
        let key = try load(tag, context: context)
        let ephPub = wrapped.prefix(65)
        do {
            let shared = try key.sharedSecretFromKeyAgreement(with: try P256.KeyAgreement.PublicKey(x963Representation: ephPub))
            let plain = try ChaChaPoly.open(try ChaChaPoly.SealedBox(combined: wrapped.dropFirst(65)), using: Self.derive(shared, ephemeral: Data(ephPub)))
            return SymmetricKey(data: plain)
        } catch { throw KeyProviderError.unwrapFailed("\(error)") }
    }

    public func destroyKey(tag: String) throws {
        try? FileManager.default.removeItem(at: blobURL(tag))
    }

    public func state(tag: String) -> KeyState {
        FileManager.default.fileExists(atPath: blobURL(tag).path) ? .present : .absent
    }
}

/// Touch ID from a command line: biometrics or an Apple Watch only, no password fallback (D3).
public enum TouchID {
    /// Whether this Mac can ask for Touch ID (or an Apple Watch) now: a sensor, enrolled fingers, not locked out.
    public static var isAvailable: Bool {
        var err: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometricsOrWatch, error: &err)
    }

    public static func authorize(reason: String) async throws -> LAAuthorization {
        let ctx = LAContext()
        ctx.localizedCancelTitle = "Deny"
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometricsOrWatch, error: &err) else {
            throw IntegrityMonitorError("Touch ID is not available: \(err?.localizedDescription ?? "unknown")")
        }
        let ok: Bool = try await withCheckedThrowingContinuation { cont in
            ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometricsOrWatch, localizedReason: reason) { ok, e in
                if let e { cont.resume(throwing: e) } else { cont.resume(returning: ok) }
            }
        }
        guard ok else { throw IntegrityMonitorError("not authenticated") }
        return LAAuthorization(context: ctx)
    }
}
