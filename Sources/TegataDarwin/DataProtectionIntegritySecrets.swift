import Foundation
import Security
import CryptoKit
import TegataCore

/// The integrity secrets in Tegata's data-protection keychain group. Same-user processes outside Tegata's access group
/// cannot read or write them. Needs the `keychain-access-groups` entitlement, so it serves the signed app and its agent;
/// a bare command-line binary cannot carry that entitlement.
public struct DataProtectionIntegritySecrets: IntegritySecrets {
    public static let defaultService = "app.tegata.integrity"
    static let keyAccount = "index-hmac-key"
    static let markerAccount = "baseline-established"
    let service: String
    public init(service: String = DataProtectionIntegritySecrets.defaultService) { self.service = service }

    private func base(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account,
         kSecUseDataProtectionKeychain as String: true]
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

    func delete(_ account: String) { SecItemDelete(base(account) as CFDictionary) }

    /// Created on first use; 32 random bytes that never leave the keychain and this process.
    public func hmacKey() throws -> SymmetricKey {
        if let d = read(Self.keyAccount), d.count == 32 { return SymmetricKey(data: d) }
        let k = SymmetricKey(size: .bits256)
        try write(Self.keyAccount, k.withUnsafeBytes { Data($0) })
        return k
    }

    public var established: Date? {
        read(Self.markerAccount).flatMap { String(data: $0, encoding: .utf8) }.flatMap { ISO8601DateFormatter().date(from: $0) }
    }
    public func setEstablished(_ date: Date) throws { try write(Self.markerAccount, Data(ISO8601DateFormatter().string(from: date).utf8)) }

    public func forget() {
        delete(Self.keyAccount)
        delete(Self.markerAccount)
    }
}
