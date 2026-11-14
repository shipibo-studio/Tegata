import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// The full baseline: every entry as the model knows it, and every entry exactly as its file wrote it (for
/// Revert). It is only ever written to disk encrypted; opening it needs the user's Touch ID.
public struct IntegritySnapshot: Codable, Sendable, Equatable {
    public var version: Int
    public var createdAt: Date
    public var extensions: [AgentExtension]
    public var raw: [String: RawEntry]

    public init(createdAt: Date, extensions: [AgentExtension], raw: [String: RawEntry], version: Int = 1) {
        self.version = version; self.createdAt = createdAt; self.extensions = extensions; self.raw = raw
    }

    /// The snapshot and its index from one scan. The index is derived from the same inventory, so the two agree.
    public static func make(inventory: AgentInventory, raw: [String: RawEntry], classifier: RiskClassifier, now: Date) -> (IntegritySnapshot, IntegrityIndex) {
        let index = IntegrityIndex.make(inventory: inventory, findings: classifier.classify(inventory), now: now)
        return (IntegritySnapshot(createdAt: now.wholeSeconds, extensions: inventory.extensions, raw: raw), index)
    }
}

// MARK: accepting changes

extension IntegrityIndex {
    /// The baseline with only `ids` brought up to date from `current`: an id present now is taken as it is now, an id gone
    /// now is dropped, and every other entry stays exactly as it was. This is Approve, and it is also how Tegata records
    /// its own writes: accepting one change can never accept another that happened at the same time.
    public func accepting(_ ids: Set<String>, from current: AgentInventory, findings: [RiskFinding], now: Date) -> IntegrityIndex {
        let fresh = IntegrityIndex.make(inventory: current, findings: findings.filter { ids.contains($0.extensionId) }, now: now)
        var merged = self
        for id in ids { merged.entries[id] = fresh.entries[id] }
        merged.createdAt = now.wholeSeconds
        return merged
    }

    /// The same baseline, recorded as read with the current rules (after every difference they explain was accepted).
    public func withCurrentRules() -> IntegrityIndex {
        var i = self; i.rulesVersion = IntegrityRules.version; return i
    }
}

extension IntegritySnapshot {
    /// Same rule as `IntegrityIndex.accepting`, for the encrypted side: the entries and their raw form for `ids` only.
    public func accepting(_ ids: Set<String>, from current: AgentInventory, raw: [String: RawEntry]) -> IntegritySnapshot {
        let currentById = current.byId
        var kept = extensions.filter { !ids.contains($0.id) }
        kept += ids.compactMap { currentById[$0] }
        var rawMerged = self.raw.filter { !ids.contains($0.key) }
        for id in ids { if let r = raw[id] { rawMerged[id] = r } }
        return IntegritySnapshot(createdAt: createdAt, extensions: kept.sorted { $0.id < $1.id }, raw: rawMerged, version: version)
    }
}

/// Authenticates the index so that a process that can write to the vault folder cannot approve its own change by
/// editing the baseline. The key must be readable by Tegata without a biometric prompt and by nothing else (a
/// keychain item in Tegata's access group on macOS); that storage is wired where the agent is built.
public protocol BaselineAuthenticator: Sendable {
    func authenticate(_ data: Data) -> Data
    func verify(_ mac: Data, for data: Data) -> Bool
}

public struct HMACBaselineAuthenticator: BaselineAuthenticator {
    private let key: SymmetricKey
    public init(key: SymmetricKey) { self.key = key }
    public func authenticate(_ data: Data) -> Data { Data(HMAC<SHA256>.authenticationCode(for: data, using: key)) }
    public func verify(_ mac: Data, for data: Data) -> Bool { HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: data, using: key) }
}

public enum IntegrityStoreError: Error, Equatable, Sendable {
    case noBaseline
    /// The index does not match its authentication code: someone edited it, or the key changed. Treat the baseline as
    /// untrusted and ask the user to review and take a new one.
    case indexTampered
    /// The snapshot belongs to another index (a half-finished write, or one file was replaced).
    case snapshotMismatch
    case snapshotCorrupt(String)
    case unsupportedVersion(Int)
}

/// Where the baseline lives. Two files with different access rules:
///
/// - `integrity-index.json`: fingerprints, severities and names, no content, authenticated with an HMAC. The
///   background watcher reads it to notice changes, with no Touch ID.
/// - `integrity-snapshot.ags`: the entries themselves, sealed with ChaCha20-Poly1305 under a fresh key that the
///   `KeyProvider` wraps. Writing needs no user presence (`wrap`); reading needs it (`unwrap`), for the diff view
///   and for Revert alike.
///
/// If the key is invalidated (the fingerprint set changed) the snapshot is unreadable and the baseline is retaken
/// from the current state; nothing in it is irreplaceable, like the vault.
public actor IntegrityStore {
    static let snapshotMagic = Data("AGS1".utf8)
    static let snapshotVersion: UInt16 = 1
    static let prefixLength = 10

    struct Header: Codable, Equatable {
        var v: Int
        var created: Date
        var provider: String
        var keyTag: String
        var wrapAlg: String
        var wrappedDEK: Data
        var dekAlg: String
        /// SHA-256 of the index file's payload bytes: binds this snapshot to exactly one index.
        var indexDigest: Data
        enum CodingKeys: String, CodingKey { case v, created, provider, keyTag = "key_tag", wrapAlg = "wrap_alg", wrappedDEK = "wrapped_dek", dekAlg = "dek_alg", indexDigest = "index_digest" }
    }

    struct IndexFile: Codable { var payload: Data; var mac: Data }

    public let directory: URL
    let provider: any KeyProvider
    let keyTag: String
    let authenticator: any BaselineAuthenticator

    var indexURL: URL { directory.appendingPathComponent("integrity-index.json") }
    var snapshotURL: URL { directory.appendingPathComponent("integrity-snapshot.ags") }

    public init(directory: URL, provider: any KeyProvider, keyTag: String, authenticator: any BaselineAuthenticator) {
        self.directory = directory; self.provider = provider; self.keyTag = keyTag; self.authenticator = authenticator
    }

    public func hasBaseline() -> Bool {
        FileManager.default.fileExists(atPath: indexURL.path) && FileManager.default.fileExists(atPath: snapshotURL.path)
    }

    // MARK: write (no user presence)

    public func writeBaseline(snapshot: IntegritySnapshot, index: IntegrityIndex) async throws {
        let fm = FileManager.default
        if !fm.fileExists(atPath: directory.path) { try fm.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) }

        let payload = try SealedCoding.makeEncoder().encode(index)
        let indexBytes = try SealedCoding.makeEncoder().encode(IndexFile(payload: payload, mac: authenticator.authenticate(payload)))

        let dek = SealedCoding.newDEK()
        let header = Header(v: Int(Self.snapshotVersion), created: index.createdAt, provider: provider.providerID, keyTag: keyTag,
                            wrapAlg: provider.wrapAlgorithm, wrappedDEK: try await provider.wrap(dek, tag: keyTag),
                            dekAlg: SealedCoding.dekAlgorithm, indexDigest: Data(SHA256.hash(data: payload)))
        let headerBytes = try SealedCoding.makeEncoder().encode(header)
        let box = try ChaChaPoly.seal(try SealedCoding.makeEncoder().encode(snapshot), using: dek, authenticating: headerBytes)
        var out = Data(Self.snapshotMagic)
        out.append(contentsOf: Self.snapshotVersion.bigEndianBytes)
        out.append(contentsOf: UInt32(headerBytes.count).bigEndianBytes)
        out.append(headerBytes)
        out.append(box.combined)

        // Both files are staged before either is moved into place, snapshot first: an interrupted write leaves an
        // index whose digest no longer matches (reported as `snapshotMismatch`), never a snapshot nobody can verify.
        try stage(out, at: snapshotURL)
        try stage(indexBytes, at: indexURL)
    }

    // MARK: read

    /// The authenticated index. Needs no Touch ID; this is what the watcher calls on every change.
    public func loadIndex() throws -> IntegrityIndex {
        let (index, _) = try readIndex()
        return index
    }

    /// The decrypted snapshot. `unwrap` asks for the user's presence through `authorization`.
    public func openSnapshot(authorization: (any UnlockAuthorization)?) async throws -> IntegritySnapshot {
        let (_, payload) = try readIndex()
        guard let data = try? Data(contentsOf: snapshotURL) else { throw IntegrityStoreError.noBaseline }
        guard data.count >= Self.prefixLength, data.prefix(4) == Self.snapshotMagic else { throw IntegrityStoreError.snapshotCorrupt("bad magic") }
        let d = Data(data)
        let ver = UInt16(bigEndianBytes: d[4..<6])
        guard ver == Self.snapshotVersion else { throw IntegrityStoreError.unsupportedVersion(Int(ver)) }
        let hl = Int(UInt32(bigEndianBytes: d[6..<10]))
        guard hl > 0, d.count > Self.prefixLength + hl else { throw IntegrityStoreError.snapshotCorrupt("truncated") }
        let headerBytes = d[Self.prefixLength..<(Self.prefixLength + hl)]
        guard let header = try? SealedCoding.makeDecoder().decode(Header.self, from: headerBytes), header.dekAlg == SealedCoding.dekAlgorithm else {
            throw IntegrityStoreError.snapshotCorrupt("header")
        }
        guard header.indexDigest == Data(SHA256.hash(data: payload)) else { throw IntegrityStoreError.snapshotMismatch }

        let dek = try await provider.unwrap(header.wrappedDEK, tag: header.keyTag, authorization: authorization)
        let plaintext: Data
        do {
            let box = try ChaChaPoly.SealedBox(combined: d[(Self.prefixLength + hl)...])
            plaintext = try ChaChaPoly.open(box, using: dek, authenticating: Data(headerBytes))
        } catch { throw IntegrityStoreError.snapshotCorrupt("authentication failed") }
        guard let snapshot = try? SealedCoding.makeDecoder().decode(IntegritySnapshot.self, from: plaintext) else { throw IntegrityStoreError.snapshotCorrupt("payload") }
        guard snapshot.version == 1 else { throw IntegrityStoreError.unsupportedVersion(snapshot.version) }
        return snapshot
    }

    /// Accepts `ids` as they are in `current` and keeps everything else (see `IntegrityIndex.accepting`). It reads the old
    /// snapshot, so it asks for the user's presence like any other read of it.
    public func accept(_ ids: Set<String>, current: AgentInventory, raw: [String: RawEntry], findings: [RiskFinding],
                       now: Date, authorization: (any UnlockAuthorization)?, markRulesCurrent: Bool = false) async throws {
        let index = try loadIndex()
        let snapshot = try await openSnapshot(authorization: authorization)
        var s = snapshot.accepting(ids, from: current, raw: raw)
        s.createdAt = now.wholeSeconds
        var merged = index.accepting(ids, from: current, findings: findings, now: now)
        if markRulesCurrent { merged = merged.withCurrentRules() }
        try await writeBaseline(snapshot: s, index: merged)
    }

    public func removeBaseline() throws {
        for u in [indexURL, snapshotURL] where FileManager.default.fileExists(atPath: u.path) { try FileManager.default.removeItem(at: u) }
    }

    // MARK: files

    func readIndex() throws -> (IntegrityIndex, Data) {
        guard let bytes = try? Data(contentsOf: indexURL) else { throw IntegrityStoreError.noBaseline }
        guard let file = try? SealedCoding.makeDecoder().decode(IndexFile.self, from: bytes) else { throw IntegrityStoreError.indexTampered }
        guard authenticator.verify(file.mac, for: file.payload) else { throw IntegrityStoreError.indexTampered }
        guard let index = try? SealedCoding.makeDecoder().decode(IntegrityIndex.self, from: file.payload) else { throw IntegrityStoreError.indexTampered }
        guard index.version == 1 else { throw IntegrityStoreError.unsupportedVersion(index.version) }
        return (index, file.payload)
    }

    /// Writes next to the target with mode 0600 and moves it into place atomically.
    func stage(_ data: Data, at url: URL) throws {
        let tmp = url.appendingPathExtension("tmp")
        try? FileManager.default.removeItem(at: tmp)
        guard FileManager.default.createFile(atPath: tmp.path, contents: data, attributes: [.posixPermissions: 0o600]) else {
            throw IntegrityStoreError.snapshotCorrupt("cannot write \(tmp.lastPathComponent)")
        }
        if FileManager.default.fileExists(atPath: url.path) { _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp) }
        else { try FileManager.default.moveItem(at: tmp, to: url) }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
