import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// What the watcher reports after a check. Values are already redacted.
public struct IntegrityStatus: Codable, Sendable, Equatable {
    public enum Baseline: String, Codable, Sendable { case none, present, missing, tampered }
    public var baseline: Baseline
    public var baselineCreatedAt: Date?
    public var lastScan: Date?
    public var scanSeconds: Double?
    public var entries: Int
    /// Changes since the baseline, most important first. Values are already redacted.
    public var changes: [IntegrityChange]
    public var unreadableSources: [String]
    /// Paths and folders left unread on purpose or by failure (protected folders, broken links).
    public var notes: [String]
    public var signatureValid: Bool?
    public init(baseline: Baseline, baselineCreatedAt: Date?, lastScan: Date?, scanSeconds: Double?, entries: Int,
                changes: [IntegrityChange], unreadableSources: [String], notes: [String], signatureValid: Bool?) {
        self.baseline = baseline; self.baselineCreatedAt = baselineCreatedAt; self.lastScan = lastScan; self.scanSeconds = scanSeconds
        self.entries = entries; self.changes = changes; self.unreadableSources = unreadableSources; self.notes = notes; self.signatureValid = signatureValid
    }
}

/// The inventory with its findings, for the Agent extensions tab and the command line.
public struct IntegrityInventoryDTO: Codable, Sendable, Equatable {
    public var scannedAt: Date
    public var extensions: [AgentExtension]
    public var findings: [RiskFinding]
    public var notes: [String]
    public init(scannedAt: Date, extensions: [AgentExtension], findings: [RiskFinding], notes: [String]) {
        self.scannedAt = scannedAt; self.extensions = extensions; self.findings = findings; self.notes = notes
    }
}

/// Something worth telling the user, once. The raw values match the app's event kinds.
public struct IntegrityEvent: Sendable, Equatable {
    public enum Kind: String, Sendable {
        case change = "integrity_change"
        case baselineMissing = "integrity_baseline_missing"
        case indexTampered = "integrity_index_tampered"
        case signatureInvalid = "integrity_signature_invalid"
        case unreadable = "integrity_unreadable"
        case rulesUpdated = "integrity_rules_updated"
    }
    public var kind: Kind
    public var critical: Bool
    public var message: String
    public init(kind: Kind, critical: Bool, message: String) { self.kind = kind; self.critical = critical; self.message = message }
}

public struct IntegrityMonitorError: Error, Equatable, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

/// The two small secrets that must not sit next to the baseline files: the key that authenticates the index, and the
/// marker that a baseline was ever taken. Anything that can edit the baseline files must not be able to read or write
/// these, or it could approve its own change, or delete the baseline and pass for a first run.
public protocol IntegritySecrets: Sendable {
    /// Created on first use; 32 random bytes.
    func hmacKey() throws -> SymmetricKey
    var established: Date? { get }
    func setEstablished(_ date: Date) throws
    /// Uninstall only.
    func forget()
}

/// How Tegata recognises its own entries: the app bundle they point at, and a check that the bundle is still the one
/// Tegata signed. Without one (command line with no app), nothing is treated as Tegata's own.
public struct FootprintCheck: Sendable {
    public let appBundle: URL
    public let isValid: @Sendable () -> Bool
    public init(appBundle: URL, isValid: @escaping @Sendable () -> Bool) { self.appBundle = appBundle; self.isValid = isValid }
}

extension IntegrityMonitor {
    /// Folders whose changes should wake the watcher (an event source per folder, plus a periodic poll).
    public static func watchedFolders(home: URL) -> [String] {
        [home.path, ".claude", ".claude/skills", ".claude/agents", ".claude/commands", ".claude/plugins", ".codex", ".codex/skills",
         ".cursor", ".gemini", "Library/Application Support/Claude"]
            .map { $0.hasPrefix("/") ? $0 : home.appendingPathComponent($0).path }
            + [(ClaudeSettingsFile.managedSettingsPath as NSString).deletingLastPathComponent]
            + ClaudeHomes.discover(home: home).flatMap { h in ["", "skills", "agents", "commands", "plugins"].map { h.root.appendingPathComponent($0).path } }
            + ClaudeHomes.knownParents.map { home.appendingPathComponent($0.path).path }   // a new account folder appears here
    }
}

/// The watcher's view of the agents' configuration, shared by the app's agent and the command line. Background
/// checks never prompt: they scan, read the authenticated index and diff. Taking a baseline and accepting changes need
/// an authorization the caller obtained from the user (Touch ID). Where secrets live, how Tegata's own bundle is
/// verified and how events reach the user are injected, so this file has no platform code.
public actor IntegrityMonitor {
    public static let defaultKeyTag = "app.tegata.integrity-kek"
    static let signatureRecheck: TimeInterval = 600

    public nonisolated let home: URL
    public nonisolated let directory: URL
    public nonisolated let quarantineDir: URL
    public nonisolated let keyTag: String
    let provider: any KeyProvider
    let secrets: any IntegritySecrets
    let footprintCheck: FootprintCheck?
    let emit: @Sendable (IntegrityEvent) async -> Void
    private var scanner: AgentInventoryScanner
    private let classifier: RiskClassifier
    private var last: IntegrityStatus?
    private var announced: Set<String> = []
    private var signature: (checked: Date, valid: Bool)?

    public init(home: URL, directory: URL, quarantineDir: URL, keyTag: String = IntegrityMonitor.defaultKeyTag,
                provider: any KeyProvider, secrets: any IntegritySecrets, footprintCheck: FootprintCheck?,
                emit: @escaping @Sendable (IntegrityEvent) async -> Void) {
        self.home = home; self.directory = directory; self.quarantineDir = quarantineDir; self.keyTag = keyTag
        self.provider = provider; self.secrets = secrets; self.footprintCheck = footprintCheck; self.emit = emit
        scanner = AgentInventoryScanner(home: home, footprint: footprintCheck.map { TegataFootprint(appBundle: $0.appBundle) } ?? nil)
        classifier = RiskClassifier(home: home.path)
    }

    private func store() throws -> IntegrityStore {
        IntegrityStore(directory: directory, provider: provider, keyTag: keyTag,
                       authenticator: HMACBaselineAuthenticator(key: try secrets.hmacKey()))
    }

    /// Recognise Tegata's own entries only while this bundle's signature holds.
    private func refreshFootprint() async {
        guard let footprintCheck else { return }
        let now = Date()
        if let s = signature, now.timeIntervalSince(s.checked) < Self.signatureRecheck { return }
        let valid = footprintCheck.isValid()
        if signature?.valid != false, !valid {
            await announce("signature", IntegrityEvent(kind: .signatureInvalid, critical: true,
                message: "Tegata's app at \(footprintCheck.appBundle.path) failed its code-signature check. Its entries in your agents' settings are no longer treated as Tegata's own until it is reinstalled."))
        }
        signature = (now, valid)
        scanner.footprint = valid ? TegataFootprint(appBundle: footprintCheck.appBundle) : nil
    }

    // MARK: checks

    public func status(rescan: Bool) async -> IntegrityStatus {
        if !rescan, let last { return last }
        return await check(reason: "requested")
    }

    @discardableResult
    public func check(reason: String) async -> IntegrityStatus {
        await refreshFootprint()
        let started = Date()
        let inventory = scanner.scan()
        let seconds = Date().timeIntervalSince(started)
        let findings = classifier.classify(inventory)
        var result = IntegrityStatus(baseline: .none, baselineCreatedAt: nil, lastScan: started, scanSeconds: seconds,
                                     entries: inventory.extensions.count, changes: [], unreadableSources: [], notes: inventory.incomplete,
                                     signatureValid: signature?.valid)
        defer { last = result }
        let store: IntegrityStore
        do { store = try self.store() } catch { result.notes.append("integrity key unavailable: \(error)"); return result }
        guard await store.hasBaseline() else {
            if let when = secrets.established {
                result.baseline = .missing
                await announce("missing", IntegrityEvent(kind: .baselineMissing, critical: true,
                    message: "The record of your agents' configuration that Tegata took on \(when.formatted(date: .abbreviated, time: .shortened)) is gone. Deleting it hides changes, so Tegata does not start over on its own: review the current configuration and take a new baseline."))
            }
            return result
        }
        let index: IntegrityIndex
        do { index = try await store.loadIndex() } catch {
            result.baseline = .tampered
            await announce("tampered", IntegrityEvent(kind: .indexTampered, critical: true,
                message: "Tegata's record of your agents' configuration was altered outside Tegata. Nothing in it can be trusted: review the current configuration and take a new baseline."))
            return result
        }
        result.baseline = .present
        result.baselineCreatedAt = index.createdAt
        let diff = IntegrityDiffer.diff(baseline: index, current: inventory, findings: findings)
        if diff.rulesUpdatePending {
            if diff.isEmpty {
                // Nothing differs, so nothing needs a decision: re-record the same state with the new rules (and entry
                // hashes). Writing the snapshot only wraps its key, so this takes no Touch ID.
                let (inv, raw) = scanner.scanWithRaw()
                let (snapshot, fresh) = IntegritySnapshot.make(inventory: inv, raw: raw, classifier: classifier, now: Date())
                if (try? await store.writeBaseline(snapshot: snapshot, index: fresh)) != nil { result.notes.append("baseline re-recorded with rules v\(IntegrityRules.version)") }
            } else {
                // Only when the update explains something: other pending changes are reported as usual, and once they are
                // accepted the next check finds nothing and re-records with the new rules by itself.
                let attributed = diff.changes.filter { $0.byRulesUpdate != nil }.count
                if attributed > 0 {
                    await announce("rules|\(IntegrityRules.version)", IntegrityEvent(kind: .rulesUpdated, critical: false,
                        message: "Tegata was updated and reads some entries differently. \(attributed) need\(attributed == 1 ? "s" : "") one confirmation (Touch ID); anything else is reported as usual."))
                }
            }
        }
        result.changes = diff.changes
        result.unreadableSources = diff.unreadableSources

        // One event per group of changes worth an interruption, once; a group that goes away can fire again if it comes back.
        var live = Set<String>()
        for g in IntegrityDiffer.grouped(diff.notifications) {
            let key = "change|" + g.changes.map(\.id).sorted().joined(separator: ",")
            live.insert(key)
            await announce(key, IntegrityEvent(kind: .change, critical: true, message: g.summary))
        }
        for u in diff.unreadableSources {
            let key = "unreadable|\(u)"
            live.insert(key)
            await announce(key, IntegrityEvent(kind: .unreadable, critical: true,
                message: "\(u) can no longer be read, so Tegata cannot tell what changed in it. A broken file is not the same as an empty one."))
        }
        announced = announced.filter { !$0.hasPrefix("change|") && !$0.hasPrefix("unreadable|") || live.contains($0) }
        if result.baseline == .present { announced.remove("missing"); announced.remove("tampered") }
        return result
    }

    public func inventory() async -> IntegrityInventoryDTO {
        await refreshFootprint()
        let inv = scanner.scan()
        return IntegrityInventoryDTO(scannedAt: inv.scannedAt, extensions: inv.extensions, findings: classifier.classify(inv), notes: inv.incomplete)
    }

    private func announce(_ key: String, _ event: IntegrityEvent) async {
        guard announced.insert(key).inserted else { return }
        await emit(event)
    }

    // MARK: Touch ID actions (the caller has already authenticated the user)

    public func establish(replace: Bool, authorization: any UnlockAuthorization) async throws {
        let store = try self.store()
        if await store.hasBaseline(), !replace { throw IntegrityMonitorError("a baseline exists; accept changes, or replace it explicitly") }
        switch await provider.state(tag: keyTag) {
        case .present: break
        case .invalidated: try await provider.destroyKey(tag: keyTag); try await provider.createKey(tag: keyTag)
        case .absent: try await provider.createKey(tag: keyTag)
        }
        await refreshFootprint()
        let (inventory, raw) = scanner.scanWithRaw()
        let (snapshot, index) = IntegritySnapshot.make(inventory: inventory, raw: raw, classifier: classifier, now: Date())
        try await store.writeBaseline(snapshot: snapshot, index: index)
        try secrets.setEstablished(Date())
        announced.removeAll()
        _ = authorization   // presence was required to get here; the snapshot itself is written without unwrapping
        await check(reason: "baseline taken")
    }

    public func accept(_ ids: Set<String>, authorization: any UnlockAuthorization) async throws {
        guard !ids.isEmpty else { return }
        await refreshFootprint()
        let (inventory, raw) = scanner.scanWithRaw()
        try await store().accept(ids, current: inventory, raw: raw, findings: classifier.classify(inventory), now: Date(), authorization: authorization)
        await check(reason: "changes accepted")
    }

    /// One pending change, undone. Revert writes the baseline's copy back (no accept needed: the entry then matches).
    /// Remove and Quarantine take the entry away and then accept its absence, so the record matches what the user chose.
    public func remedy(_ id: String, option: IntegrityRemedy.Option, authorization: any UnlockAuthorization) async throws -> String {
        let store = try self.store()
        let index = try await store.loadIndex()
        await refreshFootprint()
        let (inventory, raw) = scanner.scanWithRaw()
        let diff = IntegrityDiffer.diff(baseline: index, current: inventory, findings: classifier.classify(inventory))
        guard let change = diff.changes.first(where: { $0.extensionId == id }) else { throw IntegrityMonitorError("no pending change for that entry; rescan") }
        guard IntegrityRemedy.options(for: change).contains(option) else { throw IntegrityMonitorError("\(option.rawValue) is not available for this change") }
        let said: String
        switch option {
        case .quarantine:
            guard let entry = inventory.byId[id] else { throw IntegrityMonitorError("the entry is gone") }
            let roots = [".claude", ".codex"].map { home.appendingPathComponent($0).path }
            let r = try Quarantine.move(entry, home: home.path, store: quarantineDir, allowedRoots: roots)
            said = "Moved \(entry.name) out of \(entry.declaredIn); it can be put back from Tegata."
            _ = r
        case .revert, .remove:
            let snapshot = try await store.openSnapshot(authorization: authorization)
            guard let file = (raw[id] ?? snapshot.raw[id])?.file else { throw IntegrityMonitorError("no copy of the entry") }
            try IntegrityRemedy.applyToFile(option, url: URL(fileURLWithPath: file), current: raw[id], baseline: snapshot.raw[id], contentChanged: change.contentChanged)
            said = option == .revert ? "Put \(change.name) back the way it was in \(change.declaredIn) (a backup of the file is next to it)."
                                     : "Removed \(change.name) from \(change.declaredIn) (a backup of the file is next to it)."
        }
        if option != .revert {
            // Accept the absence, and only the absence, from the same scan that confirms it: a plain accept would rescan
            // and could record an entry that a tool wrote back in between.
            let (after, afterRaw) = scanner.scanWithRaw()
            guard after.byId[id] == nil else {
                await check(reason: "entry came back")
                throw IntegrityMonitorError("\(change.name) was written back right after it was removed: something keeps adding it. It stays pending.")
            }
            try await store.accept([id], current: after, raw: afterRaw, findings: classifier.classify(after), now: Date(), authorization: authorization)
        }
        await check(reason: option.rawValue)
        return said
    }

    /// Removes or quarantines entries that are there now, changes or not: the "fix" for what a scan reports. Entries of
    /// one file are taken out in one edit (one backup). With a baseline, the absences are accepted from the same scan
    /// that confirms them, so the record matches what the user chose and nothing a tool wrote back in between is
    /// accepted with it. One authorization covers the whole batch.
    public func fix(_ ids: [String], option: IntegrityRemedy.Option, authorization: any UnlockAuthorization) async throws -> String {
        guard option != .revert else { throw IntegrityMonitorError("revert applies to a change since the baseline, not to an entry") }
        guard !ids.isEmpty else { return "Nothing to do." }
        await refreshFootprint()
        let (inventory, raw) = scanner.scanWithRaw()
        var entries: [AgentExtension] = []
        for id in Set(ids).sorted() {
            guard let e = inventory.byId[id] else { throw IntegrityMonitorError("an entry is no longer there; rescan (\(id))") }
            guard IntegrityRemedy.options(forEntry: e).contains(option) else {
                throw IntegrityMonitorError("\(option.rawValue) is not available for \(e.name) in \(e.declaredIn)")
            }
            entries.append(e)
        }
        switch option {
        case .quarantine:
            let roots = [".claude", ".codex"].map { home.appendingPathComponent($0).path }
            for e in entries { _ = try Quarantine.move(e, home: home.path, store: quarantineDir, allowedRoots: roots) }
        case .remove:
            var byFile: [String: [RawEntry]] = [:]
            for e in entries {
                guard let current = raw[e.id] else { throw IntegrityMonitorError("no copy of \(e.name) as the scan saw it; rescan") }
                byFile[current.file, default: []].append(current)
            }
            for (file, list) in byFile.sorted(by: { $0.key < $1.key }) { try IntegrityRemedy.removeAll(list, from: URL(fileURLWithPath: file)) }
        case .revert:
            break
        }
        let done = Set(entries.map(\.id))
        let store = try self.store()
        if await store.hasBaseline() {
            let (after, afterRaw) = scanner.scanWithRaw()
            let back = done.filter { after.byId[$0] != nil }
            try await store.accept(done.subtracting(back), current: after, raw: afterRaw, findings: classifier.classify(after), now: Date(), authorization: authorization)
            if !back.isEmpty {
                await check(reason: "entries came back")
                throw IntegrityMonitorError("\(back.count) of them were written back right after removal: something keeps adding them. They stay pending.")
            }
        }
        await check(reason: "fixed")
        let files = Set(entries.map(\.declaredIn)).sorted()
        let what = entries.count == 1 ? entries[0].name : "\(entries.count) entries"
        return option == .quarantine
            ? "Moved \(what) aside; they can be put back from Tegata."
            : "Removed \(what) from \(files.joined(separator: ", ")) (a backup of each file is next to it)."
    }

    /// One entry.
    public func fix(_ id: String, option: IntegrityRemedy.Option, authorization: any UnlockAuthorization) async throws -> String {
        try await fix([id], option: option, authorization: authorization)
    }

    /// Accepts every difference the new rules explain or may explain, then records the new rules. Real edits (an entry
    /// whose text changed) are not part of it and stay pending. Returns how many entries were refreshed.
    public func refreshRules(authorization: any UnlockAuthorization) async throws -> Int {
        let store = try self.store()
        let index = try await store.loadIndex()
        await refreshFootprint()
        let (inventory, raw) = scanner.scanWithRaw()
        let findings = classifier.classify(inventory)
        let diff = IntegrityDiffer.diff(baseline: index, current: inventory, findings: findings)
        guard diff.rulesUpdatePending else { return 0 }
        let ids = Set(diff.changes.filter { $0.byRulesUpdate != nil }.map(\.extensionId))
        try await store.accept(ids, current: inventory, raw: raw, findings: findings, now: Date(), authorization: authorization, markRulesCurrent: true)
        announced = announced.filter { !$0.hasPrefix("rules|") }
        await check(reason: "rules refreshed")
        return ids.count
    }

    public func restore(stored: String) async throws {
        guard let r = Quarantine.records(in: quarantineDir).first(where: { $0.stored == stored }) else { throw IntegrityMonitorError("no quarantined item at that path") }
        try Quarantine.restore(r)
        await check(reason: "restored from quarantine")
    }

    /// Uninstall only. Order matters: the marker goes last, so an interrupted forget still reports a missing record.
    public func forget() async throws {
        try? await store().removeBaseline()
        try? await provider.destroyKey(tag: keyTag)
        secrets.forget()
        announced.removeAll(); last = nil
    }

    /// The ids Tegata's own write to `path` may have touched: entries in that file that are Tegata's now or were Tegata's
    /// in the baseline. Nothing else in the file is accepted, so a foreign edit made at the same moment stays pending.
    public func ownWriteIDs(path: String) async throws -> Set<String> {
        let store = try self.store()
        guard await store.hasBaseline() else { return [] }
        let shown = path.hasPrefix(home.path + "/") ? "~" + path.dropFirst(home.path.count) : path
        await refreshFootprint()
        let now = scanner.scan().extensions.filter { $0.declaredIn == shown && $0.tegataRole != nil }.map(\.id)
        let before = try await store.loadIndex().entries.filter { $0.value.declaredIn == shown && $0.value.tegataRole != nil }.map(\.key)
        return Set(now + before)
    }
}
