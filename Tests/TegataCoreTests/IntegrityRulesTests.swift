import Testing
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import TegataCore

/// A baseline "taken with older rules" is simulated by bumping fingerprints while keeping entry hashes, which is
/// exactly what a rules change does to an unchanged entry.
@Suite struct RulesVersioningTests {
    let home = "/Users/tester"
    var classifier: RiskClassifier { RiskClassifier(home: home, fileExists: { _ in true }) }
    func inv(_ json: String) throws -> AgentInventory {
        AgentInventory(scannedAt: Date(), extensions: try ClaudeCodeParser.settings(Data(json.utf8), scope: .user, declaredIn: "\(home)/.claude/settings.json", home: home), incomplete: [])
    }
    func oldRules(_ i: AgentInventory, keepEntryHash: Bool = true) -> IntegrityIndex {
        var index = IntegrityIndex.make(inventory: i, findings: classifier.classify(i), now: Date())
        index.rulesVersion = 1
        for k in index.entries.keys {
            let fp = index.entries[k]?.fingerprint ?? ""
            index.entries[k]?.fingerprint = "old-rules-" + fp
            if !keepEntryHash { index.entries[k]?.entryHash = nil }
        }
        return index
    }
    let json = #"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"guard.sh"}]}]},"mcpServers":{"s":{"command":"npx","args":["-y","x"]}}}"#

    @Test func entryHashesDependOnTheTextNotOnTegatasRules() throws {
        let a = try inv(json).extensions, b = try inv(json).extensions
        #expect(a.allSatisfy { $0.entryHash != nil } && a.map(\.entryHash) == b.map(\.entryHash))
        let edited = try inv(json.replacingOccurrences(of: #"["-y","x"]"#, with: #"["-y","y"]"#)).extensions
        #expect(a.first { $0.kind == .mcpServer }?.entryHash != edited.first { $0.kind == .mcpServer }?.entryHash)
    }

    @Test func differencesTheUpdateExplainsAreQuietAndPending() throws {
        let now = try inv(json)
        let d = IntegrityDiffer.diff(baseline: oldRules(now), current: now, findings: classifier.classify(now))
        #expect(d.rulesUpdatePending && d.changes.count == 2)
        #expect(d.changes.allSatisfy { $0.byRulesUpdate == .explained && $0.alert == .quiet })
        #expect(d.notifications.isEmpty)
    }

    @Test func aRealEditDuringTheUpdateStillAlerts() throws {
        let base = oldRules(try inv(json))
        let now = try inv(json.replacingOccurrences(of: "guard.sh", with: "guard.sh").replacingOccurrences(of: #"["-y","x"]"#, with: #"["-y","evil"]"#))
        let d = IntegrityDiffer.diff(baseline: base, current: now, findings: classifier.classify(now))
        let server = try #require(d.changes.first { $0.extensionKind == .mcpServer })
        #expect(server.byRulesUpdate == nil && server.alert == .notify)        // its text changed: an edit, not the update
        #expect(d.changes.first { $0.extensionKind == .hook }?.byRulesUpdate == .explained)
    }

    @Test func aSwappedPluginIsNeverSilencedByAnUpdate() throws {
        // Same entry text, different files behind it: the update may explain it, or the plugin was swapped.
        let i = try inv(#"{"enabledPlugins":{"p@m":true}}"#)
        var current = i
        current.extensions[0].contentDigest = "after"
        current.extensions[0].fingerprint = "new"
        var base = IntegrityIndex.make(inventory: i, findings: [], now: Date())
        base.rulesVersion = 1
        base.entries[i.extensions[0].id]?.contentDigest = "before"
        let c = try #require(IntegrityDiffer.diff(baseline: base, current: current, findings: []).changes.first)
        #expect(c.contentChanged && c.byRulesUpdate == .possible && c.alert == .review)
        #expect(c.summary.contains("may come from the update"))
    }

    @Test func legacyBaselinesWithoutEntryHashesAreReviewNotNotify() throws {
        let now = try inv(json)
        let d = IntegrityDiffer.diff(baseline: oldRules(now, keepEntryHash: false), current: now, findings: classifier.classify(now))
        #expect(d.changes.allSatisfy { $0.byRulesUpdate == .possible && $0.alert <= .review })
        // An index written before rulesVersion existed decodes as unversioned.
        let legacy = #"{"version":1,"createdAt":"2026-10-24T00:00:00Z","entries":{}}"#
        #expect(try SealedCoding.makeDecoder().decode(IntegrityIndex.self, from: Data(legacy.utf8)).rulesVersion == nil)
    }

    @Test func currentRulesBehaveExactlyAsBefore() throws {
        let i = try inv(json)
        let base = IntegrityIndex.make(inventory: i, findings: classifier.classify(i), now: Date())
        #expect(base.rulesVersion == IntegrityRules.version)
        let edited = try inv(json.replacingOccurrences(of: #"["-y","x"]"#, with: #"["-y","y"]"#))
        let d = IntegrityDiffer.diff(baseline: base, current: edited, findings: classifier.classify(edited))
        #expect(!d.rulesUpdatePending && d.changes.allSatisfy { $0.byRulesUpdate == nil })
    }

    @Test func refreshAcceptsWhatTheUpdateExplainsAndRecordsTheNewRules() async throws {
        let sb = try ContentSandbox()
        try sb.write(json, ".claude/settings.json")
        let scanner = AgentInventoryScanner(home: sb.root, managedSettings: sb.url("none.json"))
        let c = RiskClassifier(home: sb.path, fileExists: { _ in true })
        let first = scanner.scanWithRaw()
        var (snap, index) = IntegritySnapshot.make(inventory: first.inventory, raw: first.raw, classifier: c, now: Date())
        index.rulesVersion = 1
        for k in index.entries.keys { index.entries[k]?.fingerprint = "old-" + k }
        let p = InMemoryKeyProvider(); try await p.createKey(tag: "t")
        let store = IntegrityStore(directory: sb.url("vault"), provider: p, keyTag: "t", authenticator: HMACBaselineAuthenticator(key: SymmetricKey(size: .bits256)))
        try await store.writeBaseline(snapshot: snap, index: index)
        let now = scanner.scanWithRaw()
        let d = IntegrityDiffer.diff(baseline: try await store.loadIndex(), current: now.inventory, findings: c.classify(now.inventory))
        let ids = Set(d.changes.filter { $0.byRulesUpdate != nil }.map(\.extensionId))
        struct Presence: UnlockAuthorization {}
        try await store.accept(ids, current: now.inventory, raw: now.raw, findings: c.classify(now.inventory), now: Date(), authorization: Presence(), markRulesCurrent: true)
        let after = try await store.loadIndex()
        #expect(after.rulesVersion == IntegrityRules.version)
        #expect(IntegrityDiffer.diff(baseline: after, current: now.inventory, findings: c.classify(now.inventory)).isEmpty)
        _ = snap
    }
}
