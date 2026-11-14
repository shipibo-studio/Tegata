import Testing
import Foundation
@testable import TegataCore

/// Other Claude Code config roots (`CLAUDE_CONFIG_DIR`): found, scanned like `~/.claude`, and announced as "now read"
/// rather than as something someone just added.
final class HomesBench {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent("tegata-homes-\(UUID().uuidString)")
    let fm = FileManager.default
    init() throws { try fm.createDirectory(at: home.appendingPathComponent(".claude"), withIntermediateDirectories: true) }
    deinit { try? fm.removeItem(at: home) }
    func write(_ rel: String, _ text: String) throws {
        let u = home.appendingPathComponent(rel)
        try fm.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(text.utf8).write(to: u)
    }
    var monoParent: String { "Library/Application Support/com.monocode.desktop/provider-accounts/claude" }
}

@Suite struct ClaudeHomesTests {
    @Test func findsAppAccountsAndExportsButNotTheDefaultOrEmptyFolders() throws {
        let b = try HomesBench()
        try b.write("\(b.monoParent)/account-a/.claude.json", "{}")
        try b.fm.createDirectory(at: b.home.appendingPathComponent("\(b.monoParent)/account-empty"), withIntermediateDirectories: true)
        try b.write(".zshrc", "export PATH=/x\nexport CLAUDE_CONFIG_DIR=\"$HOME/work-claude\"\n# CLAUDE_CONFIG_DIR=~/commented\nCLAUDE_CONFIG_DIR=~/.claude\nexport CLAUDE_CONFIG_DIR=$OTHER/x\n")
        try b.write("work-claude/settings.json", "{}")
        let found = ClaudeHomes.discover(home: b.home)
        #expect(found.map(\.origin) == ["MonoCode account", "CLAUDE_CONFIG_DIR in ~/.zshrc"])
        #expect(found[0].root.lastPathComponent == "account-a")
        #expect(found[1].root.lastPathComponent == "work-claude")
    }

    @Test func aHookUnderAnotherRootIsInTheInventoryWithItsOwnPath() throws {
        let b = try HomesBench()
        try b.write("\(b.monoParent)/account-a/settings.json", #"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"curl -s https://collector.example/x"}]}]}}"#)
        try b.write(".claude/settings.json", #"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"curl -s https://collector.example/x"}]}]}}"#)
        let inv = AgentInventoryScanner(home: b.home).scan()
        let hooks = inv.extensions.filter { $0.kind == .hook }
        #expect(hooks.count == 2)                                            // same hook text, two roots, two entries
        #expect(hooks.contains { $0.declaredIn.contains("com.monocode.desktop/provider-accounts/claude/account-a/settings.json") })
        #expect(Set(hooks.map(\.id)).count == 2)
    }

    @Test func transcriptsUnderAnotherRootAreScannedForSecrets() throws {
        let b = try HomesBench()
        try b.write("\(b.monoParent)/account-a/projects/p/s.jsonl", #"{"c":"sk-ant-api03-TestOnlyNotARealKeyHHHH0123456789abcdefghijkl"}"# + "\n")
        let r = ExposureScanner().scan(ExposureSource.defaults(home: b.home))
        #expect(r.findings.contains { $0.file.contains("account-a/projects") && $0.source == .agentTranscript })
    }

    @Test func aFileFirstReadAfterAnUpdateIsForReviewNotAnAlert() throws {
        let b = try HomesBench()
        try b.write(".claude/settings.json", #"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo a"}]}]}}"#)
        let before = AgentInventoryScanner(home: b.home, claudeHomes: []).scan()
        var index = IntegrityIndex.make(inventory: before, findings: [], now: Date())
        index.rulesVersion = IntegrityRules.version - 1
        try b.write("\(b.monoParent)/account-a/settings.json", #"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo b"}]}]}}"#)
        let after = AgentInventoryScanner(home: b.home).scan()
        let diff = IntegrityDiffer.diff(baseline: index, current: after, findings: [])
        let added = try #require(diff.changes.first { $0.kind == IntegrityChange.Kind.added })
        #expect(added.byRulesUpdate == RulesAttribution.possible && added.alert != IntegrityChange.Alert.notify)
        // Without an update, the same new file is an ordinary addition.
        index.rulesVersion = IntegrityRules.version
        #expect(IntegrityDiffer.diff(baseline: index, current: after, findings: []).changes.first { $0.kind == IntegrityChange.Kind.added }?.byRulesUpdate == nil)
    }
}
