import Testing
import Foundation
import CryptoKit
@testable import TegataCore
@testable import TegataCommand
#if os(macOS)
import TegataDarwin

/// `tegata fix` and `tegata watch` without touching the real keychain or depending on Tegata.app on this Mac.
@Suite(.serialized) struct WatchCommandTests {
    final class Home {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("tegata-watchcli-\(UUID().uuidString)")
        init() throws {
            try FileManager.default.createDirectory(at: url.appendingPathComponent(".claude"), withIntermediateDirectories: true)
            try Data(#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"~/.someapp/bin/hook stop"},{"type":"command","command":"echo keep"}]}]}}"#.utf8)
                .write(to: url.appendingPathComponent(".claude/settings.json"))
        }
        deinit { try? FileManager.default.removeItem(at: url) }
        var settings: String { (try? String(contentsOf: url.appendingPathComponent(".claude/settings.json"), encoding: .utf8)) ?? "" }
    }

    func run(_ args: [String], _ h: Home, appIsWatching: Bool = false, answer: Bool = false, person: Bool? = true) -> (Int32, String, String) {
        TegataCommand.testOverrides = .init(appIsWatching: appIsWatching) { home in
            let m = IntegrityMonitor(home: home, directory: home.appendingPathComponent("state/integrity"), quarantineDir: home.appendingPathComponent("state/q"),
                                     provider: InMemoryKeyProvider(), secrets: MemorySecrets(), footprintCheck: nil) { _ in }
            return (m, "memory (test)")
        }
        defer { TegataCommand.testOverrides = nil }
        var out: [String] = [], err: [String] = []
        let s = TegataCommand.run(args, home: h.url, out: { out.append($0) }, err: { err.append($0) }, ask: { _ in answer }, presence: { _ in person })
        return (s, out.joined(separator: "\n"), err.joined(separator: "\n"))
    }

    @Test func fixByOwnerAsksFirstThenRemovesOnlyThatTool() throws {
        let h = try Home()
        let refused = run(["fix", "remove", "--owner", "someapp"], h)
        #expect(refused.0 == 0 && refused.2.contains("nothing changed") && h.settings.contains("someapp"))
        let done = run(["fix", "remove", "--owner", "someapp"], h, answer: true)
        #expect(done.0 == 0 && done.1.contains("Removed"))
        #expect(!h.settings.contains("someapp") && h.settings.contains("echo keep"))
    }

    /// Before: `fix --yes` on a Mac without a record let an agent remove hooks. --yes skips the question, not the person.
    @Test func fixWithYesStillNeedsThePerson() throws {
        let h = try Home()
        let refused = run(["fix", "remove", "--owner", "someapp", "--yes"], h, person: false)
        #expect(refused.0 == 0 && refused.2.contains("nothing changed") && h.settings.contains("someapp"))
        let noTouchID = run(["fix", "remove", "--owner", "someapp", "--yes"], h, person: nil)      // and no terminal
        #expect(noTouchID.2.contains("--yes is not enough") && h.settings.contains("someapp"))
        let done = run(["fix", "remove", "--owner", "someapp", "--yes"], h, person: true)
        #expect(done.1.contains("Removed") && !h.settings.contains("someapp"))
    }

    /// Homebrew's upgrade removes the LaunchAgent; the next command puts it back, only for the program that installed it.
    @Test func theWatcherComesBackOnlyForTheSameProgram() {
        let app = "/Applications/Tegata CLI.app/Contents/MacOS/tegata"
        var asked = false
        let appWatching = { asked = true; return false }
        #expect(TegataCommand.watcherNeedsResume(wantedBy: app, me: app, agentPresent: false, appWatching: appWatching))
        #expect(!TegataCommand.watcherNeedsResume(wantedBy: nil, me: app, agentPresent: false, appWatching: { false }))       // never asked for
        #expect(!TegataCommand.watcherNeedsResume(wantedBy: app, me: "/src/.build/debug/tegata", agentPresent: false, appWatching: { false }))  // another build
        #expect(!TegataCommand.watcherNeedsResume(wantedBy: app, me: app, agentPresent: true, appWatching: { false }))        // already there
        #expect(!TegataCommand.watcherNeedsResume(wantedBy: app, me: app, agentPresent: false, appWatching: { true }))        // the app watches
        asked = false
        _ = TegataCommand.watcherNeedsResume(wantedBy: app, me: app, agentPresent: true, appWatching: appWatching)
        #expect(!asked)                                                                                                       // launchctl only when needed
    }

    @Test func aRecordWithNobodyWatchingIsSaidPlainly() throws {
        let h = try Home()
        let s = IntegrityStatus(baseline: .present, baselineCreatedAt: Date(), lastScan: Date(), scanSeconds: 0, entries: 2,
                                changes: [], unreadableSources: [], notes: [], signatureValid: nil)
        #expect(TegataCommand.describe(s, protection: "memory", installed: false).joined().contains("Nothing is watching"))
        #expect(TegataCommand.describe(s, protection: "memory", installed: true).joined().contains("Watching in the background"))
        _ = h
    }

    @Test func fixDefersToTheAppWhenItIsWatching() throws {
        let h = try Home()
        let r = run(["fix", "remove", "--owner", "someapp", "--yes"], h, appIsWatching: true)
        #expect(r.0 == TegataCommand.Exit.usage.rawValue && r.2.contains("Tegata.app is watching"))
        #expect(h.settings.contains("someapp"))
        #expect(run(["watch", "status"], h, appIsWatching: true).1.contains("one watcher is enough"))
    }

    @Test func statusWithoutARecordSaysHowToStart() throws {
        let h = try Home()
        let r = run(["watch", "status"], h)
        #expect(r.1.contains("YOUR RECORD") && r.1.contains("Not taken yet") && r.1.contains("tegata watch establish"))
        #expect(r.1.contains("WHAT THIS IS"))
    }

    @Test func inventoryIdsShowWhatCanBeFixed() throws {
        let h = try Home()
        let r = run(["inventory", "--ids"], h)
        #expect(r.1.contains("(tegata fix remove <id>)"))
    }

    @Test func badInputIsAUsageError() throws {
        let h = try Home()
        #expect(run(["fix", "revert", "x"], h).0 == TegataCommand.Exit.usage.rawValue)
        #expect(run(["fix", "remove", "--owner"], h).0 == TegataCommand.Exit.usage.rawValue)
        #expect(run(["watch", "frobnicate"], h).0 == TegataCommand.Exit.usage.rawValue)
    }

    @Test func secureEnclaveBlobKeyWrapsAndUnwraps() async throws {
        guard SecureEnclave.isAvailable else { return }   // CI without a Secure Enclave
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("tegata-se-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let p = SecureEnclaveBlobKeyProvider(directory: dir, requireBiometry: false)
        #expect(await p.state(tag: "t") == .absent)
        try await p.createKey(tag: "t")
        let dek = SymmetricKey(size: .bits256)
        let wrapped = try await p.wrap(dek, tag: "t")
        #expect(try await p.unwrap(wrapped, tag: "t", authorization: nil) == dek)
        let perms = try FileManager.default.attributesOfItem(atPath: dir.appendingPathComponent("t.se-key").path)[.posixPermissions] as? Int
        #expect(perms == 0o600)
        var tampered = wrapped; tampered[tampered.count - 1] ^= 1
        await #expect(throws: KeyProviderError.self) { _ = try await p.unwrap(tampered, tag: "t", authorization: nil) }
        try await p.destroyKey(tag: "t")
        #expect(await p.state(tag: "t") == .absent)
        // With biometry required, no authorization means no key.
        let strict = SecureEnclaveBlobKeyProvider(directory: dir, requireBiometry: true)
        await #expect(throws: KeyProviderError.self) { _ = try await strict.unwrap(wrapped, tag: "t", authorization: nil) }
    }

    @Test func establishTwiceSaysThereIsARecordWithoutAskingForTouchID() throws {
        let h = try Home()
        // A record taken through the monitor directly (no Touch ID in tests), then establish from the command.
        let shared = IntegrityMonitor(home: h.url, directory: h.url.appendingPathComponent("state/integrity"), quarantineDir: h.url.appendingPathComponent("state/q"),
                                      provider: InMemoryKeyProvider(), secrets: MemorySecrets(), footprintCheck: nil) { _ in }
        try TegataCommand.blocking { try await shared.establish(replace: false, authorization: UserWasPresent()) }
        TegataCommand.testOverrides = .init(appIsWatching: false) { _ in (shared, "memory (test)") }
        defer { TegataCommand.testOverrides = nil }
        var out: [String] = []
        let s = TegataCommand.run(["watch", "establish"], home: h.url, out: { out.append($0) }, err: { _ in }, ask: { _ in false })
        #expect(s == 0 && out.joined(separator: "\n").contains("You already have a record"))
    }

    @Test func changesAreFoundByTheNameInTheTable() {
        func change(_ id: String, _ name: String, _ file: String) -> IntegrityChange {
            IntegrityChange(id: id, kind: .added, extensionId: id, agent: .claudeCode, scope: .user, extensionKind: .mcpServer, name: name, owner: nil,
                            declaredIn: file, severityBefore: nil, severityAfter: nil, contentChanged: false, findings: [], alert: .notify,
                            summary: "\(name) was added")
        }
        let changes = [change("a|mcp|tegata-prueba", "tegata-prueba", "~/.claude.json"),
                       change("a|mkt|1", "i-have-adhd", "~/.claude/settings.json"),
                       change("a|mkt|2", "i-have-adhd", "~/.claude/plugins/known_marketplaces.json")]
        var errors: [String] = []
        #expect(TegataCommand.resolve(["tegata-prueba"], in: changes, many: false) { errors.append($0) } == ["a|mcp|tegata-prueba"])
        #expect(TegataCommand.resolve(["TEGATA-PRUEBA"], in: changes, many: false) { errors.append($0) } == ["a|mcp|tegata-prueba"])
        #expect(TegataCommand.resolve(["a|mkt|2"], in: changes, many: false) { errors.append($0) } == ["a|mkt|2"])        // ids still work
        // One name, two changes: accept takes both, undoing asks to choose and does nothing.
        #expect(TegataCommand.resolve(["i-have-adhd"], in: changes, many: true) { errors.append($0) } == ["a|mkt|1", "a|mkt|2"])
        errors.removeAll()
        #expect(TegataCommand.resolve(["i-have-adhd"], in: changes, many: false) { errors.append($0) } == nil)
        #expect(errors.first?.contains("2 changes are named") == true && errors.count == 3)
        #expect(TegataCommand.resolve(["nope"], in: changes, many: true) { _ in } == nil)
    }

    @Test func versionsCompareSemantically() {
        #expect(Updates.isNewer("0.2.0", than: "0.1.0"))
        #expect(Updates.isNewer("0.1.10", than: "0.1.2"))
        #expect(Updates.isNewer("0.2.0", than: "0.2.0-dev"))
        #expect(!Updates.isNewer("0.2.0-dev", than: "0.2.0"))
        #expect(!Updates.isNewer("0.1.0", than: "0.1.0"))
        #expect(!Updates.isNewer("0.1.0", than: "0.1.1"))
    }

    @Test func releaseAnswersAreReadCarefully() {
        let ok = Updates.parse(Data(#"{"tag_name":"v0.3.1","html_url":"https://github.com/shipibo-studio/Tegata/releases/tag/v0.3.1","published_at":"2026-12-01T10:00:00Z"}"#.utf8))
        #expect(ok?.version == "0.3.1" && ok?.url.hasSuffix("v0.3.1") == true && ok?.published != nil)
        // A link that is not GitHub's is not shown; the releases page is.
        let odd = Updates.parse(Data(#"{"tag_name":"v9.9.9","html_url":"https://evil.example/download"}"#.utf8))
        #expect(odd?.url == Updates.releasesPage)
        #expect(Updates.parse(Data("not json".utf8)) == nil)
    }

    @Test func statusShowsVersionUpdatesAndTheRecord() throws {
        let h = try Home()
        defer { Updates.fetcher = Updates.fetchLatest }
        Updates.fetcher = { .found(ReleaseInfo(version: "99.0.0", url: Updates.releasesPage, published: nil)) }
        let newer = run(["status"], h)
        #expect(newer.0 == 0 && newer.1.contains("┃手形┃ status") && newer.1.contains("Version \(TegataCommand.version)"))
        #expect(newer.1.contains("Version 99.0.0 is out") && newer.1.contains("update:"))
        #expect(newer.1.contains("YOUR RECORD") && !newer.1.contains("┃手形┃ watch status"))   // the record, once, under status

        Updates.fetcher = { .found(ReleaseInfo(version: TegataCommand.version, url: Updates.releasesPage, published: nil)) }
        #expect(run(["status"], h).1.contains("Up to date"))

        Updates.fetcher = { .failed("offline") }
        #expect(run(["status"], h).1.contains("could not check"))

        var asked = false
        Updates.fetcher = { asked = true; return .failed("should not be called") }
        #expect(run(["status", "--offline"], h).1.contains("update check skipped") && !asked)
    }
}
#endif