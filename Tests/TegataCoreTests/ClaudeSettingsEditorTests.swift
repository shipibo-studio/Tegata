import Testing
import Foundation
@testable import TegataCore

@Suite struct ClaudeSettingsEditorTests {
    let helper = "/Applications/Tegata.app/Contents/MacOS/tegata-token"
    let userSettings = """
    {
      "model": "opus",
      "permissions": { "allow": ["Bash(git:*)"], "deny": ["Read(./.env)"] },
      "env": { "CLAUDE_CODE_ENABLE_TELEMETRY": "0", "FOO": "bar" },
      "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [ { "type": "command", "command": "echo hi" } ] } ] },
      "unknownFutureKey": { "nested": [1, 2, 3] }
    }
    """.data(using: .utf8)!

    func obj(_ d: Data) throws -> [String: Any] { try #require(JSONSerialization.jsonObject(with: d) as? [String: Any]) }

    @Test func configurePreservesEverythingElse() throws {
        let out = try ClaudeSettingsEditor.configure(userSettings, helperPath: helper, ttlMilliseconds: 300_000)
        let o = try obj(out)
        #expect(o["apiKeyHelper"] as? String == helper)
        let env = try #require(o["env"] as? [String: Any])
        #expect(env["CLAUDE_CODE_API_KEY_HELPER_TTL_MS"] as? String == "300000")
        #expect(env["CLAUDE_CODE_ENABLE_TELEMETRY"] as? String == "0")
        #expect(env["FOO"] as? String == "bar")
        #expect(o["model"] as? String == "opus")
        #expect((o["hooks"] as? [String: Any]) != nil)
        #expect(((o["unknownFutureKey"] as? [String: Any])?["nested"] as? [Int]) == [1, 2, 3])
        #expect(((o["permissions"] as? [String: Any])?["deny"] as? [String]) == ["Read(./.env)"])
        let state = try ClaudeSettingsEditor.inspect(out)
        #expect(state.isConfigured(helperPath: helper))
        #expect(state.ttlMilliseconds == 300_000)
        #expect(out.last == 0x0A)
    }

    @Test func configureFromNothingAndFromEmpty() throws {
        for input: Data? in [nil, Data(), "{}".data(using: .utf8)] {
            let out = try ClaudeSettingsEditor.configure(input, helperPath: helper, ttlMilliseconds: 43_200_000)
            let o = try obj(out)
            #expect(o["apiKeyHelper"] as? String == helper)
            #expect(((o["env"] as? [String: Any])?["CLAUDE_CODE_API_KEY_HELPER_TTL_MS"] as? String) == "43200000")
            #expect(o.count == 2)
        }
    }

    @Test func unconfigureRemovesOnlyTegataKeys() throws {
        let configured = try ClaudeSettingsEditor.configure(userSettings, helperPath: helper, ttlMilliseconds: 300_000)
        let out = try ClaudeSettingsEditor.unconfigure(configured)
        let o = try obj(out)
        #expect(o["apiKeyHelper"] == nil)
        let env = try #require(o["env"] as? [String: Any])
        #expect(env["CLAUDE_CODE_API_KEY_HELPER_TTL_MS"] == nil)
        #expect(env.count == 2)
        #expect(o["model"] as? String == "opus")
        #expect(try ClaudeSettingsEditor.inspect(out) == .init(apiKeyHelper: nil, ttlMilliseconds: nil))
        // env introduced by Tegata alone disappears entirely
        let minimal = try ClaudeSettingsEditor.configure(nil, helperPath: helper, ttlMilliseconds: 1)
        let back = try obj(try ClaudeSettingsEditor.unconfigure(minimal))
        #expect(back.isEmpty)
    }

    @Test func inspectAcceptsIntegerTTLAndRejectsNonObjects() throws {
        let s = try ClaudeSettingsEditor.inspect("{\"env\":{\"CLAUDE_CODE_API_KEY_HELPER_TTL_MS\":5000}}".data(using: .utf8))
        #expect(s.ttlMilliseconds == 5000)
        #expect(throws: ClaudeSettingsEditor.EditorError.notAnObject) { try ClaudeSettingsEditor.inspect("[1,2]".data(using: .utf8)) }
        #expect(throws: ClaudeSettingsEditor.EditorError.self) { try ClaudeSettingsEditor.inspect("{not json".data(using: .utf8)) }
    }

    @Test func denyRulesAreIdempotentAndReversible() throws {
        let rules = ["Read(**/.env*)", "Read(**/secrets/**)"]
        let once = try ClaudeSettingsEditor.addDenyRules(userSettings, rules: rules)
        let twice = try ClaudeSettingsEditor.addDenyRules(once, rules: rules)
        #expect(once == twice)
        let deny = try #require((try obj(twice)["permissions"] as? [String: Any])?["deny"] as? [String])
        #expect(deny == ["Read(./.env)"] + rules)
        let removed = try obj(try ClaudeSettingsEditor.removeDenyRules(twice, rules: rules))
        #expect(((removed["permissions"] as? [String: Any])?["deny"] as? [String]) == ["Read(./.env)"])
        #expect(((removed["permissions"] as? [String: Any])?["allow"] as? [String]) == ["Bash(git:*)"])
        let bare = try obj(try ClaudeSettingsEditor.removeDenyRules(try ClaudeSettingsEditor.addDenyRules(nil, rules: rules), rules: rules))
        #expect(bare.isEmpty)
    }

    @Test func fileEditMakesBackupAndWrites0600() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("tegata-settings-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("settings.json")
        try userSettings.write(to: url)
        let backup = try ClaudeSettingsFile.edit(url) { try ClaudeSettingsEditor.configure($0, helperPath: helper, ttlMilliseconds: 300_000) }
        #expect(backup != nil)
        #expect(FileManager.default.contents(atPath: backup!.path) == userSettings)
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
        #expect(mode == 0o600)
        #expect(try ClaudeSettingsEditor.inspect(FileManager.default.contents(atPath: url.path)).isConfigured(helperPath: helper))
        // no file yet: no backup, file created
        let fresh = dir.appendingPathComponent("sub/settings.json")
        let b2 = try ClaudeSettingsFile.edit(fresh) { try ClaudeSettingsEditor.configure($0, helperPath: helper, ttlMilliseconds: 1) }
        #expect(b2 == nil)
        #expect(FileManager.default.fileExists(atPath: fresh.path))
    }
}
