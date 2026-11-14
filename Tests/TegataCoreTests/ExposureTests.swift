import Testing
import Foundation
@testable import TegataCore

@Suite struct SecretDetectorTests {
    let d = SecretDetector()

    func rules(_ text: String) -> [String] { d.scan(text: text, file: "f", source: .shell).map(\.rule) }

    @Test func providerTokensAreHighConfidenceAndPreviewIsShort() {
        let text = """
        export ANTHROPIC_API_KEY=sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnop
        token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij123456
        aws AKIAIOSFODNN7EXAMPLX
        url postgres://app:S3cr3tPassw0rd@db.internal:5432/prod
        -----BEGIN OPENSSH PRIVATE KEY-----
        """
        let f = d.scan(text: text, file: "/tmp/x", source: .shell)
        #expect(f.map(\.rule) == ["anthropic-key", "github-token", "aws-access-key", "connection-url-with-password", "private-key-block"])
        #expect(f.allSatisfy { $0.confidence == .high })
        #expect(f[0].preview == "sk-ant****mnop")
        #expect(f[0].line == 1 && f[0].column == 26)
        #expect(f[3].keyName == "app" && f[3].preview == "S3cr****")   // 14 chars: head only
        #expect(!f.contains { $0.preview.count > 14 })
        #expect(!String(describing: f).contains("S3cr3tPassw0rd"))
    }

    @Test func assignmentsNeedSecretNamesLengthAndEntropy() {
        #expect(rules("API_KEY=abc") == [])                                  // too short
        #expect(rules("DATABASE_PASSWORD=aaaaaaaaaaaaaaaaaaaa") == [])       // placeholder-like
        #expect(rules("SECRET_TOKEN=/usr/local/share/things/here") == [])  // low entropy path
        #expect(rules("APP_NAME=x9F2kL8mQ3vR7tY1wZ4b") == [])               // name not secret-like
        #expect(rules("STRIPE_SECRET=x9F2kL8mQ3vR7tY1wZ4bN6cH0j") == ["secret-assignment"])
        let f = d.scan(text: "\"authToken\": \"q8Zt2Lp0Xc4Vm9Kj7Hn3Ws5Yb1Rd6Fg\"", file: "f", source: .agentConfig)
        #expect(f.count == 1 && f[0].keyName == "authToken" && f[0].confidence == .high)
        #expect(rules("PASSWORD=${VAULT_PASSWORD_REF_12345}") == [])
        #expect(rules("API_KEY=op://vault/item/key-1234567") == [])
        #expect(rules("TOKEN=your_token_here_1234567890") == [])
    }

    @Test func jwtAndOpenAIShapes() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        #expect(rules("Authorization: Bearer \(jwt)").contains("jwt"))
        #expect(rules("OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD").first == "openai-key")
    }

    @Test func duplicatesOnOneSpanCollapse() {
        let text = "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD"
        let f = d.scan(text: text, file: "f", source: .projectEnv)
        #expect(f.count == 1)   // provider rule wins over the assignment rule at the same location
    }
}

@Suite struct SchemaSensitiveTests {
    @Test func honoursDefaultsAndItemDecorators() {
        let schema = """
        # @defaultSensitive=false @defaultRequired=infer
        # ---
        # @sensitive @required
        # @type=string(startsWith=sk-ant-api)
        ANTHROPIC_API_KEY=
        APP_ENV=development

        # @sensitive=false
        PUBLIC_URL=
        # @sensitive
        DB_PASS=
        """
        #expect(SchemaSensitiveNames.parse(schema) == ["ANTHROPIC_API_KEY", "DB_PASS"])
        let strict = """
        # @defaultRequired=true
        A=
        # @sensitive=false
        B=
        """
        #expect(SchemaSensitiveNames.parse(strict) == ["A"])   // sensitive by default when unset
    }
}

@Suite struct ExposureScannerTests {
    func makeTree() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("tegata-exposure-\(UUID().uuidString)")
        let fm = FileManager.default
        try fm.createDirectory(at: root.appendingPathComponent(".claude/projects/p1"), withIntermediateDirectories: true)
        try fm.createDirectory(at: root.appendingPathComponent(".claude/backups"), withIntermediateDirectories: true)
        try fm.createDirectory(at: root.appendingPathComponent("Sites/app/node_modules/x"), withIntermediateDirectories: true)
        try fm.createDirectory(at: root.appendingPathComponent("Sites/app2"), withIntermediateDirectories: true)
        let ghp = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij123456"
        try """
        {"type":"user","message":{"content":"here is my token \(ghp) please deploy"}}
        {"type":"assistant","message":{"content":"ok"}}
        """.write(to: root.appendingPathComponent(".claude/projects/p1/session.jsonl"), atomically: true, encoding: .utf8)
        try "{\"mcpServers\":{\"x\":{\"env\":{\"NOTION_TOKEN\":\"ntn_9F2kL8mQ3vR7tY1wZ4bN6cH0jP5sD8fG\"}}}}".write(to: root.appendingPathComponent(".claude.json"), atomically: true, encoding: .utf8)
        try "{\"old\":\"AKIAIOSFODNN7EXAMPLX\"}".write(to: root.appendingPathComponent(".claude/backups/.claude.json.backup.123"), atomically: true, encoding: .utf8)
        try "export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD\nalias ll='ls -l'\n".write(to: root.appendingPathComponent(".zshrc"), atomically: true, encoding: .utf8)
        try "DATABASE_URL=postgres://u:hunter2hunter2@localhost/db\nDEBUG=true\n".write(to: root.appendingPathComponent("Sites/app/.env"), atomically: true, encoding: .utf8)
        try "API_KEY=sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnop\n".write(to: root.appendingPathComponent("Sites/app/.env.example"), atomically: true, encoding: .utf8)
        try "SECRET=\(ghp)\n".write(to: root.appendingPathComponent("Sites/app/node_modules/x/.env"), atomically: true, encoding: .utf8)
        try "# @defaultSensitive=false\n# @sensitive\nSHORT_PIN=\nPUBLIC=\n".write(to: root.appendingPathComponent("Sites/app2/.env.schema"), atomically: true, encoding: .utf8)
        try "SHORT_PIN=4711abcd\nPUBLIC=https://example.com\n".write(to: root.appendingPathComponent("Sites/app2/.env.local"), atomically: true, encoding: .utf8)
        return root
    }

    @Test func scansDefaultSourcesAndSkipsNoiseWithoutKeepingValues() throws {
        let root = try makeTree(); defer { try? FileManager.default.removeItem(at: root) }
        let sources = [ExposureSource.claudeTranscripts(home: root), .claudeConfig(home: root), .shellFiles(home: root), .projectEnv(roots: [root.appendingPathComponent("Sites")])]
        let report = ExposureScanner(clock: ManualClock()).scan(sources)
        let byRule = Dictionary(grouping: report.findings, by: \.rule).mapValues(\.count)
        #expect(report.findings(in: .agentTranscript).map(\.rule) == ["github-token"])
        #expect(report.findings(in: .agentConfig).map(\.rule).sorted() == ["aws-access-key", "secret-assignment"])
        #expect(report.findings(in: .shell).map(\.rule) == ["openai-key"])
        let env = report.findings(in: .projectEnv)
        #expect(env.map(\.rule).sorted() == ["connection-url-with-password", "env-schema-sensitive"])
        #expect(env.contains { $0.keyName == "SHORT_PIN" && $0.confidence == .high && $0.preview == "4711****" })
        #expect(!report.findings.contains { $0.file.contains("node_modules") || $0.file.hasSuffix(".env.example") })
        #expect(byRule["github-token"] == 1)
        #expect(report.filesScanned == 6)   // .env.example excluded, node_modules skipped, .env.schema not an env file
        #expect(report.incomplete.isEmpty)
        let dump = String(describing: report)
        for secret in ["ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij123456", "hunter2hunter2", "ntn_9F2kL8mQ3vR7tY1wZ4bN6cH0jP5sD8fG"] { #expect(!dump.contains(secret)) }
    }

    @Test func missingRootsAreNotErrorsAndSymlinksAreNotFollowed() throws {
        let root = try makeTree(); defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("Sites/link"), withDestinationURL: root.appendingPathComponent(".claude"))
        let report = ExposureScanner().scan([.projectEnv(roots: [root.appendingPathComponent("Sites"), root.appendingPathComponent("nowhere")])])
        #expect(report.incomplete.isEmpty)
        #expect(!report.findings.contains { $0.file.contains("/link/") })
    }
}

@Suite struct ExposureGuardTests {
    @Test func credentialFileDecisions() {
        for p in ["/a/.env", "/a/.env.local", "/a/.env.production", "/a/server.pem", "/a/id_rsa", "/a/id_ed25519.pub", "/a/.netrc",
                  "/a/secrets/x.txt", "/u/.claude.json", "/u/.claude/backups/.claude.json.backup.1", "/a/oauth_creds.json", "/a/AUTH.JSON"] {
            #expect(ExposureGuard.isCredentialFile(p), "\(p)")
        }
        for p in ["/a/.env.example", "/a/.env.schema", "/a/.env.sample", "/a/.envrc.md", "/a/main.swift", "/a/keys.md", "/a/environment.ts"] {
            #expect(!ExposureGuard.isCredentialFile(p), "\(p)")
        }
        #expect(ExposureGuard.commandTouchesCredentialFile("cat .env | grep KEY"))
        #expect(ExposureGuard.commandTouchesCredentialFile("cp ~/.netrc /tmp/x"))
        #expect(ExposureGuard.commandTouchesCredentialFile("source ./.env.local && npm start"))
        #expect(!ExposureGuard.commandTouchesCredentialFile("git status && npm test"))
        #expect(!ExposureGuard.commandTouchesCredentialFile("cat .env.example"))
    }

    @Test func hookAndRetentionEditsAreIdempotentAndReversible() throws {
        let base = "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"Bash\",\"hooks\":[{\"type\":\"command\",\"command\":\"echo hi\"}]}]},\"model\":\"opus\"}".data(using: .utf8)
        let cmd = "/Applications/Tegata.app/Contents/Resources/tegata-guard.sh"
        let once = try ClaudeSettingsEditor.addPreToolUseHook(base, matcher: ExposureGuard.hookMatcher, command: cmd)
        let twice = try ClaudeSettingsEditor.addPreToolUseHook(once, matcher: ExposureGuard.hookMatcher, command: cmd)
        #expect(once == twice)
        #expect(ClaudeSettingsEditor.hasPreToolUseHook(twice, command: cmd))
        let o = try #require(JSONSerialization.jsonObject(with: twice) as? [String: Any])
        #expect(((o["hooks"] as? [String: Any])?["PreToolUse"] as? [[String: Any]])?.count == 2)
        let removed = try ClaudeSettingsEditor.removePreToolUseHook(twice, command: cmd)
        #expect(!ClaudeSettingsEditor.hasPreToolUseHook(removed, command: cmd))
        let r = try #require(JSONSerialization.jsonObject(with: removed) as? [String: Any])
        #expect(((r["hooks"] as? [String: Any])?["PreToolUse"] as? [[String: Any]])?.count == 1)   // the user's own hook survives
        #expect(r["model"] as? String == "opus")
        let bare = try ClaudeSettingsEditor.removePreToolUseHook(try ClaudeSettingsEditor.addPreToolUseHook(nil, matcher: "Read", command: cmd), command: cmd)
        #expect(try #require(JSONSerialization.jsonObject(with: bare) as? [String: Any]).isEmpty)
        let days = try ClaudeSettingsEditor.setCleanupPeriodDays(nil, days: 7)
        #expect(ClaudeSettingsEditor.cleanupPeriodDays(days) == 7)
        #expect(ClaudeSettingsEditor.cleanupPeriodDays(try ClaudeSettingsEditor.setCleanupPeriodDays(days, days: nil)) == nil)
    }
}

@Suite struct RedactedPreviewTests {
    @Test func masksExactSpansAndWindowsLongLines() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("tegata-preview-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let ghp = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij123456"
        let env = dir.appendingPathComponent(".env")
        try "APP=demo\nGITHUB_TOKEN=\(ghp)\nDEBUG=1\n".write(to: env, atomically: true, encoding: .utf8)
        let findings = SecretDetector().scan(text: try String(contentsOf: env, encoding: .utf8), file: env.path, source: .projectEnv)
        let p = try #require(RedactedPreview.build(file: env.path, findings: findings))
        #expect(p.excerpts.count == 3)
        #expect(p.excerpts[1].flagged && p.excerpts[1].text == "GITHUB_TOKEN=ghp_AB****3456")
        #expect(!p.excerpts[0].flagged && p.excerpts[0].text == "APP=demo")
        // long transcript line: windowed around the hit, still masked
        let jsonl = dir.appendingPathComponent("s.jsonl")
        let filler = String(repeating: "x", count: 5000)
        try "{\"a\":\"\(filler)\"}\n{\"msg\":\"\(filler) token \(ghp) \(filler)\"}\n{\"b\":1}\n".write(to: jsonl, atomically: true, encoding: .utf8)
        let f2 = SecretDetector().scan(text: try String(contentsOf: jsonl, encoding: .utf8), file: jsonl.path, source: .agentTranscript)
        let p2 = try #require(RedactedPreview.build(file: jsonl.path, findings: f2))
        let flagged = try #require(p2.excerpts.first { $0.flagged })
        #expect(flagged.line == 2 && flagged.text.count < 400 && flagged.text.contains("ghp_AB****3456") && !flagged.text.contains(ghp))
        #expect(p2.excerpts.map(\.line) == [1, 2, 3])
    }
}
