import Testing
import Foundation
@testable import TegataCore

/// Cleaning copies of secrets: only copies, only the exact span, never breaking a transcript.
final class RedactBench {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("tegata-redact-\(UUID().uuidString)")
    static let key = "sk-ant-api03-TestOnlyNotARealKeyQQQQ0123456789abcdefghijkl"
    init() throws { try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true) }
    deinit { try? FileManager.default.removeItem(at: root) }

    func file(_ name: String, _ text: String, mode: Int = 0o600, age: TimeInterval = 3600) throws -> String {
        let url = root.appendingPathComponent(name)
        try Data(text.utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: mode, .modificationDate: Date().addingTimeInterval(-age)], ofItemAtPath: url.path)
        return url.path
    }
    func scan(_ path: String, _ kind: ExposureSource.Kind) throws -> [SecretFinding] {
        SecretDetector().scan(text: try String(contentsOfFile: path, encoding: .utf8), file: path, source: kind)
    }
    func read(_ path: String) throws -> String { try String(contentsOfFile: path, encoding: .utf8) }
}

@Suite struct SecretRedactorTests {
    @Test func aTranscriptLosesTheValueAndStaysValidJSON() throws {
        let b = try RedactBench()
        let line1 = #"{"type":"user","message":{"content":"export ANTHROPIC_API_KEY=\#(RedactBench.key) then run"}}"#
        let line2 = #"{"type":"assistant","message":{"content":"ok"}}"#
        let path = try b.file("s.jsonl", line1 + "\n" + line2 + "\n")
        let found = try b.scan(path, .agentTranscript)
        #expect(!found.isEmpty)
        let out = SecretRedactor.redact(found)
        #expect(out.cleanedCopies == found.count && out.cleanedFiles == 1)
        let after = try b.read(path)
        #expect(!after.contains(RedactBench.key) && after.contains(SecretRedactor.placeholder))
        for l in after.split(separator: "\n") { #expect(SecretRedactor.parses(String(l))) }
        #expect(after.hasSuffix(line2 + "\n"))                              // the rest of the file is untouched
        #expect(try b.scan(path, .agentTranscript).isEmpty)                 // a rescan does not count the placeholder
        #expect((try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? Int) == 0o600)
    }

    @Test func aValueEndingInAnEscapeKeepsTheEscape() throws {
        let b = try RedactBench()
        // In the JSON, the value is followed by an escaped quote; the detector's value includes the backslash.
        let line = #"{"content":"TOKEN=Zq8vTestOnly4kL2mN7pRwX9yB\"done"}"#
        #expect(SecretRedactor.parses(line))
        let path = try b.file("e.jsonl", line + "\n")
        let found = try b.scan(path, .agentTranscript)
        #expect(found.count == 1)
        _ = SecretRedactor.redact(found)
        let after = try b.read(path)
        #expect(!after.contains("Zq8vTestOnly"))
        #expect(SecretRedactor.parses(after.trimmingCharacters(in: .newlines)))
    }

    @Test func onlyCopiesAreCleaned() throws {
        let b = try RedactBench()
        let hist = try b.file(".zsh_history", ": 1:0;export OPENAI_API_KEY=sk-proj-TestOnlyNotARealKeyABCDEFGHIJKLMNOPQRSTUV0123\n")
        let rc = try b.file(".zshrc", "export OPENAI_API_KEY=sk-proj-TestOnlyNotARealKeyABCDEFGHIJKLMNOPQRSTUV0123\n")
        let cfg = try b.file(".claude.json", #"{"mcpServers":{"x":{"env":{"API_TOKEN":"Zq8vTestOnly4kL2mN7pRwX9yB"}}}}"#)
        let found = try b.scan(hist, .shell) + b.scan(rc, .shell) + b.scan(cfg, .agentConfig)
        let out = SecretRedactor.redact(found)
        #expect(out.cleanedFiles == 1)
        #expect(!(try b.read(hist)).contains("sk-proj-"))
        #expect((try b.read(rc)).contains("sk-proj-"))                     // in use: rotate it, do not break the shell
        #expect((try b.read(cfg)).contains("Zq8vTestOnly"))                 // in use by an MCP server
    }

    @Test func aFileInUseOrChangedSinceTheScanIsLeftAlone() throws {
        let b = try RedactBench()
        let busy = try b.file("busy.jsonl", #"{"c":"KEY \#(RedactBench.key)"}"# + "\n", age: 5)
        let out1 = SecretRedactor.redact(try b.scan(busy, .agentTranscript))
        #expect(out1.cleanedCopies == 0 && out1.skipped.keys.contains { $0.contains("in use") })
        #expect((try b.read(busy)).contains(RedactBench.key))

        let moved = try b.file("moved.jsonl", #"{"c":"KEY \#(RedactBench.key)"}"# + "\n")
        let found = try b.scan(moved, .agentTranscript)
        _ = try b.file("moved.jsonl", #"{"c":"KEY sk-ant-api03-TestOnlyADifferentFakeKey00000000000000000000"}"# + "\n")
        let out2 = SecretRedactor.redact(found)
        #expect(out2.cleanedCopies == 0)
        #expect((try b.read(moved)).contains("ADifferentFakeKey"))
    }

    @Test func dryRunWritesNothingAndPrivateKeysAreForRotation() throws {
        let b = try RedactBench()
        let t = try b.file("t.jsonl", #"{"c":"KEY \#(RedactBench.key)"}"# + "\n" + #"{"c":"-----BEGIN OPENSSH PRIVATE KEY-----"}"# + "\n")
        let found = try b.scan(t, .agentTranscript)
        let out = SecretRedactor.redact(found, dryRun: true)
        #expect(out.cleanedCopies == 1 && out.rotateOnly == 1)
        #expect((try b.read(t)).contains(RedactBench.key))
    }

    @Test func zshHistoryWithNonUTF8BytesIsCleanedByteForByte() throws {
        let b = try RedactBench()
        // zsh "metafies" non-ASCII: 0x83 followed by the byte xor 0x20. Not valid UTF-8.
        // Spelled out step by step: older compilers (CI) cannot type-check the one-line form.
        let metafied: [UInt8] = [0x83, 0xC3 ^ 0x20, 0x83, 0xA9 ^ 0x20]
        var bytes = Data(": 1700000000:0;echo caf".utf8)
        bytes.append(contentsOf: metafied)
        bytes.append(contentsOf: Array("\n".utf8))
        bytes.append(contentsOf: Array(": 1700000001:0;export OPENAI_API_KEY=sk-proj-TestOnlyNotARealKeyABCDEFGHIJKLMNOPQRSTUV0123\n".utf8))
        let url = b.root.appendingPathComponent(".zsh_history")
        try bytes.write(to: url)
        try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(-3600)], ofItemAtPath: url.path)
        let text = String(data: bytes, encoding: .isoLatin1)!
        let found = SecretDetector().scan(text: text, file: url.path, source: .shell)
        #expect(SecretRedactor.redact(found).cleanedCopies == found.count && !found.isEmpty)
        let after = try Data(contentsOf: url)
        #expect(after.prefix(27) == bytes.prefix(27))                       // the non-ASCII line is untouched, byte for byte
        #expect(!String(data: after, encoding: .isoLatin1)!.contains("sk-proj-"))
    }

    @Test func twoRulesOnOneSecretAreOneCleanSpan() throws {
        let b = try RedactBench()
        let path = try b.file("o.jsonl", #"{"c":"ANTHROPIC_API_KEY=\#(RedactBench.key)"}"# + "\n")
        let found = try b.scan(path, .agentTranscript)
        let out = SecretRedactor.redact(found)
        #expect(out.cleanedCopies == found.count && out.skipped.isEmpty)
        let after = try b.read(path)
        #expect(!after.contains("TestOnly") && SecretRedactor.parses(after.trimmingCharacters(in: .newlines)))
    }

    @Test func aTranscriptARunningSessionHoldsOpenIsLeftAlone() throws {
        let b = try RedactBench()
        let path = try b.file("live.jsonl", #"{"c":"KEY \#(RedactBench.key)"}"# + "\n")
        let found = try b.scan(path, .agentTranscript)
        // A session keeps its transcript open to append to it; replacing the file would send what it writes next
        // to a file nobody can see. Hold it open like a session does.
        let handle = try FileHandle(forUpdating: URL(fileURLWithPath: path))
        defer { try? handle.close() }
        let out = SecretRedactor.redact(found)
        #expect(out.cleanedCopies == 0)
        #expect(out.skipped.keys.contains { $0.contains("open in a running session") })
        #expect((try b.read(path)).contains(RedactBench.key))
        try handle.close()
        #expect(SecretRedactor.redact(found).cleanedCopies == 1)                // closed: cleaned
    }

    @Test func shellHistoryIsCleanedEvenWhenItJustChanged() throws {
        let b = try RedactBench()
        // Written a second ago, as zsh does after every command (tegata clean's own line included).
        let hist = try b.file(".zsh_history", ": 1:0;export OPENAI_API_KEY=sk-proj-TestOnlyNotARealKeyABCDEFGHIJKLMNOPQRSTUV0123\n", age: 1)
        let out = SecretRedactor.redact(try b.scan(hist, .shell))
        #expect(out.cleanedCopies == 1 && out.cleanedShellHistory)
        #expect(!(try b.read(hist)).contains("sk-proj-"))
    }
}
