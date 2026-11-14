import Foundation

/// Cleans copies of secrets out of places they were only copied to: agent transcripts and shell history. Never the
/// places a secret is used (`~/.claude.json`'s MCP env, shell startup files, `.env`), because that would break the
/// tools that read them; rotate those instead.
///
/// No backup, on purpose: a backup would be one more copy of the secret. What makes it safe instead:
/// - compare-and-swap on the exact span: the text there must still be the value the scan saw (same per-run id);
/// - an edited JSONL line must still parse, and a file whose lines no longer do is left alone;
/// - files any process has open are skipped: an agent session that is still running keeps its transcript open and
///   would go on writing to the replaced file, losing what it says next; files changed in the last minute are skipped
///   too, and the file must not change between reading and writing;
/// - the write is atomic and keeps the file's permissions.
/// The replacement is a placeholder the detectors treat as such, so a rescan does not count it again.
public enum SecretRedactor {
    public static let placeholder = "<redacted-by-tegata>"

    public struct Outcome: Sendable, Equatable {
        public var cleanedCopies = 0
        public var cleanedFiles = 0
        public var skipped: [String: Int] = [:]   // reason → copies
        public var rotateOnly = 0                  // private keys: rotate them; a block is not cleaned line by line
        public var cleanedShellHistory = false     // open shells may remember the old lines: say so
    }

    /// Whether a finding is a copy Tegata may clean (as opposed to a secret in use, or one it does not edit).
    public static func cleanable(_ f: SecretFinding) -> Bool {
        guard f.rule != "private-key-block", f.valueID != nil, f.length > 0 else { return false }
        if f.source == .agentTranscript { return true }
        if f.source == .shell { return (f.file as NSString).lastPathComponent.hasSuffix("_history") }
        return false
    }

    public static func plan(_ findings: [SecretFinding]) -> (copies: Int, files: Int) {
        let c = findings.filter(cleanable)
        return (c.count, Set(c.map(\.file)).count)
    }

    public static func redact(_ findings: [SecretFinding], now: Date = Date(), quietPeriod: TimeInterval = 60, dryRun: Bool = false) -> Outcome {
        var out = Outcome()
        out.rotateOnly = findings.filter { $0.rule == "private-key-block" }.count
        let byFile = Dictionary(grouping: findings.filter(cleanable), by: \.file)
        let open = openFiles(Array(byFile.keys))
        for (file, list) in byFile.sorted(by: { $0.key < $1.key }) {
            if open.contains(file) { out.skipped["open in a running session (close it, then clean again)", default: 0] += list.count; continue }
            switch redactFile(file, list, now: now, quietPeriod: quietPeriod, dryRun: dryRun) {
            case .success(let n):
                out.cleanedCopies += n; if n > 0 { out.cleanedFiles += 1 }
                if n > 0, (file as NSString).lastPathComponent.hasSuffix("_history") { out.cleanedShellHistory = true }
                if n < list.count { out.skipped["changed since the scan", default: 0] += list.count - n }
            case .failure(let reason):
                out.skipped[reason.text, default: 0] += list.count
            }
        }
        return out
    }

    /// The files among `paths` that some process has open, asked of `lsof` once for all of them. Where `lsof` is
    /// missing or fails, nothing is reported open and the quiet period alone protects running sessions.
    static func openFiles(_ paths: [String]) -> Set<String> {
        let lsof = ["/usr/sbin/lsof", "/usr/bin/lsof", "/bin/lsof"].first { FileManager.default.isExecutableFile(atPath: $0) }
        guard let lsof, !paths.isEmpty else { return [] }
        var found = Set<String>()
        for chunk in stride(from: 0, to: paths.count, by: 200).map({ Array(paths[$0..<min($0 + 200, paths.count)]) }) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: lsof)
            p.arguments = ["-w", "-Fn", "--"] + chunk          // -F n: one "n<path>" line per open file
            let pipe = Pipe()
            p.standardOutput = pipe; p.standardError = FileHandle.nullDevice
            do { try p.run() } catch { return found }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            for line in String(decoding: data, as: UTF8.self).split(separator: "\n") where line.hasPrefix("n") {
                found.insert(String(line.dropFirst()))
            }
        }
        // lsof reports resolved paths (/private/var for /var); map them back to the names asked about.
        let resolved = Dictionary(paths.map { (realpath($0, nil).map { r in defer { free(r) }; return String(cString: r) } ?? $0, $0) }, uniquingKeysWith: { a, _ in a })
        return Set(found.compactMap { resolved[$0] ?? (paths.contains($0) ? $0 : nil) })
    }

    struct Skip: Error { let text: String; init(_ t: String) { text = t } }

    static func redactFile(_ path: String, _ list: [SecretFinding], now: Date, quietPeriod: TimeInterval, dryRun: Bool) -> Result<Int, Skip> {
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: path), (attrs[.type] as? FileAttributeType) == .typeRegular else { return .failure(Skip("not a regular file")) }
        let modified = attrs[.modificationDate] as? Date ?? .distantPast
        // A shell history changes with every command, `tegata clean` included, so it never sits still for a minute.
        // Shells append by opening the file by name, so after the swap they write to the cleaned file; a write during
        // the cleaning is caught by the size and date check below.
        let isHistory = (path as NSString).lastPathComponent.hasSuffix("_history")
        if !isHistory, now.timeIntervalSince(modified) < quietPeriod { return .failure(Skip("in use (changed in the last minute)")) }
        // Same decoding as the scanner: UTF-8, else Latin-1, which maps every byte to one character and back, so zsh's
        // own encoding of non-ASCII history survives byte for byte.
        guard let data = fm.contents(atPath: path) else { return .failure(Skip("unreadable")) }
        let encoding: String.Encoding = String(data: data, encoding: .utf8) != nil ? .utf8 : .isoLatin1
        guard let text = String(data: data, encoding: encoding) else { return .failure(Skip("not text")) }

        var lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let jsonl = path.hasSuffix(".jsonl")
        var done = 0
        for (lineNo, hits) in Dictionary(grouping: list, by: \.line) {
            guard lineNo >= 1, lineNo <= lines.count else { continue }
            let original = lines[lineNo - 1]
            let parsedBefore = jsonl && parses(original)
            let source = original as NSString
            // Every span is checked against the original line first; spans two rules found for one secret overlap and
            // are merged, then replaced right to left so earlier offsets stay valid.
            var spans: [NSRange] = []
            var changed = 0
            for f in hits {
                let r = NSRange(location: f.column - 1, length: f.length)
                guard r.location >= 0, r.location + r.length <= source.length,
                      SecretFinding.valueID(source.substring(with: r)) == f.valueID else { continue }
                spans.append(r); changed += 1
            }
            guard changed > 0 else { continue }
            var merged: [NSRange] = []
            for r in spans.sorted(by: { $0.location < $1.location }) {
                if let last = merged.last, r.location <= last.location + last.length {
                    merged[merged.count - 1] = NSRange(location: last.location, length: max(last.location + last.length, r.location + r.length) - last.location)
                } else { merged.append(r) }
            }
            var ns = source
            for r in merged.reversed() {
                // A value that ends in backslashes ends inside a JSON escape (`…xyz\\"`): keep them so the escape survives.
                let trailing = String(ns.substring(with: r).reversed().prefix { $0 == "\\" })
                ns = ns.replacingCharacters(in: r, with: placeholder + trailing) as NSString
            }
            let edited = ns as String
            if parsedBefore && !parses(edited) { return .failure(Skip("an edit would break the file's JSON")) }
            lines[lineNo - 1] = edited
            done += changed
        }
        guard done > 0, !dryRun else { return .success(done) }

        // Nothing may have been written to the file while we worked on it.
        let again = try? fm.attributesOfItem(atPath: path)
        guard (again?[.modificationDate] as? Date) == modified, (again?[.size] as? NSNumber)?.intValue == data.count else {
            return .failure(Skip("changed while cleaning (run it again)"))
        }
        let url = URL(fileURLWithPath: path)
        let tmp = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).tegata-\(UUID().uuidString)")
        do {
            guard let bytes = lines.joined(separator: "\n").data(using: encoding) else { return .failure(Skip("could not re-encode")) }
            try bytes.write(to: tmp, options: [.withoutOverwriting])
            if let perms = attrs[.posixPermissions] { try fm.setAttributes([.posixPermissions: perms], ofItemAtPath: tmp.path) }
            _ = try fm.replaceItemAt(url, withItemAt: tmp)
        } catch {
            try? fm.removeItem(at: tmp)
            return .failure(Skip("could not write"))
        }
        return .success(done)
    }

    static func parses(_ line: String) -> Bool {
        let t = line.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return true }
        return (try? JSONSerialization.jsonObject(with: Data(t.utf8), options: [.fragmentsAllowed])) != nil
    }
}
