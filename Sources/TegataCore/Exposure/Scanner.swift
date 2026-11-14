import Foundation

public struct ExposureReport: Sendable, Equatable {
    public var startedAt: Date
    public var finishedAt: Date
    public var filesScanned: Int
    public var bytesScanned: Int
    public var findings: [SecretFinding]
    /// Files or roots that could not be read, with the reason. The report is honest about gaps.
    public var incomplete: [String]
    public var duration: TimeInterval { finishedAt.timeIntervalSince(startedAt) }

    public func findings(in kind: ExposureSource.Kind) -> [SecretFinding] { findings.filter { $0.source == kind } }
    public var byFile: [String: [SecretFinding]] { Dictionary(grouping: findings, by: \.file) }
}

/// Reads each file once, detects, keeps no content. `.env.schema` files are consulted for `@sensitive`
/// names so those keys count as high confidence regardless of the value's shape.
public struct ExposureScanner: Sendable {
    public let detector: SecretDetector
    public var clock: any TimeSource
    public init(detector: SecretDetector = SecretDetector(), clock: any TimeSource = SystemClock()) { self.detector = detector; self.clock = clock }

    public func scan(_ sources: [ExposureSource], progress: (@Sendable (Int) -> Void)? = nil) -> ExposureReport {
        let start = clock.now
        let work: [(ExposureSource, URL)] = sources.flatMap { s in s.files().map { (s, $0) } }
        final class Box: @unchecked Sendable { var findings: [SecretFinding] = []; var incomplete: [String] = []; var files = 0; var bytes = 0; let lock = NSLock() }
        let box = Box()
        DispatchQueue.concurrentPerform(iterations: work.count) { i in
            let (source, url) = work[i]
            let result = scanOne(source: source, url: url)
            box.lock.withLock {
                box.files += 1; box.bytes += result.bytes
                box.findings.append(contentsOf: result.findings)
                if let inc = result.incomplete { box.incomplete.append(inc) }
                progress?(box.files)
            }
        }
        let findings = box.findings.sorted { ($0.file, $0.line, $0.column) < ($1.file, $1.line, $1.column) }
        return ExposureReport(startedAt: start, finishedAt: clock.now, filesScanned: box.files, bytesScanned: box.bytes, findings: findings, incomplete: box.incomplete.sorted())
    }

    private func scanOne(source: ExposureSource, url: URL) -> (findings: [SecretFinding], bytes: Int, incomplete: String?) {
        guard let data = FileManager.default.contents(atPath: url.path) else { return ([], 0, "\(url.path): unreadable") }
        guard let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else { return ([], data.count, "\(url.path): not text") }
        var findings: [SecretFinding] = []
        do {
                var found = detector.scan(text: text, file: url.path, source: source.kind)
                if source.kind == .projectEnv, let sensitive = SchemaSensitiveNames.load(nextTo: url) {
                    found = found.map { f in
                        var f = f
                        if let k = f.keyName, sensitive.contains(k) { f.confidence = .high; f.rule = "env-schema-sensitive" }
                        return f
                    }
                    // Keys the schema marks sensitive that the rules missed (short or low-entropy values).
                    let known = Set(found.compactMap(\.keyName))
                    for (i, line) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
                        guard let eq = line.firstIndex(of: "=") else { continue }
                        let key = line[..<eq].trimmingCharacters(in: .whitespaces)
                        let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                        guard sensitive.contains(key), !known.contains(key), !value.isEmpty, !SecretRules.isPlaceholder(value) else { continue }
                        let col = (String(line) as NSString).range(of: String(value)).location
                        found.append(SecretFinding(file: url.path, line: i + 1, column: (col == NSNotFound ? line.distance(from: line.startIndex, to: eq) + 1 : col) + 1, length: (value as NSString).length, rule: "env-schema-sensitive",
                                                   keyName: key, preview: SecretFinding.mask(String(value)), confidence: .high, source: .projectEnv))
                    }
                }
                findings.append(contentsOf: found)
        }
        return (findings, data.count, nil)
    }
}

/// Reads `@sensitive` item names from a varlock `.env.schema` in the same directory, honouring
/// `@defaultSensitive`. Values are never read from the schema.
public enum SchemaSensitiveNames {
    public static func load(nextTo envFile: URL) -> Set<String>? {
        let schema = envFile.deletingLastPathComponent().appendingPathComponent(".env.schema")
        guard let data = FileManager.default.contents(atPath: schema.path), let text = String(data: data, encoding: .utf8) else { return nil }
        return parse(text)
    }

    public static func parse(_ text: String) -> Set<String> {
        var out = Set<String>()
        var defaultSensitive = true
        var pendingSensitive: Bool? = nil
        var inHeader = true
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { pendingSensitive = nil; continue }
            if line.hasPrefix("#") {
                if inHeader, let r = line.range(of: "@defaultSensitive") {
                    let rest = line[r.upperBound...].trimmingCharacters(in: .whitespaces)
                    if rest.hasPrefix("=") { defaultSensitive = !(rest.dropFirst().trimmingCharacters(in: .whitespaces).lowercased().hasPrefix("false")) }
                }
                if line.contains("@sensitive") {
                    pendingSensitive = !line.contains("@sensitive=false") && !line.contains("@sensitive = false")
                }
                continue
            }
            inHeader = false
            guard let eq = line.firstIndex(of: "=") else { pendingSensitive = nil; continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces)
            if pendingSensitive ?? defaultSensitive { out.insert(key) }
            pendingSensitive = nil
        }
        return out
    }
}
