import Foundation

/// A redacted view of a scanned file: every finding's value span is replaced by its 4-character
/// preview and dots. Long lines (transcripts) are cut to a window around each match.
public struct RedactedPreview: Sendable, Equatable {
    public struct Excerpt: Sendable, Equatable, Identifiable {
        public var id: String { "\(line):\(text.hashValue)" }
        public var line: Int
        public var text: String
        public var flagged: Bool
    }
    public var file: String
    public var totalLines: Int
    public var excerpts: [Excerpt]

    public static func build(file: String, findings: [SecretFinding], context: Int = 2, window: Int = 160, maxLines: Int = 400) -> RedactedPreview? {
        guard let data = FileManager.default.contents(atPath: file), let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else { return nil }
        var lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        if lines.last == "" { lines.removeLast() }   // trailing newline is not a line
        let byLine = Dictionary(grouping: findings.filter { $0.file == file }, by: \.line)
        let short = lines.count <= maxLines && lines.allSatisfy { $0.count <= window * 2 }
        var wanted = Set<Int>()
        if short { wanted = Set(1...max(1, lines.count)) } else {
            for l in byLine.keys { for d in -context...context where l + d >= 1 && l + d <= lines.count { wanted.insert(l + d) } }
        }
        var out: [Excerpt] = []
        for n in wanted.sorted() {
            let raw = lines[n - 1]
            let hits = (byLine[n] ?? []).sorted { $0.column < $1.column }
            var masked = mask(raw, hits)
            if masked.count > window * 2 {
                // window around the first hit, or the head of the line
                let anchor = hits.first.map { max(0, $0.column - 1 - window) } ?? 0
                let start = masked.index(masked.startIndex, offsetBy: min(anchor, max(0, masked.count - window * 2)))
                let end = masked.index(start, offsetBy: min(window * 2, masked.distance(from: start, to: masked.endIndex)))
                masked = (start > masked.startIndex ? "… " : "") + masked[start..<end] + (end < masked.endIndex ? " …" : "")
            }
            out.append(Excerpt(line: n, text: masked, flagged: !hits.isEmpty))
        }
        return RedactedPreview(file: file, totalLines: lines.count, excerpts: out)
    }

    /// Replaces each finding's span (1-based column, length) with `preview` + dots, right to left so
    /// earlier offsets stay valid. Works on UTF-16 offsets, which is what the detector recorded.
    static func mask(_ line: String, _ hits: [SecretFinding]) -> String {
        var ns = NSMutableString(string: line)
        for h in hits.sorted(by: { $0.column > $1.column }) where h.length > 0 {
            let loc = h.column - 1
            guard loc >= 0, loc + h.length <= ns.length else { continue }
            ns.replaceCharacters(in: NSRange(location: loc, length: h.length), with: h.preview)
        }
        return ns as String
    }
}
