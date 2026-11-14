import Foundation

/// Writes an edited JSON document so it looks like the file it replaces: same key order, same indentation, same
/// spelling of every value that did not change, same trailing newline. Agents write their settings with
/// `JSON.stringify(value, null, 2)`, and many developers keep those files in a dotfiles repository; an edit by Tegata
/// must show up there as the lines it changed, not as a reordered file.
///
/// The edit itself is still made on Foundation values (`JSONSerialization`), which lose order; `restyle` puts the
/// original order and spelling back. Keys that are new go at the end of their object, in sorted order.
public enum OrderedJSON {
    indirect enum Node {
        case object([(String, Node)])
        case array([Node])
        /// The decoded value and the token exactly as written (`"café"` stays that way if unchanged).
        case string(String, raw: String)
        case number(String)
        case bool(Bool)
        case null
    }

    struct Style: Equatable {
        /// nil for a compact file (`{"a":1}`).
        var indent: String?
        var trailingNewline: Bool
    }

    struct ParseError: Error {}
    /// Real agent configs nest about ten levels. Recursion runs on whatever thread calls it (agent queues have small stacks), so
    /// the cap stays low: deeper input is refused, not parsed.
    static let maxDepth = 128

    /// `edited` re-written in the style of `original`. Falls back to `edited` unchanged if either cannot be read.
    public static func restyle(_ edited: Data, like original: Data?) -> Data {
        guard let original, let tree = try? parse(original),
              let value = try? JSONSerialization.jsonObject(with: edited, options: [.fragmentsAllowed]) else { return edited }
        let st = style(of: original)
        var out = render(value, like: tree, style: st, depth: 0)
        if st.trailingNewline { out += "\n" }
        return Data(out.utf8)
    }

    // MARK: style

    static func style(of data: Data) -> Style {
        let text = String(decoding: data, as: UTF8.self)
        let trailing = text.hasSuffix("\n")
        let body = trailing ? String(text.dropLast()) : text
        guard let nl = body.firstIndex(of: "\n") else { return Style(indent: nil, trailingNewline: trailing) }
        let line = body[body.index(after: nl)...].prefix { $0 == " " || $0 == "\t" }
        return Style(indent: line.isEmpty ? "  " : String(line), trailingNewline: trailing)
    }

    // MARK: rendering (JSON.stringify's layout)

    static func render(_ value: Any, like original: Node?, style: Style, depth: Int) -> String {
        let pad = { (d: Int) in style.indent.map { String(repeating: $0, count: d) } ?? "" }
        let nl = style.indent == nil ? "" : "\n"
        let colon = style.indent == nil ? ":" : ": "
        switch value {
        case let dict as [String: Any]:
            if dict.isEmpty { return "{}" }
            var originalPairs: [(String, Node)] = []
            if case .object(let pairs)? = original { originalPairs = pairs }
            let known = originalPairs.map(\.0).filter { dict[$0] != nil }
            var seen = Set<String>()
            let order = known.filter { seen.insert($0).inserted } + dict.keys.filter { !seen.contains($0) }.sorted()
            let lookup = Dictionary(originalPairs, uniquingKeysWith: { a, _ in a })
            let items = order.map { k in pad(depth + 1) + quote(k) + colon + render(dict[k]!, like: lookup[k], style: style, depth: depth + 1) }
            return "{" + nl + items.joined(separator: "," + nl) + nl + pad(depth) + "}"
        case let array as [Any]:
            if array.isEmpty { return "[]" }
            var originals: [Node] = []
            if case .array(let a)? = original { originals = a }
            let items = array.enumerated().map { i, v in pad(depth + 1) + render(v, like: i < originals.count ? originals[i] : nil, style: style, depth: depth + 1) }
            return "[" + nl + items.joined(separator: "," + nl) + nl + pad(depth) + "]"
        case let s as String:
            if case .string(let old, let raw)? = original, old == s { return raw }
            return quote(s)
        case let n as NSNumber:
            if CFGetTypeID(n) == CFBooleanGetTypeID() { return n.boolValue ? "true" : "false" }
            // A long decimal (Claude Code stores 17-digit metrics) does not survive JSONSerialization exactly; a difference that
            // small is the round trip, not an edit, so the original spelling is kept.
            if case .number(let token)? = original, let d = Double(token), sameNumber(d, n.doubleValue) { return token }
            return number(n)
        case is NSNull:
            return "null"
        default:
            return "null"
        }
    }

    static func sameNumber(_ a: Double, _ b: Double) -> Bool {
        a == b || abs(a - b) <= 1e-12 * max(1, abs(a), abs(b))
    }

    static func number(_ n: NSNumber) -> String {
        let d = n.doubleValue
        if d.rounded() == d, abs(d) < 9_007_199_254_740_992 { return String(Int64(d)) }
        return "\(d)"
    }

    /// Escapes the way `JSON.stringify` does: quote, backslash and control characters; `/` and non-ASCII stay as they are.
    static func quote(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if u.value < 0x20 { out += String(format: "\\u%04x", u.value) } else { out.unicodeScalars.append(u) }
            }
        }
        return out + "\""
    }

    // MARK: parsing (strict JSON, order and spelling kept)

    static func parse(_ data: Data) throws -> Node {
        var p = Parser(b: Array(data))
        p.skip()
        let n = try p.value(depth: 0)
        p.skip()
        guard p.i == p.b.count else { throw ParseError() }
        return n
    }

    struct Parser {
        let b: [UInt8]
        var i = 0

        mutating func skip() { while i < b.count, b[i] == 0x20 || b[i] == 0x0A || b[i] == 0x0D || b[i] == 0x09 { i += 1 } }

        mutating func value(depth: Int) throws -> Node {
            guard depth < OrderedJSON.maxDepth, i < b.count else { throw ParseError() }
            switch b[i] {
            case UInt8(ascii: "{"):
                i += 1; skip()
                var pairs: [(String, Node)] = []
                if i < b.count, b[i] == UInt8(ascii: "}") { i += 1; return .object(pairs) }
                while true {
                    skip()
                    guard i < b.count, b[i] == UInt8(ascii: "\"") else { throw ParseError() }
                    let (key, _) = try string()
                    skip()
                    guard i < b.count, b[i] == UInt8(ascii: ":") else { throw ParseError() }
                    i += 1; skip()
                    pairs.append((key, try value(depth: depth + 1)))
                    skip()
                    guard i < b.count else { throw ParseError() }
                    if b[i] == UInt8(ascii: ",") { i += 1; continue }
                    if b[i] == UInt8(ascii: "}") { i += 1; return .object(pairs) }
                    throw ParseError()
                }
            case UInt8(ascii: "["):
                i += 1; skip()
                var items: [Node] = []
                if i < b.count, b[i] == UInt8(ascii: "]") { i += 1; return .array(items) }
                while true {
                    skip()
                    items.append(try value(depth: depth + 1))
                    skip()
                    guard i < b.count else { throw ParseError() }
                    if b[i] == UInt8(ascii: ",") { i += 1; continue }
                    if b[i] == UInt8(ascii: "]") { i += 1; return .array(items) }
                    throw ParseError()
                }
            case UInt8(ascii: "\""):
                let (s, raw) = try string()
                return .string(s, raw: raw)
            case UInt8(ascii: "t"): try literal("true"); return .bool(true)
            case UInt8(ascii: "f"): try literal("false"); return .bool(false)
            case UInt8(ascii: "n"): try literal("null"); return .null
            default:
                let start = i
                while i < b.count, "+-0123456789.eE".utf8.contains(b[i]) { i += 1 }
                guard i > start, let token = String(bytes: b[start..<i], encoding: .utf8), Double(token) != nil else { throw ParseError() }
                return .number(token)
            }
        }

        mutating func literal(_ word: String) throws {
            let w = Array(word.utf8)
            guard i + w.count <= b.count, Array(b[i..<i + w.count]) == w else { throw ParseError() }
            i += w.count
        }

        /// Returns the decoded string and its raw token (quotes included).
        mutating func string() throws -> (String, String) {
            let start = i
            i += 1
            var scalars = String.UnicodeScalarView()
            var pendingHigh: UInt32?
            var run = i
            func flush(_ to: Int) throws {
                guard let s = String(bytes: b[run..<to], encoding: .utf8) else { throw ParseError() }
                scalars.append(contentsOf: s.unicodeScalars)
            }
            while i < b.count {
                let c = b[i]
                if c == UInt8(ascii: "\"") {
                    try flush(i); i += 1
                    guard let raw = String(bytes: b[start..<i], encoding: .utf8) else { throw ParseError() }
                    return (String(scalars), raw)
                }
                if c < 0x20 { throw ParseError() }
                if c == UInt8(ascii: "\\") {
                    try flush(i)
                    guard i + 1 < b.count else { throw ParseError() }
                    let e = b[i + 1]; i += 2
                    switch e {
                    case UInt8(ascii: "\""): scalars.append("\"")
                    case UInt8(ascii: "\\"): scalars.append("\\")
                    case UInt8(ascii: "/"): scalars.append("/")
                    case UInt8(ascii: "b"): scalars.append("\u{08}")
                    case UInt8(ascii: "f"): scalars.append("\u{0C}")
                    case UInt8(ascii: "n"): scalars.append("\n")
                    case UInt8(ascii: "r"): scalars.append("\r")
                    case UInt8(ascii: "t"): scalars.append("\t")
                    case UInt8(ascii: "u"):
                        guard i + 4 <= b.count, let v = UInt32(String(decoding: b[i..<i + 4], as: UTF8.self), radix: 16) else { throw ParseError() }
                        i += 4
                        if (0xD800...0xDBFF).contains(v) { pendingHigh = v }
                        else if (0xDC00...0xDFFF).contains(v), let h = pendingHigh {
                            pendingHigh = nil
                            if let s = Unicode.Scalar(0x10000 + ((h - 0xD800) << 10) + (v - 0xDC00)) { scalars.append(s) }
                        } else if let s = Unicode.Scalar(v) { scalars.append(s) }
                    default: throw ParseError()
                    }
                    run = i
                    continue
                }
                i += 1
            }
            throw ParseError()
        }
    }
}
