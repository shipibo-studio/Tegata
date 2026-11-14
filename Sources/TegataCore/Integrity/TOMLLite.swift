import Foundation

/// A small, forgiving TOML reader for agent configuration files (Codex's `config.toml`). It is not a
/// validator: a line it cannot read is counted in `problems` and skipped, so one odd entry on a customer's
/// machine does not hide the rest of the file. Input is capped and nesting is bounded, so a hostile file
/// cannot make it run long or recurse deeply.
///
/// Supported: tables, arrays of tables, dotted and quoted keys, basic and literal strings (single and
/// multi-line), integers, floats, booleans, arrays, inline tables, comments. Dates stay strings.
public enum TOMLLite {
    public struct Result {
        public var root: [String: Any]
        /// Statements that could not be read and were skipped.
        public var problems: Int
        /// True when the input was over `maxBytes` and nothing was read.
        public var tooLarge: Bool
    }

    public static let maxBytes = 2_000_000
    static let maxDepth = 24

    public static func parse(_ data: Data, maxBytes: Int = TOMLLite.maxBytes) -> Result {
        guard data.count <= maxBytes else { return Result(root: [:], problems: 0, tooLarge: true) }
        var p = Parser(bytes: Array(data))
        p.run()
        return Result(root: p.root, problems: p.problems, tooLarge: false)
    }

    struct Parser {
        let b: [UInt8]
        var i = 0
        var root: [String: Any] = [:]
        var table: [String] = []
        var problems = 0
        init(bytes: [UInt8]) { b = bytes }

        struct Bad: Error {}

        mutating func run() {
            while i < b.count {
                skipBlank()
                guard i < b.count else { break }
                let start = i
                do {
                    if b[i] == UInt8(ascii: "[") { try header() } else { try keyValue() }
                    try endOfStatement()
                } catch {
                    problems += 1
                    i = start
                    skipLine()
                }
            }
        }

        // MARK: statements

        mutating func header() throws {
            i += 1
            let isArray = peek() == UInt8(ascii: "[")
            if isArray { i += 1 }
            skipSpaces()
            let path = try keyPath()
            skipSpaces()
            guard peek() == UInt8(ascii: "]") else { throw Bad() }
            i += 1
            if isArray { guard peek() == UInt8(ascii: "]") else { throw Bad() }; i += 1 }
            guard path.count <= TOMLLite.maxDepth else { throw Bad() }
            table = path
            if isArray { Self.appendTable(&root, path[...]) } else { Self.update(&root, path[...]) { _ in } }
        }

        mutating func keyValue() throws {
            let key = try keyPath()
            skipSpaces()
            guard peek() == UInt8(ascii: "=") else { throw Bad() }
            i += 1
            skipSpaces()
            let value = try self.value(depth: 0)
            guard key.count + table.count <= TOMLLite.maxDepth else { throw Bad() }
            let full = table + key
            Self.set(&root, full[...], value)
        }

        mutating func endOfStatement() throws {
            skipSpaces()
            if peek() == UInt8(ascii: "#") { skipLine(); return }
            if i >= b.count { return }
            guard b[i] == 0x0A || b[i] == 0x0D else { throw Bad() }
        }

        // MARK: keys

        mutating func keyPath() throws -> [String] {
            var parts: [String] = []
            while true {
                skipSpaces()
                parts.append(try keyPart())
                skipSpaces()
                if peek() == UInt8(ascii: ".") { i += 1; continue }
                return parts
            }
        }

        mutating func keyPart() throws -> String {
            guard let c = peek() else { throw Bad() }
            if c == UInt8(ascii: "\"") { return try basicString() }
            if c == UInt8(ascii: "'") { return try literalString() }
            let start = i
            while let c = peek(), isBare(c) { i += 1 }
            guard i > start else { throw Bad() }
            return String(decoding: b[start..<i], as: UTF8.self)
        }

        func isBare(_ c: UInt8) -> Bool {
            (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == UInt8(ascii: "_") || c == UInt8(ascii: "-")
        }

        // MARK: values

        mutating func value(depth: Int) throws -> Any {
            guard depth <= TOMLLite.maxDepth, let c = peek() else { throw Bad() }
            switch c {
            case UInt8(ascii: "\""): return try quoted(basic: true)
            case UInt8(ascii: "'"): return try quoted(basic: false)
            case UInt8(ascii: "["): return try array(depth: depth)
            case UInt8(ascii: "{"): return try inlineTable(depth: depth)
            default: return try scalar()
            }
        }

        mutating func quoted(basic: Bool) throws -> String {
            let q = basic ? UInt8(ascii: "\"") : UInt8(ascii: "'")
            if i + 2 < b.count, b[i + 1] == q, b[i + 2] == q { return try multiline(basic: basic) }
            return basic ? try basicString() : try literalString()
        }

        mutating func basicString() throws -> String {
            i += 1
            var out: [UInt8] = []
            while let c = peek() {
                if c == UInt8(ascii: "\"") { i += 1; return String(decoding: out, as: UTF8.self) }
                if c == 0x0A { throw Bad() }
                if c == UInt8(ascii: "\\") { i += 1; try escape(into: &out) } else { out.append(c); i += 1 }
            }
            throw Bad()
        }

        mutating func literalString() throws -> String {
            i += 1
            let start = i
            while let c = peek() {
                if c == UInt8(ascii: "'") { defer { i += 1 }; return String(decoding: b[start..<i], as: UTF8.self) }
                if c == 0x0A { throw Bad() }
                i += 1
            }
            throw Bad()
        }

        mutating func multiline(basic: Bool) throws -> String {
            let q = basic ? UInt8(ascii: "\"") : UInt8(ascii: "'")
            i += 3
            if peek() == 0x0D { i += 1 }
            if peek() == 0x0A { i += 1 }
            var out: [UInt8] = []
            while i < b.count {
                if b[i] == q, i + 2 < b.count, b[i + 1] == q, b[i + 2] == q {
                    i += 3
                    var extra = 0   // up to two more quotes right before the closing ones belong to the string
                    while extra < 2, peek() == q { out.append(q); i += 1; extra += 1 }
                    return String(decoding: out, as: UTF8.self)
                }
                if basic, b[i] == UInt8(ascii: "\\") {
                    i += 1
                    if let n = peek(), n == 0x0A || n == 0x0D || n == 0x20 || n == 0x09 {
                        while let w = peek(), w == 0x0A || w == 0x0D || w == 0x20 || w == 0x09 { i += 1 }   // line-ending backslash
                    } else { try escape(into: &out) }
                    continue
                }
                out.append(b[i]); i += 1
            }
            throw Bad()
        }

        mutating func escape(into out: inout [UInt8]) throws {
            guard let c = peek() else { throw Bad() }
            i += 1
            switch c {
            case UInt8(ascii: "n"): out.append(0x0A)
            case UInt8(ascii: "t"): out.append(0x09)
            case UInt8(ascii: "r"): out.append(0x0D)
            case UInt8(ascii: "b"): out.append(0x08)
            case UInt8(ascii: "f"): out.append(0x0C)
            case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"): out.append(c)
            case UInt8(ascii: "u"), UInt8(ascii: "U"):
                let n = c == UInt8(ascii: "u") ? 4 : 8
                guard i + n <= b.count, let code = UInt32(String(decoding: b[i..<i + n], as: UTF8.self), radix: 16), let scalar = Unicode.Scalar(code) else { throw Bad() }
                i += n
                out.append(contentsOf: Array(String(Character(scalar)).utf8))
            default: throw Bad()
            }
        }

        mutating func array(depth: Int) throws -> [Any] {
            i += 1
            var items: [Any] = []
            while true {
                skipBlankAndComments()
                guard let c = peek() else { throw Bad() }
                if c == UInt8(ascii: "]") { i += 1; return items }
                items.append(try value(depth: depth + 1))
                skipBlankAndComments()
                if peek() == UInt8(ascii: ",") { i += 1 }
                else if peek() != UInt8(ascii: "]") { throw Bad() }
                if items.count > 100_000 { throw Bad() }
            }
        }

        mutating func inlineTable(depth: Int) throws -> [String: Any] {
            i += 1
            var t: [String: Any] = [:]
            while true {
                skipBlankAndComments()
                guard let c = peek() else { throw Bad() }
                if c == UInt8(ascii: "}") { i += 1; return t }
                let key = try keyPath()
                skipSpaces()
                guard peek() == UInt8(ascii: "=") else { throw Bad() }
                i += 1
                skipSpaces()
                Self.set(&t, key[...], try value(depth: depth + 1))
                skipBlankAndComments()
                if peek() == UInt8(ascii: ",") { i += 1 }
                else if peek() != UInt8(ascii: "}") { throw Bad() }
            }
        }

        mutating func scalar() throws -> Any {
            let start = i
            while let c = peek(), c != 0x0A, c != 0x0D, c != UInt8(ascii: ","), c != UInt8(ascii: "]"), c != UInt8(ascii: "}"), c != UInt8(ascii: "#") { i += 1 }
            let text = String(decoding: b[start..<i], as: UTF8.self).trimmingCharacters(in: .whitespaces)
            guard !text.isEmpty else { throw Bad() }
            if text == "true" { return true }
            if text == "false" { return false }
            let clean = text.replacingOccurrences(of: "_", with: "")
            if let n = Int(clean) { return n }
            if let n = Int(clean.dropFirst(2), radix: 16), clean.hasPrefix("0x") { return n }
            if let d = Double(clean) { return d }
            if text.first.map({ $0.isNumber }) == true { return text }   // a date or time: kept as written
            throw Bad()
        }

        // MARK: whitespace

        func peek() -> UInt8? { i < b.count ? b[i] : nil }
        mutating func skipSpaces() { while let c = peek(), c == 0x20 || c == 0x09 { i += 1 } }
        mutating func skipLine() { while let c = peek(), c != 0x0A { i += 1 } }
        mutating func skipBlank() {
            while let c = peek() {
                if c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D { i += 1 }
                else if c == UInt8(ascii: "#") { skipLine() }
                else { break }
            }
        }
        mutating func skipBlankAndComments() { skipBlank() }

        // MARK: tree

        /// Walks `path`, creating tables on the way; an array of tables is entered at its last element.
        static func update(_ node: inout [String: Any], _ path: ArraySlice<String>, _ body: (inout [String: Any]) -> Void) {
            guard let key = path.first else { body(&node); return }
            let rest = path.dropFirst()
            if var arr = node[key] as? [Any], var last = arr.last as? [String: Any] {
                node[key] = nil
                update(&last, rest, body)
                arr[arr.count - 1] = last
                node[key] = arr
                return
            }
            var child = (node[key] as? [String: Any]) ?? [:]
            node[key] = nil
            update(&child, rest, body)
            node[key] = child
        }

        static func set(_ root: inout [String: Any], _ path: ArraySlice<String>, _ value: Any) {
            guard let leaf = path.last else { return }
            update(&root, path.dropLast()) { $0[leaf] = value }
        }

        /// `[[a.b]]`: append an empty table to the array at `a.b`, creating it if needed.
        static func appendTable(_ root: inout [String: Any], _ path: ArraySlice<String>) {
            guard let leaf = path.last else { return }
            update(&root, path.dropLast()) { parent in
                var arr = (parent[leaf] as? [Any]) ?? []
                arr.append([String: Any]())
                parent[leaf] = arr
            }
        }
    }
}
