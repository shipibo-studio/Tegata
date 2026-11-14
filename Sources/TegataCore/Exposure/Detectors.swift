import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// A secret-shaped match. `value` is never stored; only what the report shows.
public struct SecretFinding: Sendable, Equatable, Identifiable {
    public enum Confidence: String, Sendable, Codable { case high, medium, low }
    public var id: String { "\(file):\(line):\(column):\(rule)" }
    public var file: String
    public var line: Int
    public var column: Int
    /// Length of the matched value, so a preview can mask exactly that span. Never the value.
    public var length: Int
    public var rule: String
    public var keyName: String?
    /// Masked form of the value: the first six and the last four characters around `****` for values
    /// of 20+ characters, the first four and `****` for shorter ones. Enough to recognise, useless to reuse.
    public var preview: String
    public var confidence: Confidence
    public var source: ExposureSource.Kind
    /// Same value, same id, within one run: an HMAC under a key made when the process starts and never stored, so
    /// copies of one key can be counted as one key to rotate. Not printed, not comparable across runs, no use for
    /// guessing. nil where the match is not the secret itself (a private key's header line).
    public var valueID: String?
    /// For a JWT, its `exp` claim (the only claim read). nil when absent or not a JWT.
    public var expiresAt: Date?

    /// `sk-ant-****cdef` for long values, `sk-a****` for short ones. The value is not kept.
    public static func mask(_ value: String) -> String {
        value.count >= 20 ? String(value.prefix(6)) + "****" + String(value.suffix(4)) : String(value.prefix(4)) + "****"
    }

    public init(file: String, line: Int, column: Int, length: Int = 0, rule: String, keyName: String?, preview: String, confidence: Confidence,
                source: ExposureSource.Kind, valueID: String? = nil, expiresAt: Date? = nil) {
        self.file = file; self.line = line; self.column = column; self.length = length; self.rule = rule; self.keyName = keyName
        self.preview = preview; self.confidence = confidence; self.source = source; self.valueID = valueID; self.expiresAt = expiresAt
    }

    /// The per-process key behind `valueID`.
    static let runKey = SymmetricKey(size: .bits256)
    static func valueID(_ value: String) -> String {
        HMAC<SHA256>.authenticationCode(for: Data(value.utf8), using: runKey).prefix(12).map { String(format: "%02x", $0) }.joined()
    }

    /// The `exp` of a JWT, read from its payload; nothing else in the payload is kept.
    static func jwtExpiry(_ token: String) -> Date? {
        let parts = token.split(separator: ".")
        guard parts.count == 3 else { return nil }
        var b64 = parts[1].replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64 += "=" }
        guard b64.count <= 16_384, let data = Data(base64Encoded: b64),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        if let n = obj["exp"] as? NSNumber { return Date(timeIntervalSince1970: n.doubleValue) }
        return nil
    }
}

/// One detection rule: a name, a regex over a line, and the confidence a match carries.
public struct SecretRule: Sendable {
    public let name: String
    public let pattern: NSRegularExpression
    public let confidence: SecretFinding.Confidence
    /// Capture group holding the value (0 = whole match).
    public let valueGroup: Int
    /// Capture group holding the key name, if the pattern has one.
    public let keyGroup: Int?

    public init(_ name: String, _ regex: String, confidence: SecretFinding.Confidence, valueGroup: Int = 0, keyGroup: Int? = nil) {
        self.name = name
        self.pattern = try! NSRegularExpression(pattern: regex, options: [])
        self.confidence = confidence; self.valueGroup = valueGroup; self.keyGroup = keyGroup
    }
}

/// Provider-shaped tokens first (high confidence), then assignments of secret-looking names to
/// long values (medium), then long random strings next to such names (low).
public enum SecretRules {
    public static let providers: [SecretRule] = [
        .init("anthropic-key", #"sk-ant-(?:api|oat|admin)[0-9]{2}-[A-Za-z0-9_-]{20,}"#, confidence: .high),
        .init("openai-key", #"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}"#, confidence: .high),
        .init("openai-legacy-key", #"\bsk-[A-Za-z0-9]{32,}\b"#, confidence: .medium),
        .init("github-token", #"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"#, confidence: .high),
        .init("github-fine-grained", #"\bgithub_pat_[A-Za-z0-9_]{60,}\b"#, confidence: .high),
        .init("aws-access-key", #"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"#, confidence: .high),
        .init("google-api-key", #"\bAIza[0-9A-Za-z_-]{35}\b"#, confidence: .high),
        .init("slack-token", #"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"#, confidence: .high),
        .init("stripe-key", #"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b"#, confidence: .high),
        .init("sendgrid-key", #"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"#, confidence: .high),
        .init("npm-token", #"\bnpm_[A-Za-z0-9]{36}\b"#, confidence: .high),
        .init("vercel-token", #"\bvcp_[A-Za-z0-9]{20,}\b"#, confidence: .medium),
        .init("fly-token", #"\bfo1_[A-Za-z0-9_-]{20,}\b"#, confidence: .high),
        .init("hf-token", #"\bhf_[A-Za-z0-9]{30,}\b"#, confidence: .high),
        .init("jwt", #"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"#, confidence: .medium),
        .init("private-key-block", #"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"#, confidence: .high),
        .init("connection-url-with-password", #"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/([^:\/\s]+):([^@\/\s]{4,})@"#, confidence: .high, valueGroup: 2, keyGroup: 1),
    ]

    /// `NAME=value`, `NAME: value`, `"NAME": "value"`, `export NAME=value` where NAME smells like a
    /// secret and the value is long enough to be one.
    public static let assignment = SecretRule(
        "secret-assignment",
        #"(?i)(?:^|[\s,{"'])(?:export\s+)?["']?([A-Z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|APIKEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|AUTH|CREDENTIAL|BEARER)[A-Z0-9_.-]*)["']?\s*[:=]\s*["']?([^\s"',;]{16,})"#,
        confidence: .medium, valueGroup: 2, keyGroup: 1)

    public static let all: [SecretRule] = providers + [assignment]

    /// Values that look like placeholders, not secrets.
    public static func isPlaceholder(_ v: String) -> Bool {
        let l = v.lowercased()
        if l.contains("xxxx") || l.contains("your_") || l.contains("your-") || l.contains("changeme") || l.contains("example") || l.contains("placeholder") || l.contains("<") { return true }
        if l.hasPrefix("${") || l.hasPrefix("$(") || l.hasPrefix("op://") || l.hasPrefix("varlock(") || l.hasPrefix("keychain(") { return true }
        // Paths and plain URLs are configuration, not secrets (URLs with a password match their own rule).
        if l.hasPrefix("/") || l.hasPrefix("./") || l.hasPrefix("~/") || l.hasPrefix("http://") || l.hasPrefix("https://") || l.hasPrefix("file://") { return true }
        if Set(l).count <= 3 { return true }   // "0000000000000000", "aaaa…"
        return false
    }

    /// Shannon entropy in bits per character; random keys sit above ~3.5.
    public static func entropy(_ s: String) -> Double {
        guard !s.isEmpty else { return 0 }
        var counts: [Character: Double] = [:]
        for c in s { counts[c, default: 0] += 1 }
        let n = Double(s.count)
        return counts.values.reduce(0) { $0 - ($1 / n) * log2($1 / n) }
    }
}

/// Runs the rules over text, one line at a time. Values are dropped after the preview is cut.
public struct SecretDetector: Sendable {
    public let rules: [SecretRule]
    public init(rules: [SecretRule] = SecretRules.all) { self.rules = rules }

    public func scan(text: String, file: String, source: ExposureSource.Kind, maxLineLength: Int = 20_000) -> [SecretFinding] {
        var out: [SecretFinding] = []
        var seen = Set<String>()
        var lineNo = 0
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            lineNo += 1
            guard rawLine.count <= maxLineLength else { continue }
            let line = String(rawLine)
            let ns = line as NSString
            let range = NSRange(location: 0, length: ns.length)
            for rule in rules {
                for m in rule.pattern.matches(in: line, options: [], range: range) {
                    let vr = m.range(at: rule.valueGroup)
                    guard vr.location != NSNotFound else { continue }
                    let value = ns.substring(with: vr)
                    if SecretRules.isPlaceholder(value) { continue }
                    var confidence = rule.confidence
                    if rule.name == "secret-assignment" {
                        let e = SecretRules.entropy(value)
                        if e < 3.0 { continue }               // words, paths, repeated chars
                        if e >= 4.0 && value.count >= 24 { confidence = .high }
                    }
                    let key = rule.keyGroup.flatMap { g -> String? in
                        let kr = m.range(at: g); return kr.location == NSNotFound ? nil : ns.substring(with: kr)
                    }
                    let dedupe = "\(lineNo):\(vr.location)"
                    guard !seen.contains(dedupe) else { continue }
                    seen.insert(dedupe)
                    out.append(SecretFinding(file: file, line: lineNo, column: vr.location + 1, length: vr.length, rule: rule.name, keyName: key,
                                             preview: SecretFinding.mask(value), confidence: confidence, source: source,
                                             valueID: rule.name == "private-key-block" ? nil : SecretFinding.valueID(value),
                                             expiresAt: rule.name == "jwt" ? SecretFinding.jwtExpiry(value) : nil))
                }
            }
        }
        return out
    }
}
