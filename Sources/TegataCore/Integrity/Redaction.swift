import Foundation

/// Makes a command line or URL safe to show, store in a report and put in a notification. The
/// original stays in memory only long enough to fingerprint it.
public enum IntegrityRedaction {
    /// Longest text a report carries; the rest is `…`.
    public static let maxDisplayLength = 300
    /// Text redacted before cutting to `maxDisplayLength`. A hostile or just huge hook command must not make the
    /// regexes run for seconds; a secret that starts past this point is cut from the display anyway.
    static let maxScanLength = 2_000

    /// Masks values the Exposure rules recognise (same masking: 6 + `****` + 4), strips credentials from
    /// URLs, shows the home directory as `~` and cuts long text.
    public static func command(_ text: String, home: String) -> String {
        var s = text.count > maxScanLength ? String(text.prefix(maxScanLength)) : text
        s = redactURLs(in: s)
        s = redactSecrets(in: s)
        s = redactNamedValues(in: s)
        if !home.isEmpty, home != "/" { s = s.replacingOccurrences(of: home, with: "~") }
        return truncate(s)
    }

    public static func truncate(_ s: String, to limit: Int = maxDisplayLength) -> String {
        s.count > limit ? String(s.prefix(limit)) + "…" : s
    }

    /// `https://user:pw@host/p?token=abc#frag` becomes `https://host/p?token=…`. Applied to every
    /// `scheme://` run in the text, so inline scripts and `curl` commands are covered too.
    static let urlRegex = try! NSRegularExpression(pattern: #"[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>)\]]+"#)

    static func redactURLs(in s: String) -> String {
        let regex = urlRegex
        let ns = s as NSString
        var out = s
        for m in regex.matches(in: s, range: NSRange(location: 0, length: ns.length)).reversed() {
            let raw = ns.substring(with: m.range)
            guard let r = Range(m.range, in: out) else { continue }
            out.replaceSubrange(r, with: redactURL(raw))
        }
        return out
    }

    static func redactURL(_ raw: String) -> String {
        guard var c = URLComponents(string: raw) else { return raw }
        c.user = nil; c.password = nil; c.fragment = nil
        if let items = c.queryItems, !items.isEmpty {
            c.queryItems = items.map { URLQueryItem(name: $0.name, value: $0.value == nil ? nil : "…") }
        }
        return c.string?.removingPercentEncoding ?? c.string ?? raw
    }

    /// Anything that follows a secret-sounding name (`--token x`, `PASSWORD=x`, `Bearer x`, `api_key: x`) is
    /// hidden whatever its length or shape: a command line is shown to the user and put in notifications, and a
    /// short password has no recognisable shape. Over-masking an ordinary word costs a glance; leaking costs more.
    /// Variable references (`$TOKEN`, `${X}`) are left alone, they are not the secret.
    /// Starts at the keyword, so there is no leading run to re-scan from every position; what follows the keyword
    /// (the rest of the name, a separator, an optional quote) is matched once, left to right.
    static let namedValueRegex = try! NSRegularExpression(
        pattern: #"(?i)(secret|token|passw(?:or)?d|api[_-]?key|private[_-]?key|credential|bearer)([A-Za-z0-9_.-]{0,40})(\s*[=:]\s*|\s+)(["']?)([^\s"']{3,})"#)

    static func redactNamedValues(in s: String) -> String {
        let regex = namedValueRegex
        let ns = s as NSString
        var out = s
        for m in regex.matches(in: s, range: NSRange(location: 0, length: ns.length)).reversed() {
            let value = ns.substring(with: m.range(at: 5))
            if value.hasPrefix("$") || value.hasPrefix("<") || value.contains("****") || value.contains("…") { continue }
            guard let r = Range(m.range(at: 5), in: out) else { continue }
            out.replaceSubrange(r, with: value.count >= 20 ? SecretFinding.mask(value) : "****")
        }
        return out
    }

    static func redactSecrets(in s: String) -> String {
        let ns = s as NSString
        var hits: [NSRange] = []
        for rule in SecretRules.all {
            for m in rule.pattern.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
                let r = m.range(at: rule.valueGroup)
                guard r.location != NSNotFound else { continue }
                if SecretRules.isPlaceholder(ns.substring(with: r)) { continue }
                hits.append(r)
            }
        }
        // Longest first, then drop ranges contained in an earlier one, so overlapping rules mask once.
        hits.sort { $0.location != $1.location ? $0.location < $1.location : $0.length > $1.length }
        var merged: [NSRange] = []
        for r in hits {
            if let last = merged.last, r.location < last.location + last.length { continue }
            merged.append(r)
        }
        var out = s
        for r in merged.reversed() {
            guard let range = Range(r, in: out) else { continue }
            out.replaceSubrange(range, with: SecretFinding.mask(ns.substring(with: r)))
        }
        return out
    }
}
