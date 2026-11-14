import Foundation

/// The entries Tegata itself writes into an agent's configuration.
public enum TegataRole: String, Sendable, Codable, CaseIterable {
    /// `apiKeyHelper` pointing at this copy's `tegata-token`.
    case credentialHelper = "credential-helper"
    /// The `PreToolUse` hook that runs this copy's `tegata-guard.sh` with the guard's matcher.
    case guardHook = "guard-hook"
}

/// Something that names Tegata's files without being this copy's own entry.
public enum TegataClaim: String, Sendable, Codable, CaseIterable {
    /// A Tegata bundle path whose file is gone (the app was moved or deleted): needs repair, not alarm.
    case staleCopy = "stale-copy"
    /// A Tegata bundle path that exists but is not this copy (a developer build, an old download, or a fake bundle):
    /// only the code signature can tell, which the agent checks.
    case otherCopy = "other-copy"
    /// Uses this copy's own files in an entry Tegata did not write: the guard script under another matcher or event,
    /// the credential helper as a hook. Tegata's own entry was edited, or someone borrows its files.
    case tampered
    /// Uses the names of Tegata's files outside a Tegata bundle (`/tmp/tegata-token`, `~/.tegata/tegata-guard.sh`).
    case impostor
}

/// What this copy of Tegata writes, so the inventory can tell Tegata's own entries from everything else. Recognition
/// is by exact value, never by name: an owner inferred as "tegata" from a path is just a string anyone can choose.
public struct TegataFootprint: Sendable, Equatable {
    public var helperPath: String
    public var guardHookPath: String
    public var guardMatcher: String

    public init(helperPath: String, guardHookPath: String, guardMatcher: String = ExposureGuard.hookMatcher) {
        self.helperPath = helperPath; self.guardHookPath = guardHookPath; self.guardMatcher = guardMatcher
    }

    /// The paths inside an app bundle, as the app computes them (`ClaudeCodeService`).
    public init(appBundle: URL) {
        self.init(helperPath: appBundle.appendingPathComponent("Contents/MacOS/tegata-token").path,
                  guardHookPath: appBundle.appendingPathComponent("Contents/Resources/tegata-guard.sh").path)
    }

    /// File names only Tegata ships. A command that uses one of them outside this copy's bundle is a claim to be Tegata.
    static let shippedNames: Set<String> = ["tegata-token", "tegata-guard.sh", "tegatad"]
    static let bundleShape = try! NSRegularExpression(pattern: #"/Tegata\.app/Contents/(?:MacOS/tegata-token|Resources/tegata-guard\.sh|Library/LoginItems/[^/]+/Contents/MacOS/tegatad)$"#, options: [.caseInsensitive])

    /// Whether `command` is this copy's entry for `role`, or else whether it claims to be Tegata, and how.
    /// `contentDigest` tells a stale bundle path (`missing`) from one that exists.
    static func mark(command: String, home: String, footprint: TegataFootprint?, expected role: TegataRole?,
                     event: String? = nil, matcher: String? = nil, contentDigest: String?) -> (role: TegataRole?, claim: TegataClaim?) {
        let trimmed = command.trimmingCharacters(in: .whitespaces)
        let unquoted = trimmed.count >= 2 && (trimmed.first == "\"" && trimmed.last == "\"" || trimmed.first == "'" && trimmed.last == "'")
            ? String(trimmed.dropFirst().dropLast()) : trimmed
        if let fp = footprint, let role {
            switch role {
            case .credentialHelper where unquoted == fp.helperPath: return (.credentialHelper, nil)
            case .guardHook where unquoted == fp.guardHookPath && event == "PreToolUse" && matcher == fp.guardMatcher: return (.guardHook, nil)
            default: break
            }
        }
        // Any path token that uses a name only Tegata ships.
        let paths = CommandAnalysis.scriptPaths(in: command, home: home, limit: 8)
        let named = paths.filter { shippedNames.contains(($0 as NSString).lastPathComponent.lowercased()) }
            + CommandAnalysis.tokens(command).filter { !$0.hasPrefix("/") && !$0.hasPrefix("~") && shippedNames.contains(($0 as NSString).lastPathComponent.lowercased()) }
        guard !named.isEmpty else { return (nil, nil) }
        if let fp = footprint, named.contains(where: { $0 == fp.helperPath || $0 == fp.guardHookPath }) { return (nil, .tampered) }
        let bundled = named.allSatisfy { p in bundleShape.firstMatch(in: p, range: NSRange(location: 0, length: (p as NSString).length)) != nil }
        guard bundled else { return (nil, .impostor) }
        return (nil, contentDigest == "missing" ? .staleCopy : .otherCopy)
    }
}
