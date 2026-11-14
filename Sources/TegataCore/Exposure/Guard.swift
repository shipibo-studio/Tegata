import Foundation

/// "Close the source": what Tegata writes into Claude Code settings so the agent stops reading
/// credential files. Rules and the hook are removable from the same screen.
public enum ExposureGuard {
    /// Permission deny rules (Claude Code `permissions.deny`). Exact env names, not `.env.*`: a wildcard
    /// would also deny `.env.example` and `.env.schema`, which the agent should read. The hook covers the rest.
    public static let denyRules: [String] = [
        "Read(**/.env)",
        "Read(**/.env.local)",
        "Read(**/.env.development)",
        "Read(**/.env.development.local)",
        "Read(**/.env.production)",
        "Read(**/.env.production.local)",
        "Read(**/.env.staging)",
        "Read(**/.env.test)",
        "Read(**/.env.test.local)",
        "Read(**/.env.secret)",
        "Read(**/.env.secrets)",
        "Read(**/*.pem)",
        "Read(**/*.key)",
        "Read(**/*.p12)",
        "Read(**/*.pfx)",
        "Read(**/id_rsa*)",
        "Read(**/id_ed25519*)",
        "Read(**/id_ecdsa*)",
        "Read(**/.netrc)",
        "Read(**/secrets/**)",
        "Read(**/.aws/credentials)",
        "Read(~/.claude.json)",
        "Read(~/.claude/backups/**)",
    ]

    /// Files whose names are credential-shaped, for the hook (basename match, case-insensitive).
    public static let fileNamePatterns: [String] = [
        #"^\.env(\..*)?$"#, #".*\.(pem|key|p12|pfx|jks|keystore)$"#, #"^id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$"#,
        #"^\.netrc$"#, #"^credentials(\.json)?$"#, #"^\.claude\.json(\.backup.*)?$"#, #"^oauth_creds\.json$"#, #"^auth\.json$"#,
    ]
    public static let allowedEnvSuffixes = [".example", ".sample", ".schema", ".template", ".dist"]

    public static let hookMatcher = "Read|Edit|Write|MultiEdit|Bash|Grep|Glob"

    /// Decides for one path. `.env.example`-style files are allowed.
    public static func isCredentialFile(_ path: String) -> Bool {
        let name = (path as NSString).lastPathComponent
        if name.hasPrefix(".env"), allowedEnvSuffixes.contains(where: { name.hasSuffix($0) }) { return false }
        if path.contains("/secrets/") { return true }
        return fileNamePatterns.contains { name.range(of: $0, options: [.regularExpression, .caseInsensitive]) != nil }
    }

    /// For Bash commands: any token that looks like a credential file path.
    public static func commandTouchesCredentialFile(_ command: String) -> Bool {
        let tokens = command.split(whereSeparator: { " \t;&|<>()'\"`".contains($0) })
        return tokens.contains { t in
            var s = String(t)
            if s.hasPrefix("~/") { s = "/" + s.dropFirst(2) }
            return isCredentialFile(s)
        }
    }
}
