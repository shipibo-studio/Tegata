import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Which agent a piece of configuration belongs to.
public enum AgentKind: String, Sendable, Codable, CaseIterable {
    case claudeCode = "claude-code"
    case codex
    case cursor
    case claudeDesktop = "claude-desktop"
    case gemini
}

/// What the entry can do to the user's agent.
public enum ExtensionKind: String, Sendable, Codable, CaseIterable {
    case hook, mcpServer = "mcp-server", plugin, marketplace, skill, subagent, command, permissions, env
    /// A program the agent runs to get its own credential (`apiKeyHelper`). Whatever it prints is the key.
    case credentialHelper = "credential-helper"
}

/// Where the entry was declared. `managed` outranks the others in Claude Code.
public enum ConfigScope: String, Sendable, Codable, CaseIterable {
    case managed, user, project, local
}

/// The facts about one entry, kept apart from the entry's identity so a parser fills only what its
/// kind has. Anything that can carry a secret (command lines, URLs, env) is already redacted here;
/// raw values never reach the model.
public enum ExtensionDetail: Sendable, Equatable, Codable {
    /// `event` is `PreToolUse`, `UserPromptSubmit`...; `matcher` is nil when it applies to everything.
    /// `commandKind` is the hook's own `type` (`command`, `prompt`, `agent`, `http`...).
    case hook(event: String, matcher: String?, commandKind: String, command: String?, scriptPath: String?, timeoutSeconds: Int?)
    /// `transport`: `stdio`, `http`, `sse` or `unknown`. `pinned` is false for `npx -y pkg`, `uvx pkg`,
    /// `bunx` and similar launches that fetch whatever is newest.
    case mcpServer(transport: String, command: String?, args: [String], url: String?, envKeys: [String], pinned: Bool)
    case plugin(id: String, enabled: Bool)
    case marketplace(name: String, sourceKind: String?, location: String?)
    /// Skills, subagents and commands are directories or files on disk. `executables` are paths relative
    /// to the entry, so the report can say what would run, never its content.
    case fileBased(fileCount: Int, executables: [String], modified: Date?)
    /// `allow` rules are kept as written (they are patterns, not secrets); counts are for the report.
    case permissions(allow: [String], deny: [String], ask: [String], defaultMode: String?)
    /// Names only. A value is never read into the model.
    case envKeys([String])
    /// Non-secret policy switches an agent keeps in its config (`approval_policy`, `sandbox_mode`, folder trust).
    /// Only whitelisted keys are copied, so this can never carry a credential.
    case policy(values: [String: String])
}

/// One entry of an agent's configuration, with a stable identity so two scans can be diffed.
public struct AgentExtension: Sendable, Equatable, Identifiable, Codable {
    /// `agent|scope|kind|file|key`: `file` is the declaring file as shown (`~/.claude/settings.json`), so the same
    /// hook in two projects, or a marketplace named in two files, are two entries; `key` locates the entry
    /// inside its file (event + matcher + command hash, server name, skill name).
    public var id: String
    public var agent: AgentKind
    public var scope: ConfigScope
    public var kind: ExtensionKind
    /// Short label for the UI: a server name, a skill name, `PreToolUse · Bash`.
    public var name: String
    /// File that declares it, with the home directory shown as `~`. Never the file's content.
    public var declaredIn: String
    public var detail: ExtensionDetail
    /// Who installed it, inferred from paths and package names; nil when nothing in the entry says.
    public var owner: String?
    /// SHA-256 over the canonical form of the entry as written, values included, so a changed token or
    /// a redirected `ANTHROPIC_BASE_URL` still counts as a change. Hex only; the entry cannot be read back
    /// from it, but a low-entropy value could be guessed, so a stored baseline is as private as the audit log.
    public var fingerprint: String
    /// Digest of what the entry runs or reads on disk (the script behind a hook or a local MCP server, the files of
    /// a skill or an installed plugin); see `ContentDigester` for the values. nil when there is nothing to hash
    /// (an inline command, an env setting). It is already part of `fingerprint`; it is kept apart so a change can
    /// be told as "the script it runs changed" instead of "the entry changed".
    public var contentDigest: String?
    /// What the command and the script behind it do, as `ScriptTrait` raw values, sorted. nil when nothing was found or
    /// nothing was analysed. Derived from the command and the files already in the fingerprint, so it is not hashed.
    public var traits: [String]?
    /// Set only when the entry is exactly what this copy of Tegata writes (see `TegataFootprint`). Such an entry gets no
    /// risk findings and is not content-hashed: its files are inside Tegata's signed bundle.
    public var tegataRole: TegataRole?
    /// Set when the entry uses Tegata's file names without being Tegata's own entry. Rated, never trusted.
    public var tegataClaim: TegataClaim?
    /// SHA-256 of where the entry sits and its text as written (canonical JSON), independent of Tegata's rules: it only
    /// changes when the entry itself does. nil for skills, subagents and commands, which have no entry text.
    public var entryHash: String?
    /// For an MCP server: the `headersHelper` program the agent runs to build the server's request headers (usually its
    /// credentials), redacted. Kept outside `detail` so snapshots written before it existed still decode.
    public var headersHelper: String?
    /// For an MCP server: the names of its static `headers`. Values are never read into the model; they are often tokens.
    public var headerKeys: [String]?

    public init(agent: AgentKind, scope: ConfigScope, kind: ExtensionKind, key: String, name: String,
                declaredIn: String, detail: ExtensionDetail, owner: String?, fingerprint: String, contentDigest: String? = nil, traits: [String]? = nil,
                tegataRole: TegataRole? = nil, tegataClaim: TegataClaim? = nil) {
        self.id = [agent.rawValue, scope.rawValue, kind.rawValue, declaredIn, key].joined(separator: "|")
        self.agent = agent; self.scope = scope; self.kind = kind; self.name = name
        self.declaredIn = declaredIn; self.detail = detail; self.owner = owner; self.fingerprint = fingerprint
        self.contentDigest = contentDigest; self.traits = traits; self.tegataRole = tegataRole; self.tegataClaim = tegataClaim
    }
}

/// What a scan found, and what it could not read. A partial inventory says so, like the Exposure report.
public struct AgentInventory: Sendable, Equatable {
    public var scannedAt: Date
    public var extensions: [AgentExtension]
    /// Files or directories that exist but could not be read or parsed, with the reason.
    public var incomplete: [String]

    public init(scannedAt: Date, extensions: [AgentExtension], incomplete: [String]) {
        self.scannedAt = scannedAt; self.extensions = extensions; self.incomplete = incomplete
    }

    public func entries(of kind: ExtensionKind) -> [AgentExtension] { extensions.filter { $0.kind == kind } }
    public var byId: [String: AgentExtension] { Dictionary(extensions.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a }) }
}

enum Fingerprint {
    /// Canonical JSON (sorted keys, no whitespace) so formatting changes do not look like edits.
    static func ofJSON(_ value: Any) -> String {
        guard JSONSerialization.isValidJSONObject(["v": value]),
              let data = try? JSONSerialization.data(withJSONObject: ["v": value], options: [.sortedKeys, .withoutEscapingSlashes])
        else { return ofBytes(Data("\(value)".utf8)) }
        return ofBytes(data)
    }
    static func ofBytes(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

extension Date {
    /// Whole seconds: the iso8601 encoding the snapshot uses drops fractions, so a value that went through it must
    /// already be whole for the model to compare equal after a round trip.
    var wholeSeconds: Date { Date(timeIntervalSince1970: timeIntervalSince1970.rounded(.down)) }
}
