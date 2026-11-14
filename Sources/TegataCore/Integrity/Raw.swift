import Foundation

/// The entry exactly as the file declares it, kept so Revert can put it back. It can hold secrets (a hook's
/// inline script, an `env` value, an MCP header), so it exists only in memory and inside the encrypted
/// snapshot; the model, the index, reports and notifications never carry it.
public struct RawEntry: Sendable, Equatable, Codable {
    public var extensionId: String
    /// Absolute path of the file that declares it.
    public var file: String
    /// Where the entry sits in the file: `["hooks", "PreToolUse"]`, `["mcpServers", "name"]`, `["env"]`.
    public var pointer: [String]
    /// For hooks: the `matcher` of the group the hook belongs to (nil = the group has none).
    public var hookMatcher: String?
    /// `json` or `toml`. A TOML entry is recorded as JSON of its parsed value; putting it back needs a
    /// format-preserving edit, which is a later step.
    public var format: String
    /// Canonical JSON (sorted keys) of the entry.
    public var json: String
}

/// Collects `RawEntry` values while the parsers run. A class because parsers are value-oriented and nested;
/// guarded by a lock so a parallel scan stays correct.
public final class RawCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: RawEntry] = [:]
    public init() {}

    func record(_ e: RawEntry) { lock.withLock { items[e.extensionId] = e } }
    public var entries: [String: RawEntry] { lock.withLock { items } }

    static func canonicalJSON(_ value: Any) -> String {
        guard JSONSerialization.isValidJSONObject(["v": value]),
              let data = try? JSONSerialization.data(withJSONObject: ["v": value], options: [.sortedKeys, .withoutEscapingSlashes]),
              let s = String(data: data, encoding: .utf8)
        else { return "null" }
        // Strip the {"v": … } wrapper added to allow scalar top-level values.
        return String(s.dropFirst(5).dropLast())
    }
}
