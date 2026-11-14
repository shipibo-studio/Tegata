import Foundation

/// Edits a Claude Code `settings.json` for Tegata's two keys and nothing else. Every other key,
/// including unknown ones, survives untouched. Formatting is normalized (pretty-printed, sorted
/// keys), which Claude Code does not care about; the caller keeps a backup before writing.
public enum ClaudeSettingsEditor {
    public static let helperKey = "apiKeyHelper"
    public static let envKey = "env"
    public static let ttlKey = "CLAUDE_CODE_API_KEY_HELPER_TTL_MS"

    public struct State: Equatable, Sendable {
        public var apiKeyHelper: String?
        public var ttlMilliseconds: Int?
        public init(apiKeyHelper: String?, ttlMilliseconds: Int?) { self.apiKeyHelper = apiKeyHelper; self.ttlMilliseconds = ttlMilliseconds }
        /// True when `apiKeyHelper` points at the given helper path.
        public func isConfigured(helperPath: String) -> Bool { apiKeyHelper == helperPath }
    }

    public enum EditorError: Error, Equatable {
        case notAnObject
        case invalidJSON(String)
    }

    static func parse(_ data: Data?) throws -> [String: Any] {
        guard let data = data, !data.isEmpty else { return [:] }
        let obj: Any
        do { obj = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) }
        catch { throw EditorError.invalidJSON(String(describing: error)) }
        guard let dict = obj as? [String: Any] else { throw EditorError.notAnObject }
        return dict
    }

    static func serialize(_ dict: [String: Any]) throws -> Data {
        var out = try JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        out.append(0x0A)
        return out
    }

    public static func inspect(_ data: Data?) throws -> State {
        let dict = try parse(data)
        let env = dict[envKey] as? [String: Any]
        let ttlRaw = env?[ttlKey]
        let ttl: Int? = (ttlRaw as? Int) ?? (ttlRaw as? String).flatMap(Int.init)
        return State(apiKeyHelper: dict[helperKey] as? String, ttlMilliseconds: ttl)
    }

    /// Sets `apiKeyHelper` and `env.CLAUDE_CODE_API_KEY_HELPER_TTL_MS`, keeping every other key.
    public static func configure(_ data: Data?, helperPath: String, ttlMilliseconds: Int) throws -> Data {
        var dict = try parse(data)
        dict[helperKey] = helperPath
        var env = (dict[envKey] as? [String: Any]) ?? [:]
        env[ttlKey] = String(ttlMilliseconds)   // Claude Code documents env values as strings
        dict[envKey] = env
        return try serialize(dict)
    }

    /// Removes Tegata's keys; drops `env` only if Tegata's entry was the last one.
    public static func unconfigure(_ data: Data?) throws -> Data {
        var dict = try parse(data)
        dict.removeValue(forKey: helperKey)
        if var env = dict[envKey] as? [String: Any] {
            env.removeValue(forKey: ttlKey)
            if env.isEmpty { dict.removeValue(forKey: envKey) } else { dict[envKey] = env }
        }
        return try serialize(dict)
    }

    /// Adds Claude Code permission deny rules (Exposure module, M4.5); idempotent.
    public static func addDenyRules(_ data: Data?, rules: [String]) throws -> Data {
        var dict = try parse(data)
        var perms = (dict["permissions"] as? [String: Any]) ?? [:]
        var deny = (perms["deny"] as? [String]) ?? []
        for r in rules where !deny.contains(r) { deny.append(r) }
        perms["deny"] = deny
        dict["permissions"] = perms
        return try serialize(dict)
    }

    /// Adds a `PreToolUse` command hook (idempotent by command path).
    public static func addPreToolUseHook(_ data: Data?, matcher: String, command: String) throws -> Data {
        var dict = try parse(data)
        var hooks = (dict["hooks"] as? [String: Any]) ?? [:]
        var pre = (hooks["PreToolUse"] as? [[String: Any]]) ?? []
        let present = pre.contains { entry in ((entry["hooks"] as? [[String: Any]]) ?? []).contains { ($0["command"] as? String) == command } }
        if !present {
            pre.append(["matcher": matcher, "hooks": [["type": "command", "command": command]]])
        }
        hooks["PreToolUse"] = pre
        dict["hooks"] = hooks
        return try serialize(dict)
    }

    public static func removePreToolUseHook(_ data: Data?, command: String) throws -> Data {
        var dict = try parse(data)
        guard var hooks = dict["hooks"] as? [String: Any], var pre = hooks["PreToolUse"] as? [[String: Any]] else { return try serialize(dict) }
        pre = pre.compactMap { entry in
            var e = entry
            let kept = ((e["hooks"] as? [[String: Any]]) ?? []).filter { ($0["command"] as? String) != command }
            if kept.isEmpty { return nil }
            e["hooks"] = kept
            return e
        }
        if pre.isEmpty { hooks.removeValue(forKey: "PreToolUse") } else { hooks["PreToolUse"] = pre }
        if hooks.isEmpty { dict.removeValue(forKey: "hooks") } else { dict["hooks"] = hooks }
        return try serialize(dict)
    }

    public static func hasPreToolUseHook(_ data: Data?, command: String) -> Bool {
        guard let dict = try? parse(data), let hooks = dict["hooks"] as? [String: Any], let pre = hooks["PreToolUse"] as? [[String: Any]] else { return false }
        return pre.contains { entry in ((entry["hooks"] as? [[String: Any]]) ?? []).contains { ($0["command"] as? String) == command } }
    }

    public static func denyRules(_ data: Data?) -> [String] {
        guard let dict = try? parse(data), let perms = dict["permissions"] as? [String: Any] else { return [] }
        return (perms["deny"] as? [String]) ?? []
    }

    /// `cleanupPeriodDays`: how long Claude Code keeps transcripts (default 30). nil removes the key.
    public static func setCleanupPeriodDays(_ data: Data?, days: Int?) throws -> Data {
        var dict = try parse(data)
        if let d = days { dict["cleanupPeriodDays"] = d } else { dict.removeValue(forKey: "cleanupPeriodDays") }
        return try serialize(dict)
    }
    public static func cleanupPeriodDays(_ data: Data?) -> Int? {
        (try? parse(data))?["cleanupPeriodDays"] as? Int
    }

    public static func removeDenyRules(_ data: Data?, rules: [String]) throws -> Data {
        var dict = try parse(data)
        guard var perms = dict["permissions"] as? [String: Any], var deny = perms["deny"] as? [String] else { return try serialize(dict) }
        deny.removeAll { rules.contains($0) }
        if deny.isEmpty { perms.removeValue(forKey: "deny") } else { perms["deny"] = deny }
        if perms.isEmpty { dict.removeValue(forKey: "permissions") } else { dict["permissions"] = perms }
        return try serialize(dict)
    }
}

/// File-level operations around the editor: backup, atomic write, 0600.
public enum ClaudeSettingsFile {
    /// Claude Code's managed settings file (admin-writable, overrides user settings).
    public static let managedSettingsPath = "/Library/Application Support/ClaudeCode/managed-settings.json"

    public static func backup(_ url: URL, clock: any TimeSource = SystemClock()) throws -> URL? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        // Named after the file it backs up (`.claude.json` too, not only settings.json), and unique: several edits in the
        // same second (a Revert of several changes) must each keep their own copy instead of failing on the second.
        let stamp = Int(clock.now.timeIntervalSince1970)
        let dir = url.deletingLastPathComponent()
        var dest = dir.appendingPathComponent("\(url.lastPathComponent).tegata-backup-\(stamp)")
        var n = 2
        while FileManager.default.fileExists(atPath: dest.path) {
            dest = dir.appendingPathComponent("\(url.lastPathComponent).tegata-backup-\(stamp)-\(n)"); n += 1
        }
        try FileManager.default.copyItem(at: url, to: dest)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: dest.path)
        return dest
    }

    public static func write(_ data: Data, to url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let tmp = url.appendingPathExtension("tegata-tmp")
        try data.write(to: tmp, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp.path)
        _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp)
        // replaceItemAt keeps the replaced file's attributes; the settings file must not be group/world readable: it can
        // hold tokens in `env`. Git records only the executable bit, so 644 → 600 does not show in a dotfiles repository.
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    /// Backup, edit, write. Returns the backup URL (nil when there was no file).
    public static func edit(_ url: URL, _ transform: (Data?) throws -> Data) throws -> URL? {
        let current = FileManager.default.contents(atPath: url.path)
        let backup = try backup(url)
        // Keep the user's key order, indentation and spelling; only what the edit touched should differ.
        try write(OrderedJSON.restyle(try transform(current), like: current), to: url)
        return backup
    }
}

/// What Tegata wrote into a user's setting and what was there before, so taking Tegata away gives back the user's
/// own value instead of deleting it. nil stands for "the key was absent".
public struct SettingLedger: Codable, Sendable, Equatable {
    public var wrote: Int?
    public var previous: Int?
    public init(wrote: Int?, previous: Int?) { self.wrote = wrote; self.previous = previous }

    /// After Tegata writes `value` over `current`: the first write keeps what the user had; later writes only move
    /// what Tegata wrote.
    public static func recording(_ value: Int?, over current: Int?, existing: SettingLedger?) -> SettingLedger {
        SettingLedger(wrote: value, previous: existing?.previous ?? current)
    }

    /// What Uninstall writes back. nil: leave the file alone (Tegata never set it, or the user changed it since).
    /// `.some(nil)`: remove the key. `.some(n)`: put the user's value back.
    public static func undo(current: Int?, ledger: SettingLedger?) -> Int?? {
        guard let ledger, current == ledger.wrote else { return nil }
        return .some(ledger.previous)
    }
}
