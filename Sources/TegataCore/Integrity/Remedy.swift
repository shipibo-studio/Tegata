import Foundation

/// Undoing one change, and nothing else. Revert puts a single entry of a JSON config back the way the baseline had it
/// (or takes out one that was added); Quarantine moves one skill, subagent or command aside where it can be put back.
///
/// Every operation is compare-and-swap: it names what it expects to find, and refuses if the file says otherwise, so
/// a tool that wrote again since the scan is never overwritten blindly. Files are backed up before they are written
/// (`ClaudeSettingsFile.edit`), and the rest of the file is kept as it is.
public enum IntegrityRemedy {
    public enum RemedyError: Error, Equatable, Sendable {
        /// The entry lives in a TOML file (Codex); editing TOML without losing its comments and layout is not done yet.
        case unsupportedFormat(String)
        /// The file no longer holds what the scan saw. Rescan and look again before undoing anything.
        case conflict(String)
        /// Nothing to undo with: no baseline copy for a removed or edited entry, or no current copy for an added one.
        case missingCopy(String)
        /// Only the script or files behind the entry changed; Tegata keeps no copies of scripts, so it can take the
        /// entry out (Remove) but cannot bring the old script back.
        case contentOnly
        case notAllowed(String)
    }

    /// What can be offered for a change. `revert` puts the baseline's version back; `remove` takes the entry out.
    public enum Option: String, Sendable, Codable { case revert, remove, quarantine }

    /// `format` nil means "infer it from the file the entry is declared in".
    public static func options(for change: IntegrityChange, format: String? = nil) -> [Option] {
        let format = format ?? (change.declaredIn.hasSuffix(".toml") ? "toml" : "json")
        let fileBased: Set<ExtensionKind> = [.skill, .subagent, .command]
        if fileBased.contains(change.extensionKind) { return change.kind == .removed ? [] : [.quarantine] }
        guard format == "json" else { return [] }
        switch change.kind {
        case .added: return [.remove]
        case .removed: return [.revert]
        case .modified: return change.contentChanged ? [.remove] : [.revert, .remove]
        }
    }

    /// What can be done with an entry that is there now, whether or not it changed since the baseline. Tegata's own
    /// entries are removed from Tegata's own screens; managed ones belong to the administrator's file; entries in TOML
    /// (Codex `config.toml`) wait for a TOML editor that keeps comments and layout.
    public static func options(forEntry e: AgentExtension) -> [Option] {
        if e.tegataRole != nil || e.scope == .managed { return [] }
        if [.skill, .subagent, .command].contains(e.kind) { return [.quarantine] }
        guard !e.declaredIn.hasSuffix(".toml") else { return [] }
        return [.hook, .mcpServer].contains(e.kind) ? [.remove] : []
    }

    // MARK: JSON entries

    /// New bytes for the file that declares the entry.
    /// - `current`: the entry as the latest scan saw it (nil when it was removed).
    /// - `baseline`: the entry as the baseline recorded it (nil when it was added).
    /// - `option`: `.revert` writes `baseline` in place of `current`; `.remove` takes `current` out.
    public static func apply(_ option: Option, to data: Data?, current: RawEntry?, baseline: RawEntry?, contentChanged: Bool = false) throws -> Data {
        let any = current ?? baseline
        guard let entry = any else { throw RemedyError.missingCopy("no copy of the entry to work with") }
        guard entry.format == "json" else { throw RemedyError.unsupportedFormat(entry.format) }
        var root: [String: Any]
        if let data, !data.allSatisfy({ $0 == 0x20 || $0 == 0x0A || $0 == 0x0D || $0 == 0x09 }) {
            guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw RemedyError.conflict("the file is not a JSON object any more") }
            root = obj
        } else { root = [:] }

        switch option {
        case .quarantine:
            throw RemedyError.notAllowed("quarantine applies to skills, subagents and commands, not to config entries")
        case .remove:
            guard let current else { throw RemedyError.missingCopy("the entry is not in the file now") }
            try remove(current, from: &root)
        case .revert:
            if contentChanged && current != nil && baseline != nil && current?.json == baseline?.json { throw RemedyError.contentOnly }
            guard let baseline else { throw RemedyError.missingCopy("the baseline has no copy of this entry") }
            if let current { try replace(current, with: baseline, in: &root) } else { try insert(baseline, into: &root) }
        }
        return try ClaudeSettingsEditor.serialize(root)
    }

    static func value(_ json: String) throws -> Any {
        guard let data = "{\"v\":\(json)}".data(using: .utf8), let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any], let v = obj["v"] else {
            throw RemedyError.conflict("unreadable entry copy")
        }
        return v
    }

    static func same(_ a: Any, _ b: String) -> Bool { RawCollector.canonicalJSON(a) == b }

    // Hooks sit inside `hooks.<Event>[i].hooks[j]`, grouped by `matcher`; everything else is a value at its pointer.
    static func isHook(_ e: RawEntry) -> Bool { e.pointer.count == 2 && e.pointer[0] == "hooks" }

    static func remove(_ e: RawEntry, from root: inout [String: Any]) throws {
        if isHook(e) {
            let event = e.pointer[1]
            guard var hooks = root["hooks"] as? [String: Any], var groups = hooks[event] as? [Any] else { throw RemedyError.conflict("no \(event) hooks in the file") }
            var removed = false
            groups = groups.compactMap { g in
                guard !removed, var group = g as? [String: Any], (group["matcher"] as? String) == e.hookMatcher, var list = group["hooks"] as? [Any],
                      let i = list.firstIndex(where: { same($0, e.json) }) else { return g }
                list.remove(at: i); removed = true
                if list.isEmpty { return nil }
                group["hooks"] = list
                return group
            }
            guard removed else { throw RemedyError.conflict("the hook is not in the file as the scan saw it") }
            if groups.isEmpty { hooks.removeValue(forKey: event) } else { hooks[event] = groups }
            if hooks.isEmpty { root.removeValue(forKey: "hooks") } else { root["hooks"] = hooks }
            return
        }
        guard let existing = get(e.pointer, root), same(existing, e.json) else { throw RemedyError.conflict("\(e.pointer.joined(separator: ".")) is not as the scan saw it") }
        set(e.pointer[...], nil, &root)
    }

    static func insert(_ e: RawEntry, into root: inout [String: Any]) throws {
        let v = try value(e.json)
        if isHook(e) {
            let event = e.pointer[1]
            var hooks = (root["hooks"] as? [String: Any]) ?? [:]
            var groups = (hooks[event] as? [Any]) ?? []
            if let i = groups.firstIndex(where: { ($0 as? [String: Any]).map { ($0["matcher"] as? String) == e.hookMatcher } ?? false }),
               var group = groups[i] as? [String: Any] {
                var list = (group["hooks"] as? [Any]) ?? []
                if !list.contains(where: { same($0, e.json) }) { list.append(v) }
                group["hooks"] = list; groups[i] = group
            } else {
                var group: [String: Any] = ["hooks": [v]]
                if let m = e.hookMatcher { group["matcher"] = m }
                groups.append(group)
            }
            hooks[event] = groups; root["hooks"] = hooks
            return
        }
        if get(e.pointer, root) != nil { throw RemedyError.conflict("\(e.pointer.joined(separator: ".")) exists again; rescan before restoring it") }
        set(e.pointer[...], v, &root)
    }

    static func replace(_ current: RawEntry, with baseline: RawEntry, in root: inout [String: Any]) throws {
        if isHook(current) {
            try remove(current, from: &root)
            try insert(baseline, into: &root)
            return
        }
        guard let existing = get(current.pointer, root), same(existing, current.json) else { throw RemedyError.conflict("\(current.pointer.joined(separator: ".")) is not as the scan saw it") }
        set(baseline.pointer[...], try value(baseline.json), &root)
    }

    static func get(_ pointer: [String], _ root: [String: Any]) -> Any? {
        var node: Any = root
        for p in pointer { guard let d = node as? [String: Any], let next = d[p] else { return nil }; node = next }
        return node
    }

    /// Sets (or removes, for nil) the value at `path`, creating objects on the way and dropping ones left empty.
    static func set(_ path: ArraySlice<String>, _ value: Any?, _ node: inout [String: Any]) {
        guard let key = path.first else { return }
        if path.count == 1 { node[key] = value; return }
        var child = (node[key] as? [String: Any]) ?? [:]
        set(path.dropFirst(), value, &child)
        if child.isEmpty && value == nil { node.removeValue(forKey: key) } else { node[key] = child }
    }

    /// Takes several entries out of one file in a single edit: one backup, one write. Each removal is still
    /// compare-and-swap against what the scan saw; if any of them no longer matches, nothing is written.
    @discardableResult
    public static func removeAll(_ entries: [RawEntry], from url: URL) throws -> URL? {
        guard !entries.isEmpty else { return nil }
        for e in entries where e.file != url.path { throw RemedyError.notAllowed("the entry belongs to \(e.file), not \(url.path)") }
        return try ClaudeSettingsFile.edit(url) { data in
            var bytes = data
            for e in entries { bytes = try apply(.remove, to: bytes, current: e, baseline: nil) }
            return bytes ?? Data()
        }
    }

    /// Reads the file, applies one change, backs the file up and writes it (0600, atomic). Returns the backup's URL.
    @discardableResult
    public static func applyToFile(_ option: Option, url: URL, current: RawEntry?, baseline: RawEntry?, contentChanged: Bool = false) throws -> URL? {
        let expected = (current ?? baseline)?.file
        guard expected == url.path else { throw RemedyError.notAllowed("the entry belongs to \(expected ?? "?"), not \(url.path)") }
        return try ClaudeSettingsFile.edit(url) { try apply(option, to: $0, current: current, baseline: baseline, contentChanged: contentChanged) }
    }
}

// MARK: Quarantine

/// Where a skill, subagent or command went, so it can be put back exactly where it was.
public struct QuarantineRecord: Codable, Sendable, Equatable {
    public var extensionId: String
    public var original: String
    public var stored: String
    public var at: Date
}

public enum Quarantine {
    public enum QuarantineError: Error, Equatable, Sendable {
        case notAllowed(String)
        case missing(String)
        case occupied(String)
    }

    /// The file or folder on disk for a skill, subagent or command entry. Only these kinds are moved, and only from
    /// inside the folder that declares them.
    public static func path(of e: AgentExtension, home: String) throws -> String {
        guard [.skill, .subagent, .command].contains(e.kind) else { throw QuarantineError.notAllowed("only skills, subagents and commands can be quarantined") }
        let dir = e.declaredIn.hasPrefix("~") ? home + e.declaredIn.dropFirst() : e.declaredIn
        guard !e.name.contains(".."), !e.name.hasPrefix("/") else { throw QuarantineError.notAllowed("unexpected name \(e.name)") }
        return e.kind == .skill ? dir + "/" + e.name : dir + "/" + e.name + ".md"
    }

    /// Moves the entry into `store/<timestamp>-<name>` and writes a record next to it. A symlinked skill moves as the
    /// link, never what it points to. Refuses anything outside `allowedRoots`.
    public static func move(_ e: AgentExtension, home: String, store: URL, allowedRoots: [String], now: Date = Date()) throws -> QuarantineRecord {
        let original = try path(of: e, home: home)
        let parent = (original as NSString).deletingLastPathComponent
        guard allowedRoots.contains(where: { parent == $0 || parent.hasPrefix($0 + "/") }) else { throw QuarantineError.notAllowed("\(original) is outside the agents' folders") }
        var st = stat()
        guard lstat(original, &st) == 0 else { throw QuarantineError.missing(original) }
        let fm = FileManager.default
        try fm.createDirectory(at: store, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let stamp = Int(now.timeIntervalSince1970)
        let slot = store.appendingPathComponent("\(stamp)-\(e.name.replacingOccurrences(of: "/", with: "_"))", isDirectory: true)
        guard !fm.fileExists(atPath: slot.path) else { throw QuarantineError.occupied(slot.path) }
        try fm.createDirectory(at: slot, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let target = slot.appendingPathComponent((original as NSString).lastPathComponent)
        try fm.moveItem(atPath: original, toPath: target.path)
        let record = QuarantineRecord(extensionId: e.id, original: original, stored: target.path, at: now.wholeSeconds)
        try SealedCoding.makeEncoder().encode(record).write(to: slot.appendingPathComponent("record.json"), options: [.atomic])
        return record
    }

    /// Puts it back. Refuses if something new took its place in the meantime.
    public static func restore(_ r: QuarantineRecord) throws {
        let fm = FileManager.default
        var st = stat()
        guard lstat(r.original, &st) != 0 else { throw QuarantineError.occupied(r.original) }
        guard lstat(r.stored, &st) == 0 else { throw QuarantineError.missing(r.stored) }
        try fm.createDirectory(atPath: (r.original as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try fm.moveItem(atPath: r.stored, toPath: r.original)
        let slot = (r.stored as NSString).deletingLastPathComponent
        try? fm.removeItem(atPath: slot + "/record.json")
        try? fm.removeItem(atPath: slot)
    }

    /// Every record in the store, newest first.
    public static func records(in store: URL) -> [QuarantineRecord] {
        let fm = FileManager.default
        guard let slots = try? fm.contentsOfDirectory(at: store, includingPropertiesForKeys: nil) else { return [] }
        return slots.compactMap { (try? Data(contentsOf: $0.appendingPathComponent("record.json"))).flatMap { try? SealedCoding.makeDecoder().decode(QuarantineRecord.self, from: $0) } }
            .sorted { $0.at > $1.at }
    }
}
