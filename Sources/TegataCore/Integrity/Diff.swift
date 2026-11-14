import Foundation

/// What the baseline remembers about each entry without any content: enough to notice a change, to say what
/// kind of entry it was and who it looked like it came from, and to rank it. It is deliberately readable
/// without a Touch ID prompt, so the background watcher can alert; the entry itself lives in the encrypted
/// snapshot. Every field here is already redacted or a hash.
public struct IntegrityIndex: Codable, Sendable, Equatable {
    public struct Entry: Codable, Sendable, Equatable {
        public var fingerprint: String
        public var severity: RiskSeverity?
        public var declaredIn: String
        public var name: String
        public var owner: String?
        /// `AgentExtension.contentDigest` at baseline time; lets a change be told as "the script it runs changed".
        public var contentDigest: String?
        /// Set when the entry was Tegata's own at baseline time. Tegata refreshes the baseline in the same step as its own
        /// writes, so any later difference in such an entry was made by something else.
        public var tegataRole: TegataRole?
        /// `AgentExtension.entryHash` at baseline time.
        public var entryHash: String?
    }
    public var version: Int
    /// `IntegrityRules.version` the baseline was taken with; nil for baselines from before it was recorded.
    public var rulesVersion: Int?
    public var createdAt: Date
    public var entries: [String: Entry]

    public init(createdAt: Date, entries: [String: Entry], version: Int = 1, rulesVersion: Int? = IntegrityRules.version) {
        self.version = version; self.createdAt = createdAt; self.entries = entries; self.rulesVersion = rulesVersion
    }

    public static func make(inventory: AgentInventory, findings: [RiskFinding], now: Date) -> IntegrityIndex {
        var worst: [String: RiskSeverity] = [:]
        for f in findings { worst[f.extensionId] = max(worst[f.extensionId] ?? .info, f.severity) }
        var entries: [String: Entry] = [:]
        for e in inventory.extensions {
            entries[e.id] = Entry(fingerprint: e.fingerprint, severity: worst[e.id], declaredIn: e.declaredIn, name: e.name, owner: e.owner,
                                  contentDigest: e.contentDigest, tegataRole: e.tegataRole, entryHash: e.entryHash)
        }
        return IntegrityIndex(createdAt: now.wholeSeconds, entries: entries)
    }
}

public struct IntegrityChange: Codable, Sendable, Equatable, Identifiable {
    public enum Kind: String, Codable, Sendable { case added, removed, modified }
    /// `notify`: interrupt the user. `review`: shown as new or changed in the Agent extensions tab, no interruption.
    /// `quiet`: kept in the history only.
    public enum Alert: Int, Codable, Sendable, Comparable {
        case quiet, review, notify
        public static func < (a: Alert, b: Alert) -> Bool { a.rawValue < b.rawValue }
    }

    public var id: String
    public var kind: Kind
    public var extensionId: String
    public var agent: AgentKind
    public var scope: ConfigScope
    public var extensionKind: ExtensionKind
    public var name: String
    public var owner: String?
    public var declaredIn: String
    public var severityBefore: RiskSeverity?
    public var severityAfter: RiskSeverity?
    /// True for a modified entry whose script or files changed (not only the entry that points at them).
    public var contentChanged: Bool
    /// Set when the baseline was taken with older rules and this difference may be the update's, not an edit.
    public var byRulesUpdate: RulesAttribution? = nil
    /// Findings for the entry as it is now; empty for a removed one.
    public var findings: [RiskFinding]
    public var alert: Alert
    /// One plain sentence, naming the entry, who it looks like it came from and where.
    public var summary: String
}

/// A burst of related changes shown as one line ("nodeterm: 14 hooks added in ~/.claude/settings.json"), so
/// installing a tool that adds a hook per event is one notification, not fourteen.
public struct IntegrityChangeGroup: Sendable, Equatable, Identifiable {
    public var id: String
    public var owner: String?
    public var declaredIn: String
    public var kind: IntegrityChange.Kind
    public var changes: [IntegrityChange]
    public var alert: IntegrityChange.Alert
    public var summary: String
}

public struct IntegrityDiff: Sendable, Equatable {
    public var changes: [IntegrityChange]
    /// Files the baseline had entries from that could not be read now. They are reported instead of their
    /// entries being called "removed": breaking a file must not look the same as emptying it, and must not hide
    /// what was in it.
    public var unreadableSources: [String]

    /// The baseline was taken with older rules (`IntegrityRules`); one confirmation brings it up to date.
    public var rulesUpdatePending: Bool = false

    public var notifications: [IntegrityChange] { changes.filter { $0.alert == .notify } }
    public var isEmpty: Bool { changes.isEmpty && unreadableSources.isEmpty }
}

public enum IntegrityDiffer {
    /// Compares the current inventory with a baseline. Same id and same fingerprint is unchanged, even if a newer
    /// Tegata ranks the entry differently: only the user's configuration changing counts as a change.
    public static func diff(baseline: IntegrityIndex, current: AgentInventory, findings: [RiskFinding]) -> IntegrityDiff {
        var worst: [String: RiskSeverity] = [:]
        var byEntry: [String: [RiskFinding]] = [:]
        for f in findings { worst[f.extensionId] = max(worst[f.extensionId] ?? .info, f.severity); byEntry[f.extensionId, default: []].append(f) }
        let now = current.byId
        var changes: [IntegrityChange] = []
        let rulesUpdated = (baseline.rulesVersion ?? IntegrityRules.unversioned) != IntegrityRules.version
        let baselineFiles = Set(baseline.entries.values.map(\.declaredIn))

        for e in current.extensions.sorted(by: { $0.id < $1.id }) {
            let f = (byEntry[e.id] ?? []).sorted { ($1.severity, $0.id) < ($0.severity, $1.id) }
            if let old = baseline.entries[e.id] {
                guard old.fingerprint != e.fingerprint else { continue }
                var c = change(.modified, e, before: old, severityAfter: worst[e.id], findings: f, contentChanged: old.contentDigest != e.contentDigest)
                if rulesUpdated, let h = old.entryHash, h == e.entryHash, !c.contentChanged {
                    // The entry is exactly as recorded and so are the files behind it; only the new rules read it differently.
                    c.byRulesUpdate = .explained; c.alert = .quiet
                    c.summary += " Tegata was updated and reads this entry differently; the entry itself did not change."
                } else if rulesUpdated, old.entryHash == nil || e.entryHash == nil || old.entryHash == e.entryHash {
                    // The entry text is unchanged but its files' digest moved, or nothing recorded can tell: the update may have
                    // changed how files are hashed, or the files changed (a swapped plugin). Shown for review, never silenced.
                    c.byRulesUpdate = .possible; c.alert = min(c.alert, .review)
                    c.summary += " Tegata was updated; this may come from the update rather than an edit."
                } else if let role = old.tegataRole {
                    c.alert = .notify; c.summary = foreignEdit(role, verb: "was changed", declaredIn: e.declaredIn, still: e.tegataRole != nil)
                }
                changes.append(c)
            } else {
                var c = change(.added, e, before: nil, severityAfter: worst[e.id], findings: f)
                if rulesUpdated, !baselineFiles.contains(e.declaredIn) {
                    // A file the baseline never read entries from, seen for the first time after an update that reads
                    // more places: maybe it was always there. Shown for review, never silenced (it may also be new).
                    c.byRulesUpdate = .possible; c.alert = min(c.alert, .review)
                    c.summary += " Tegata was updated and now reads \(e.declaredIn); it may have been there before."
                }
                changes.append(c)
            }
        }

        let unreadable = unreadableSources(baseline: baseline, current: current)
        for (id, old) in baseline.entries.sorted(by: { $0.key < $1.key }) where now[id] == nil {
            if current.incomplete.contains(where: { suppresses($0, old) }) { continue }
            var c = removed(id, old)
            if let role = old.tegataRole { c.alert = .notify; c.summary = foreignEdit(role, verb: "was removed", declaredIn: old.declaredIn, still: false) }
            changes.append(c)
        }
        changes.sort { ($1.alert, $0.id) < ($0.alert, $1.id) }
        return IntegrityDiff(changes: changes, unreadableSources: unreadable, rulesUpdatePending: rulesUpdated)
    }

    /// "Tegata's guard hook was removed from ~/.claude/settings.json by something other than Tegata."
    static func foreignEdit(_ role: TegataRole, verb: String, declaredIn: String, still: Bool) -> String {
        let what = role == .guardHook ? "Tegata's guard hook" : "Tegata's credential helper (apiKeyHelper)"
        let consequence: String
        switch (role, verb) {
        case (.guardHook, "was removed"): consequence = " The agent can read credential files again until it is repaired."
        case (.credentialHelper, "was removed"): consequence = " Claude Code no longer asks Tegata for its credential."
        case (.credentialHelper, _) where !still: consequence = " Claude Code now asks another program for its credential."
        default: consequence = ""
        }
        return "\(what) \(verb) in \(declaredIn) by something other than Tegata.\(consequence)"
    }

    // MARK: grouping

    public static func grouped(_ changes: [IntegrityChange]) -> [IntegrityChangeGroup] {
        var order: [String] = []
        var buckets: [String: [IntegrityChange]] = [:]
        for c in changes {
            let key = "\(c.kind.rawValue)|\(c.owner ?? "")|\(c.declaredIn)"
            if buckets[key] == nil { order.append(key) }
            buckets[key, default: []].append(c)
        }
        return order.map { key in
            let cs = buckets[key]!
            let first = cs[0]
            let alert = cs.map(\.alert).max() ?? .quiet
            let summary: String
            if cs.count == 1 { summary = first.summary }
            else {
                let who = first.owner.map { "“\($0)”: " } ?? ""
                let kinds = Set(cs.map(\.extensionKind))
                let noun = kinds.count == 1 ? plural(kinds.first!, cs.count) : "\(cs.count) entries"
                let verb = first.kind == .added ? "added to" : first.kind == .removed ? "removed from" : "changed in"
                summary = "\(who)\(noun) \(verb) \(first.declaredIn)."
            }
            return IntegrityChangeGroup(id: key, owner: first.owner, declaredIn: first.declaredIn, kind: first.kind, changes: cs, alert: alert, summary: summary)
        }.sorted { ($1.alert, $0.id) < ($0.alert, $1.id) }
    }

    // MARK: rules

    static func change(_ kind: IntegrityChange.Kind, _ e: AgentExtension, before: IntegrityIndex.Entry?, severityAfter: RiskSeverity?, findings: [RiskFinding], contentChanged: Bool = false) -> IntegrityChange {
        let alert = alertLevel(kind, e, severityAfter, contentChanged: contentChanged)
        var summary = sentence(kind: kind, e.kind, name: e.name, owner: e.owner, scope: e.scope, declaredIn: e.declaredIn, contentChanged: contentChanged)
        if let top = findings.first, top.severity >= .medium { summary += " \(top.title)." }
        return IntegrityChange(id: "\(kind.rawValue)|\(e.id)|\(e.fingerprint.prefix(12))", kind: kind, extensionId: e.id, agent: e.agent, scope: e.scope,
                               extensionKind: e.kind, name: e.name, owner: e.owner, declaredIn: e.declaredIn,
                               severityBefore: before?.severity, severityAfter: severityAfter, contentChanged: contentChanged, findings: findings, alert: alert, summary: summary)
    }

    static func removed(_ id: String, _ old: IntegrityIndex.Entry) -> IntegrityChange {
        let parts = id.split(separator: "|", maxSplits: 3, omittingEmptySubsequences: false).map(String.init)
        let agent = parts.count > 0 ? AgentKind(rawValue: parts[0]) ?? .claudeCode : .claudeCode
        let scope = parts.count > 1 ? ConfigScope(rawValue: parts[1]) ?? .user : .user
        let kind = parts.count > 2 ? ExtensionKind(rawValue: parts[2]) ?? .hook : .hook
        let alert: IntegrityChange.Alert = (old.severity ?? .info) >= .medium ? .review : .quiet
        return IntegrityChange(id: "removed|\(id)|\(old.fingerprint.prefix(12))", kind: .removed, extensionId: id, agent: agent, scope: scope,
                               extensionKind: kind, name: old.name, owner: old.owner, declaredIn: old.declaredIn,
                               severityBefore: old.severity, severityAfter: nil, contentChanged: false, findings: [], alert: alert,
                               summary: sentence(kind: .removed, kind, name: old.name, owner: old.owner, scope: scope, declaredIn: old.declaredIn))
    }

    static func alertLevel(_ kind: IntegrityChange.Kind, _ e: AgentExtension, _ severity: RiskSeverity?, contentChanged: Bool = false) -> IntegrityChange.Alert {
        if (severity ?? .info) >= .medium { return .notify }
        // The script behind a hook, a local MCP server or a plugin was rewritten: that is code that runs on its own, so
        // it interrupts however low the entry ranks. Skills, agents and commands are text the model reads and are
        // edited and updated all the time; their content changes are for review.
        if contentChanged, [.hook, .mcpServer, .plugin, .credentialHelper].contains(e.kind) { return .notify }
        switch e.kind {
        // What an agent can run or install: a new or edited one is worth an interruption even when it ranks low.
        // A new or changed credential helper decides who gets the agent's key.
        case .mcpServer, .marketplace, .credentialHelper: return e.tegataRole != nil ? .review : .notify
        case .plugin: if case .plugin(_, true) = e.detail { return .notify }; return .review
        default: return .review
        }
    }

    // MARK: unreadable sources

    /// Files the baseline had entries from that the scan could not read as a whole.
    static func unreadableSources(baseline: IntegrityIndex, current: AgentInventory) -> [String] {
        let declared = Set(baseline.entries.values.map(\.declaredIn))
        return declared.filter { d in current.incomplete.contains { $0.hasPrefix(d + ":") } }.sorted()
    }

    /// An `incomplete` note is `"<shown path>: reason"` for a file, or `"<shown dir>/<name>: reason"` for one entry
    /// of a folder (a skill whose link is broken). A note hides "removed" for what it covers and nothing wider, so a
    /// single bad skill link does not silence removals across the whole folder.
    static func suppresses(_ note: String, _ old: IntegrityIndex.Entry) -> Bool {
        note.hasPrefix(old.declaredIn + ":") || note.hasPrefix(old.declaredIn + "/" + old.name + ":")
    }

    // MARK: wording

    static func sentence(kind: IntegrityChange.Kind, _ ext: ExtensionKind, name: String, owner: String?, scope: ConfigScope, declaredIn: String, contentChanged: Bool = false) -> String {
        let subject: String
        switch ext {
        case .hook: subject = "\(name) hook"
        case .mcpServer: subject = "MCP server “\(name)”"
        case .plugin: subject = "plugin “\(name)”"
        case .marketplace: subject = "plugin marketplace “\(name)”"
        case .skill: subject = "skill “\(name)”"
        case .subagent: subject = "subagent “\(name)”"
        case .command: subject = "command “\(name)”"
        case .permissions: subject = name
        case .env: subject = "environment variables"
        case .credentialHelper: subject = "credential helper “\(name)”"
        }
        let from = owner.map { " from “\($0)”" } ?? ""
        let place = scope == .project ? "\(declaredIn) (a project folder)" : declaredIn
        if kind == .modified, contentChanged {
            // Told apart from an edited entry: here the entry may be exactly as it was and the file behind it is not.
            let what: String
            switch ext {
            case .hook, .mcpServer, .credentialHelper: what = "The script behind"
            default: what = "The files of"
            }
            let s = "\(what) \(subject)\(from) changed (declared in \(place))."
            return s
        }
        let verb = kind == .added ? "was added to" : kind == .removed ? "was removed from" : "changed in"
        let s = "\(subject)\(from) \(verb) \(place)."
        return s.prefix(1).uppercased() + s.dropFirst()
    }

    static func plural(_ k: ExtensionKind, _ n: Int) -> String {
        let word: String
        switch k {
        case .hook: word = "hook"
        case .mcpServer: word = "MCP server"
        case .plugin: word = "plugin"
        case .marketplace: word = "marketplace"
        case .skill: word = "skill"
        case .subagent: word = "subagent"
        case .command: word = "command"
        case .permissions: word = "permission setting"
        case .env: word = "environment setting"
        case .credentialHelper: word = "credential helper"
        }
        return "\(n) \(word)\(n == 1 ? "" : "s")"
    }
}
