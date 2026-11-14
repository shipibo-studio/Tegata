import Foundation
import TegataCore

/// What `tegata scan` found, once, so the terminal, the Markdown file and the JSON file always say the same thing.
/// Every string in it is already safe to show: names and paths with control characters replaced and the home folder
/// (and its encoded form in transcript folders) shown as `~`. No secret value, no preview of one.
public struct ScanReport: Codable, Sendable {
    public struct Short: Codable, Sendable { public var level: String; public var text: String }
    public struct KindRow: Codable, Sendable { public var kind: String; public var count: Int; public var highestRisk: String? }
    public struct Notable: Codable, Sendable {
        public var level: String; public var name: String; public var agent: String; public var kind: String
        public var installedBy: String; public var why: String; public var whatToDo: String; public var declaredIn: String
    }
    public struct OwnerFix: Codable, Sendable { public var owner: String; public var count: Int; public var command: String }
    public struct Pin: Codable, Sendable { public var name: String; public var declaredIn: String }
    public struct SecretArea: Codable, Sendable { public var area: String; public var copies: Int; public var files: Int }
    public struct Place: Codable, Sendable { public var place: String; public var path: String; public var copies: Int }
    public struct Step: Codable, Sendable {
        public var urgency: String; public var title: String; public var what: String; public var copies: Int; public var places: Int
        public var where_: [Place]; public var names: [String]; public var steps: [String]; public var rotateAt: String?
        enum CodingKeys: String, CodingKey { case urgency, title, what, copies, places, where_ = "where", names, steps, rotateAt }
    }

    public var tool = "tegata"
    public var version: String
    public var generatedAt: Date
    public var agents: [String]
    public var extensions: Int
    public var findingsByLevel: [String: Int]
    public var short: [Short]
    public var kinds: [KindRow]
    public var notable: [Notable]
    public var notableTotal: Int
    public var ownerFixes: [OwnerFix]
    public var pins: [Pin]
    public var secretCopies: Int?
    public var filesRead: Int?
    public var secondsReading: Double?
    public var secretAreas: [SecretArea]
    public var plan: [Step]
    public var notRead: [String]

    static let levelWord: [RiskSeverity: String] = [.critical: "critical", .high: "high", .medium: "medium", .low: "low", .info: "info"]

    public init(inventory inv: AgentInventory, findings: [RiskFinding], exposure: ExposureReport?, home: String, version: String,
                now: Date = Date(), top: Int = 12) {
        let safe = Render.safe
        let worst = Render.worst(findings)
        let plan = exposure.map { SecretTriage.plan($0.findings) } ?? []
        self.version = version
        generatedAt = now
        let present = Set(inv.extensions.map(\.agent))
        agents = AgentKind.allCases.filter(present.contains).map { Render.agentLabels[$0] ?? $0.rawValue }
        extensions = inv.extensions.count
        findingsByLevel = Dictionary(grouping: findings, by: { Self.levelWord[$0.severity]! }).mapValues(\.count)

        // In short.
        let rotateNow = plan.filter { $0.urgency == .now }.reduce(0) { $0 + $1.distinct }
        let rotateSoon = plan.filter { $0.urgency == .soon }.reduce(0) { $0 + $1.distinct }
        let byLevel = Dictionary(grouping: inv.extensions.compactMap { worst[$0.id] }, by: { $0 }).mapValues(\.count)
        var short: [Short] = []
        if let n = byLevel[.critical] { short.append(.init(level: "critical", text: "\(Render.plural(n, "extension")) to act on now")) }
        if rotateNow > 0 { short.append(.init(level: "critical", text: "\(Render.plural(rotateNow, "key")) to rotate now")) }
        if let n = byLevel[.high] { short.append(.init(level: "high", text: "\(Render.plural(n, "extension")) to review today")) }
        if rotateSoon > 0 { short.append(.init(level: "high", text: "\(Render.plural(rotateSoon, "password or token", "passwords or tokens")) to change soon")) }
        if let n = byLevel[.medium] { short.append(.init(level: "medium", text: "\(Render.plural(n, "extension")) to review")) }
        if byLevel[.critical] == nil { short.append(.init(level: "ok", text: "nothing critical in your agents' extensions")) }
        self.short = short

        let byKind = Dictionary(grouping: inv.extensions, by: \.kind)
        kinds = Render.kindLabels.compactMap { (k, label) -> KindRow? in
            guard let list = byKind[k] else { return nil }
            return KindRow(kind: label + "s", count: list.count, highestRisk: list.compactMap { worst[$0.id] }.max().map { Self.levelWord[$0]! })
        }

        // Worth a look, with what to do.
        let notableEntries = inv.extensions.filter { (worst[$0.id] ?? .info) >= .medium }
            .sorted { a, b in
                let (sa, sb) = (worst[a.id]!, worst[b.id]!)
                return sa != sb ? sa > sb : a.id < b.id
            }
        notableTotal = notableEntries.count
        var removable: [String: Int] = [:]
        var pins: [Pin] = []
        notable = notableEntries.prefix(top).map { e in
            let f = findings.filter { $0.extensionId == e.id }.max(by: { $0.severity < $1.severity })
            let advice = f.map { RiskAdvice.advice(for: $0.rule) }
            if let a = advice, [.removeNow, .removeIfUnused].contains(a.action), let o = e.owner, IntegrityRemedy.options(forEntry: e).contains(.remove) {
                removable[o, default: 0] += 1
            }
            if advice?.action == .pinVersion { pins.append(Pin(name: safe(e.name), declaredIn: safe(e.declaredIn))) }
            return Notable(level: Self.levelWord[worst[e.id]!]!, name: safe(e.name), agent: Render.agentLabels[e.agent] ?? e.agent.rawValue,
                           kind: e.kind.rawValue, installedBy: safe(e.owner ?? "unknown"), why: safe(f?.title ?? ""),
                           whatToDo: advice?.short ?? "", declaredIn: safe(e.declaredIn))
        }
        ownerFixes = removable.sorted { $0.key < $1.key }.map { OwnerFix(owner: safe($0.key), count: $0.value, command: "tegata fix remove --owner \(safe($0.key))") }
        self.pins = Array(pins.prefix(3))
        notRead = inv.incomplete.prefix(5).map(safe)

        // Secrets.
        secretCopies = exposure?.findings.count
        filesRead = exposure?.filesScanned
        secondsReading = exposure.map { ($0.duration * 10).rounded() / 10 }
        secretAreas = exposure.map { r in
            ExposureSource.Kind.allCases.compactMap { kind in
                let f = r.findings(in: kind)
                return f.isEmpty ? nil : SecretArea(area: Render.sourceLabels[kind] ?? kind.rawValue, copies: f.count, files: Set(f.map(\.file)).count)
            }
        } ?? []
        if let r = exposure { notRead += r.incomplete.prefix(5).map { safe(Render.shown($0, home: home)) } }
        self.plan = plan.map { a in
            let what: String
            switch a.rules {
            case ["private-key-block"]: what = Render.plural(a.distinct, "key")
            case ["secret-assignment"], ["env-schema-sensitive"]: what = Render.plural(a.distinct, "value")
            case ["connection-url-with-password"]: what = Render.plural(a.distinct, "password")
            case ["jwt"]: what = Render.plural(a.distinct, "token")
            default: what = Render.plural(a.distinct, "key")
            }
            let inUse = a.places.contains { $0.file.contains(".claude.json") && !$0.file.contains("backup") }
            let clean = inUse ? "tegata clean removes the copies in chats and history; the one in Claude Code's settings is in use by an MCP server: replace it there"
                              : "Then remove the copies: tegata clean"
            var steps: [String]
            switch a.urgency {
            case .none: steps = ["Nothing to rotate; remove the copies when convenient: tegata clean"]
            case .check: steps = [a.how, clean]
            default: steps = a.rules == ["private-key-block"] ? [a.how] : [a.how, clean]
            }
            let urgency: String
            switch a.urgency { case .now: urgency = "now"; case .soon: urgency = "soon"; case .check: urgency = "check"; case .none: urgency = "done" }
            return Step(urgency: urgency, title: a.title, what: what, copies: a.copies, places: a.places.count,
                        where_: a.places.prefix(3).map { Place(place: Render.place($0.file, home: home), path: safe(Render.shown($0.file, home: home)), copies: $0.copies) },
                        names: a.names.prefix(6).map(safe), steps: steps, rotateAt: a.rotateAt)
        }
    }

    // MARK: Markdown

    public func markdown() -> String {
        func cell(_ s: String) -> String { s.replacingOccurrences(of: "|", with: "\\|") }
        let mark: [String: String] = ["critical": "●", "high": "▲", "medium": "◆", "low": "·", "info": "", "ok": "✓"]
        var md: [String] = []
        md.append("# Tegata scan")
        md.append("")
        md.append("*\(generatedAt.formatted(date: .long, time: .shortened)) · tegata \(version) · a read-only look at this Mac's AI coding agents. "
                  + "This report names files and counts; it never contains a secret value.*")
        md.append("")
        md.append("## In short")
        md.append("")
        for s in short { md.append("- \(mark[s.level] ?? "") \(s.text)") }
        md.append("")
        md.append("## What your agents load: \(Render.plural(extensions, "extension"))" + (agents.isEmpty ? "" : " in " + agents.joined(separator: ", ")))
        md.append("")
        md.append("Things your AI agents load and run on their own: hooks run on every action, MCP servers give them tools, skills and subagents add instructions. Each one acts with your permissions.")
        md.append("")
        md.append("| Kind | How many | Highest risk |")
        md.append("|---|---:|---|")
        for k in kinds { md.append("| \(k.kind) | \(k.count) | \(k.highestRisk.map { "\(mark[$0] ?? "") \($0)" } ?? "–") |") }
        md.append("")
        md.append("Risk levels: ● critical, act now · ▲ high, review today · ◆ medium, review · · low, good to know · info, nothing to do.")
        md.append("")
        md.append("## Worth a look")
        md.append("")
        if notable.isEmpty {
            md.append("✓ Nothing rated medium or above.")
        } else {
            md.append("The extensions that can do the most. Not necessarily bad: keep what you installed and use, remove what you do not.")
            md.append("")
            md.append("| Level | Name | Installed by | Why | What to do | Declared in |")
            md.append("|---|---|---|---|---|---|")
            for n in notable {
                md.append("| \(mark[n.level] ?? "") \(n.level) | \(cell(n.name)) | \(cell(n.installedBy)) | \(cell(n.why)) | **\(cell(n.whatToDo))** | `\(cell(n.declaredIn))` |")
            }
            if notableTotal > notable.count { md.append("\n…and \(notableTotal - notable.count) more: `tegata inventory --why`.") }
            md.append("")
            for f in ownerFixes { md.append("- Not using \(f.owner)? Remove what it installed (\(f.count)): `\(f.command)`") }
            for p in pins { md.append("- \(p.name): in `\(p.declaredIn)`, replace the package name by name@version (for example some-mcp@1.4.2).") }
        }
        if let copies = secretCopies {
            md.append("")
            md.append("## Secrets your agents copied: \(Render.plural(copies, "copy", "copies"))")
            md.append("")
            md.append("Passwords, API keys and tokens that ended up in your agents' chats, their settings and your shell history. Any program that reads those files can use them.")
            if let f = filesRead, let s = secondsReading { md.append("*\(Render.plural(f, "file")) read in \(s) s.*") }
            md.append("")
            if secretAreas.isEmpty {
                md.append("✓ None found.")
            } else {
                md.append("| Where | Copies | Files |")
                md.append("|---|---:|---:|")
                for a in secretAreas { md.append("| \(a.area) | \(a.copies) | \(a.files) |") }
            }
            if !plan.isEmpty {
                md.append("")
                md.append("## What to do, in order")
                md.append("")
                md.append("Rotating a key makes every copy of it worthless, so rotate first; clean the copies after.")
                let label = ["now": "● Now", "soon": "▲ Soon", "check": "◆ Check", "done": "✓ Done"]
                for s in plan {
                    md.append("")
                    md.append("### \(label[s.urgency] ?? s.urgency): \(s.title)")
                    md.append("")
                    md.append("\(s.what), \(Render.plural(s.copies, "copy", "copies")) in \(Render.plural(s.places, "place")).")
                    md.append("")
                    md.append("**Where**")
                    md.append("")
                    for p in s.where_ { md.append("- \(p.place)\(p.copies > 1 ? " ×\(p.copies)" : "") — `\(p.path)`") }
                    if s.places > s.where_.count { md.append("- and \(s.places - s.where_.count) more (`tegata scan --details`)") }
                    if !s.names.isEmpty { md.append("\n**Names:** " + s.names.map { "`\(cell($0))`" }.joined(separator: ", ")) }
                    md.append("")
                    md.append("**Do**")
                    md.append("")
                    for (i, step) in s.steps.enumerated() {
                        md.append("\(i + 1). " + step.replacingOccurrences(of: "tegata clean", with: "`tegata clean`") + (i == 0 ? s.rotateAt.map { " <\($0)>" } ?? "" : ""))
                    }
                }
            }
        }
        if !notRead.isEmpty {
            md.append("")
            md.append("## Not read")
            md.append("")
            for n in notRead { md.append("- `\(cell(n))`") }
        }
        md.append("")
        md.append("## Next")
        md.append("")
        md.append("- `tegata inventory --why`: why each finding matters")
        md.append("- `tegata clean`: after rotating keys, remove their copies")
        md.append("- `tegata watch install`: be told when something changes")
        md.append("")
        md.append("---")
        md.append("Generated by [Tegata](https://www.tegata.cc), a checkpoint for your AI coding agents.")
        return md.joined(separator: "\n") + "\n"
    }

    public func json() throws -> Data {
        let enc = SealedCoding.makeEncoder()
        enc.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
        return try enc.encode(self)
    }

    // MARK: writing

    /// Writes the report next to the user, never over an existing file, readable by the user only (it says where
    /// secrets are, even if it never says what they are). Returns the path written.
    public func write(to requested: String?, cwd: URL, now: Date = Date()) throws -> URL {
        // The user's own date, not UTC: a report made at 22:00 on the 12th is the 12th's.
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "yyyy-MM-dd"
        let day = f.string(from: now)
        var url = requested.map { URL(fileURLWithPath: ($0 as NSString).expandingTildeInPath, relativeTo: cwd) }
            ?? cwd.appendingPathComponent("tegata-scan-\(day).md")
        if requested == nil {
            var n = 2
            while FileManager.default.fileExists(atPath: url.path) {
                url = cwd.appendingPathComponent("tegata-scan-\(day)-\(n).md"); n += 1
            }
        } else if FileManager.default.fileExists(atPath: url.path) {
            throw CocoaError(.fileWriteFileExists, userInfo: [NSLocalizedDescriptionKey: "\(url.path) exists; choose another name"])
        }
        let data = url.pathExtension.lowercased() == "json" ? try json() : Data(markdown().utf8)
        // O_EXCL: fails if the file appeared since the check, so nothing is ever overwritten.
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteFileExists, userInfo: [NSLocalizedDescriptionKey: "could not create \(url.path): \(String(cString: strerror(errno)))"]) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try handle.write(contentsOf: data)
        try handle.close()
        return url.standardizedFileURL
    }
}
