import Foundation
import TegataCore

/// Plain-text rendering for the command line. Pure functions over already-redacted data, so the output is safe to
/// paste into an issue: names, owners, paths, counts and rule titles; never a secret value or a preview of one.
public enum Render {
    static let kindLabels: [(ExtensionKind, String)] = [
        (.hook, "hook"), (.mcpServer, "MCP server"), (.plugin, "plugin"), (.marketplace, "marketplace"),
        (.credentialHelper, "credential helper"), (.permissions, "permission set"), (.env, "env block"),
        (.subagent, "subagent"), (.command, "command"), (.skill, "skill"),
    ]
    static let agentLabels: [AgentKind: String] = [
        .claudeCode: "Claude Code", .codex: "Codex", .cursor: "Cursor", .claudeDesktop: "Claude Desktop", .gemini: "Gemini",
    ]
    static let sourceLabels: [ExposureSource.Kind: String] = [
        .agentTranscript: "agent transcripts and history", .agentConfig: "agent config files",
        .shell: "shell startup files and history", .projectEnv: "project .env files",
    ]

    /// Worst finding per entry.
    public static func worst(_ findings: [RiskFinding]) -> [String: RiskSeverity] {
        Dictionary(grouping: findings, by: \.extensionId).mapValues { $0.map(\.severity).max() ?? .info }
    }

    public static func counts(_ findings: [RiskFinding]) -> String {
        let by = Dictionary(grouping: findings, by: \.severity).mapValues(\.count)
        let parts = RiskSeverity.allCases.reversed().compactMap { s in by[s].map { "\($0) \(s)" } }
        return parts.isEmpty ? "none" : parts.joined(separator: ", ")
    }

    /// Paths under the home folder as `~/…`, so a pasted report does not carry the user name.
    /// Also under the home's resolved path: scanners report resolved paths (`/var` is `/private/var` on macOS).
    /// Claude Code names a project's transcript folder after the project's path with `/` as `-`
    /// (`-Users-name-Sites-app`), so the user name is in it too; that part is shown as `~` as well.
    public static func shown(_ path: String, home: String) -> String {
        // realpath, not URL.resolvingSymlinksInPath (which drops `/private` again).
        let resolved = realpath(home, nil).map { p in defer { free(p) }; return String(cString: p) } ?? home
        var out = path
        for h in Set([home, resolved]) where !h.isEmpty {
            if out == h { out = "~"; break }
            if out.hasPrefix(h + "/") { out = "~" + out.dropFirst(h.count); break }
        }
        for h in Set([home, resolved]) where !h.isEmpty {
            out = out.replacingOccurrences(of: h.replacingOccurrences(of: "/", with: "-"), with: "~")
        }
        return out
    }

    /// Text that came from the user's files (names, owners, paths, variable names) is shown with its control
    /// characters replaced: a skill folder named with escape codes must not be able to hide lines or repaint the
    /// report in someone's terminal. C0 controls, DEL and C1 controls become `?`; tabs become a space.
    public static func safe(_ s: String) -> String {
        String(String.UnicodeScalarView(s.unicodeScalars.map { u -> Unicode.Scalar in
            if u == "\t" { return " " }
            return (u.value < 0x20 || (0x7F...0x9F).contains(u.value)) ? "?" : u
        }))
    }

    static func plural(_ n: Int, _ one: String, _ many: String? = nil) -> String { "\(n) \(n == 1 ? one : (many ?? one + "s"))" }

    static func pad(_ s: String, _ n: Int) -> String { s.count >= n ? s + " " : s.padding(toLength: n, withPad: " ", startingAt: 0) }

    static func line(_ e: AgentExtension, severity: RiskSeverity?, _ st: Style = .plain) -> String {
        let agent = agentLabels[e.agent] ?? e.agent.rawValue
        return "\(st.severity(severity))\(agent) \(e.kind.rawValue) \(st.bold("\"\(safe(e.name))\""))  \(st.dim("owner:")) \(safe(e.owner ?? "unknown"))  \(st.dim("in \(safe(e.declaredIn))"))"
    }

    // MARK: help

    public static let tagline = "a checkpoint for your AI coding agents"

    public static func help(_ st: Style, version: String) -> [String] {
        func cmd(_ c: String, _ what: String, _ flags: String = "") -> String {
            "    \(st.bold(pad(c, 30)))\(what)\(flags.isEmpty ? "" : "  " + st.dim(flags))"
        }
        return Banner.lines(st, version: version, tagline: tagline) + [
            "",
            "  Your agents run hooks, MCP servers and plugins nobody reviewed, and copy your secrets into their",
            "  transcripts. Tegata shows what they can run, what they have seen, and tells you when it changes.",
            "  " + st.dim("Read-only unless you ask. Touch ID for every change to its record. Nothing about you leaves your Mac;"),
            "  " + st.dim("only tegata status and tegata update ask GitHub whether a newer version exists (--offline skips it)."),
            "",
            "  " + st.shu("Start here"),
            cmd("tegata scan", "a first look: what your agents run, which secrets they copied", "--details --export"),
            "",
            "  " + st.heading("See"),
            cmd("tegata inventory", "every extension, worst first", "--why --ids --all --json"),
            "",
            "  " + st.heading("Fix"),
            cmd("tegata fix remove <id>…", "take out a hook or MCP server, backup kept", "--owner <name>"),
            cmd("tegata fix quarantine <id>…", "move a skill, subagent or command aside"),
            cmd("tegata clean", "remove copies of secrets from chats and history", "--list --dry-run"),
            "",
            "  " + st.heading("Watch"),
            cmd("tegata status", "version, updates, your record and what changed"),
            cmd("tegata watch install", "be told when your agents' configuration changes"),
            cmd("tegata watch establish", "trust what is there now (Touch ID)"),
            cmd("tegata watch status", "the record, and what changed since"),
            cmd("tegata watch accept <id>…", "keep a change (or revert, remove: undo it)"),
            cmd("tegata watch uninstall", "stop watching (forget also drops the record)"),
            "",
            "  " + st.heading("Keep up to date"),
            cmd("tegata update", "check for a newer tegata and offer to update"),
            "",
            "  " + st.dim("--fail-on <severity> exits with status 2 for CI · --no-color for plain output · tegata version"),
            "  " + st.dim("https://www.tegata.cc"),
        ]
    }

    /// `tegata inventory`: every entry, worst first. Skills are many and usually low risk, so they are folded unless
    /// `all`, except the ones with a finding of medium or above.
    public static func inventory(_ inv: AgentInventory, findings: [RiskFinding], why: Bool, all: Bool, ids: Bool = false, style st: Style = .plain) -> [String] {
        let worst = worst(findings)
        let sorted = inv.extensions.sorted { a, b in
            let (sa, sb) = (worst[a.id] ?? .info, worst[b.id] ?? .info)
            return sa != sb ? sa > sb : a.id < b.id
        }
        var out: [String] = st.header("inventory", "every extension your agents load, worst first")
        var hidden = 0
        if !why && !ids {
            var rows: [[String]] = []
            for e in sorted {
                if e.kind == .skill, !all, (worst[e.id] ?? .info) < .medium { hidden += 1; continue }
                rows.append([worst[e.id]?.label ?? "  –", agentLabels[e.agent] ?? e.agent.rawValue, e.kind.rawValue, safe(e.name),
                             safe(e.owner ?? "unknown"), safe(e.declaredIn)])
            }
            out += Table(columns: [.init(title: "Level", color: st.severityCell), .init(title: "Agent"), .init(title: "Kind"),
                                   .init(title: "Name", flexible: true, minWidth: 10), .init(title: "Owner", flexible: true, minWidth: 8),
                                   .init(title: "Declared in", flexible: true, minWidth: 12, color: st.dim)], rows: rows).render(st)
            if hidden > 0 { out.append(st.dim("  (\(hidden) skills without notable findings hidden; --all lists them)")) }
            for n in inv.incomplete { out.append(st.dim("  not read: \(safe(n))")) }
            out.append(st.dim("  why each one: tegata inventory --why · ids to fix: tegata inventory --ids"))
            return out
        }
        for e in sorted {
            if e.kind == .skill, !all, (worst[e.id] ?? .info) < .medium { hidden += 1; continue }
            out.append(line(e, severity: worst[e.id], st))
            if why { for f in findings where f.extensionId == e.id { out.append("          \(st.dim("·")) \(safe(f.title)): \(st.dim(safe(f.why)))") } }
            if ids {
                let can = IntegrityRemedy.options(forEntry: e).map(\.rawValue)
                out.append("          \(st.dim("id")) '\(safe(e.id))'" + (can.isEmpty ? "" : st.dim("  (tegata fix \(can.joined(separator: "|")) <id>)")))
            }
        }
        if hidden > 0 { out.append(st.dim("(\(hidden) skills without notable findings hidden; --all lists them)")) }
        for n in inv.incomplete { out.append(st.dim("not read: \(safe(n))")) }
        return out
    }

    // MARK: where, in words

    /// A file holding a copy, said the way a person would look for it: "Claude Code chat in Sites-app (3 Nov)".
    public static func place(_ file: String, home: String) -> String {
        let shownPath = safe(shown(file, home: home))
        let date: String = {
            guard let d = (try? FileManager.default.attributesOfItem(atPath: file))?[.modificationDate] as? Date else { return "" }
            return " (" + d.formatted(.dateTime.day().month(.abbreviated)) + ")"
        }()
        if let r = shownPath.range(of: "/projects/") {
            let rest = shownPath[r.upperBound...]
            var project = String(rest.split(separator: "/").first ?? "")
            if project.hasPrefix("~-") { project.removeFirst(2) }
            let app = shownPath.contains("com.monocode.desktop") ? " (MonoCode)" : ""
            return "Claude Code chat\(app) in \(project)\(date)"
        }
        if shownPath.hasSuffix("/.claude/history.jsonl") || shownPath == "~/.claude/history.jsonl" { return "Claude Code prompt history" }
        if shownPath.contains(".claude.json") { return shownPath.contains("backup") ? "a backup of Claude Code's settings (\(shownPath))" : "Claude Code's settings (\(shownPath))" }
        return shownPath
    }

    // MARK: clean

    /// The kind of place a copy is in, for grouping: "Claude Code chats", "~/.zsh_history"…
    public static func area(_ file: String, home: String) -> String {
        let p = safe(shown(file, home: home))
        if p.contains("/projects/") { return p.contains("com.monocode.desktop") ? "Claude Code chats (MonoCode)" : "Claude Code chats" }
        if p.hasSuffix("history.jsonl") { return "Claude Code prompt history" }
        if p.contains(".claude.json") {
            if p.contains("backup") { return "Backups of Claude Code's settings" }
            return p.contains("com.monocode.desktop") ? "Claude Code's settings (MonoCode account)" : "Claude Code's settings (\(p))"
        }
        return p
    }

    /// Why a copy that is not cleaned stays, and what to do instead.
    static func leftAloneReason(_ area: String) -> String {
        if area.hasPrefix("Claude Code's settings") { return "MCP servers sign in with it. Rotate the key, then replace it in that file." }
        if area.hasPrefix("Backups of Claude Code's settings") { return "Claude Code's own copies of its settings. Rotating the key makes them useless." }
        if area.hasSuffix("rc") || area.hasSuffix("profile") || area.hasSuffix("zshenv") { return "Your shell sets it in every session. Rotate the key and update that line." }
        return "In use where it is. Rotate the key and update it there."
    }

    /// `tegata clean`, before asking: what these copies are, where they are, what stays and why, how it works.
    public static func cleanPlan(_ findings: [SecretFinding], home: String, list: Bool, style st: Style = .plain) -> [String] {
        var out: [String] = []
        out.append(st.section("What this is"))
        out.append("  " + st.dim("Your agents' chats and your shell history keep a copy of everything that went through them, including secrets"))
        out.append("  " + st.dim("you pasted or that a command printed. Nothing reads those copies to work, so removing the value breaks nothing."))
        out.append("  " + st.dim("Rotating a key is what protects you; cleaning removes the leftovers so nothing else can pick them up."))
        out.append("")
        out.append(st.section("You keep your chats"))
        out.append("  " + st.ok("No chat is deleted. Only the secret value in a line is replaced; your questions, answers and code stay,"))
        out.append("    and " + st.bold("claude --resume") + " loads them as before.")
        out.append("  " + st.ok("A chat open right now keeps its context, and its next message goes into the cleaned file."))
        out.append("  " + st.dim("What changes: a resumed chat no longer contains the secret. If the agent needs the key, give it the new one."))
        out.append("")

        let cleanable = findings.filter(SecretRedactor.cleanable)
        let files = Dictionary(grouping: cleanable, by: \.file)
        out.append(st.section("Can be cleaned: \(plural(cleanable.count, "copy", "copies")) in \(plural(files.count, "file"))"))
        if cleanable.isEmpty {
            out.append("  " + st.ok("nothing to clean"))
        } else {
            let byArea = Dictionary(grouping: cleanable, by: { area($0.file, home: home) })
            out += Table(columns: [.init(title: "Where"), .init(title: "Files", align: .right), .init(title: "Copies", align: .right)],
                         rows: byArea.sorted { $0.value.count > $1.value.count }.map { [$0.key, "\(Set($0.value.map(\.file)).count)", "\($0.value.count)"] }).render(st)
            let ranked = files.sorted { $0.value.count != $1.value.count ? $0.value.count > $1.value.count : $0.key < $1.key }
            out.append("  " + st.dim(list ? "Every file:" : "Most copies:"))
            for (file, hits) in ranked.prefix(list ? ranked.count : 6) {
                out.append("    \(st.dim("·")) \(place(file, home: home)) \(st.dim("— \(hits.count)"))" + (list ? "  " + st.dim(safe(shown(file, home: home))) : ""))
            }
            if !list && ranked.count > 6 { out.append("    " + st.dim("and \(ranked.count - 6) more files: tegata clean --list")) }
        }

        let kept = findings.filter { !SecretRedactor.cleanable($0) && $0.rule != "private-key-block" }
        let keys = findings.filter { $0.rule == "private-key-block" }.count
        if !kept.isEmpty || keys > 0 {
            out.append("")
            out.append(st.section("Left alone: \(plural(kept.count + keys, "copy", "copies"))", "these files use them; cleaning would break something"))
            for (a, hits) in Dictionary(grouping: kept, by: { area($0.file, home: home) }).sorted(by: { $0.value.count > $1.value.count }) {
                out.append("    \(st.dim("·")) \(a) \(st.dim("— \(hits.count)")): \(leftAloneReason(a))")
            }
            if keys > 0 { out.append("    \(st.dim("·")) private keys \(st.dim("— \(keys)")): a key is a block of lines; make a new key pair and retire the old one.") }
        }

        out.append("")
        out.append(st.section("How it works"))
        out.append("  " + st.dim("Each value becomes \(SecretRedactor.placeholder); the rest of every file stays as it was. Files in use right now"))
        out.append("  " + st.dim("are skipped. No backup, on purpose: a backup would be one more copy. tegata clean --dry-run rehearses it."))
        return out
    }

    // MARK: scan, on the terminal

    /// `tegata scan`: the first look, read like a check-up. Built from `ScanReport`, so the file export says the same.
    public static func scan(_ inv: AgentInventory, findings: [RiskFinding], exposure: ExposureReport?, details: Bool,
                            home: String, top: Int = 12, style st: Style = .plain, version: String = "") -> [String] {
        let r = ScanReport(inventory: inv, findings: findings, exposure: exposure, home: home, version: version, top: top)
        func level(_ l: String, _ text: String) -> String {
            switch l {
            case "critical": return st.wrap("● " + text, "1;31")
            case "high": return st.red("▲ " + text)
            case "medium": return st.yellow("◆ " + text)
            default: return st.green("✓ " + text)
            }
        }
        func cmd(_ s: String) -> String { s.replacingOccurrences(of: "tegata clean", with: st.bold("tegata clean")) }
        let label: [String: String] = ["critical": "● critical", "high": "▲ high", "medium": "◆ medium", "low": "· low", "info": "  info"]

        var out = st.header("scan", "a read-only look at this Mac's AI coding agents · nothing leaves it, nothing changes")
        out.append(st.section("In short"))
        for s in r.short { out.append("  " + level(s.level, s.text)) }
        out.append("")

        out.append(st.section("What your agents load: \(plural(r.extensions, "extension"))", r.agents.isEmpty ? "" : "in " + r.agents.joined(separator: ", ")))
        out.append("  " + st.dim("Things your AI agents load and run on their own: hooks run on every action, MCP servers give them tools,"))
        out.append("  " + st.dim("skills and subagents add instructions. Each one acts with your permissions."))
        if !r.kinds.isEmpty {
            out += Table(columns: [.init(title: "Kind"), .init(title: "How many", align: .right), .init(title: "Highest risk", color: st.severityCell)],
                         rows: r.kinds.map { [$0.kind, "\($0.count)", $0.highestRisk.flatMap { label[$0] } ?? "  –"] }).render(st)
        }
        out.append("  " + st.dim("Risk: ") + st.severityCell("● critical") + st.dim(" act now  ") + st.severityCell("▲ high") + st.dim(" review today  ")
                   + st.severityCell("◆ medium") + st.dim(" review  ") + st.severityCell("· low") + st.dim(" good to know  info nothing to do"))

        out.append("")
        if r.notable.isEmpty {
            out.append(st.section("Worth a look") + "  " + st.ok("nothing rated medium or above"))
        } else {
            out.append(st.section("Worth a look", "\(r.notableTotal) rated medium or above"))
            out.append("  " + st.dim("The extensions that can do the most. Not necessarily bad: keep what you installed and use, remove what you do not."))
            out += Table(columns: [.init(title: "Level", color: st.severityCell), .init(title: "Name", flexible: true, minWidth: 10),
                                   .init(title: "Installed by", flexible: true, minWidth: 8), .init(title: "Why", flexible: true, minWidth: 12),
                                   .init(title: "What to do", color: st.bold)],
                         rows: r.notable.map { [label[$0.level] ?? $0.level, $0.name, $0.installedBy, $0.why, $0.whatToDo] }).render(st)
            if r.notableTotal > r.notable.count { out.append(st.dim("  … and \(r.notableTotal - r.notable.count) more: tegata inventory --why")) }
            for f in r.ownerFixes { out.append("  " + st.shu("›") + " not using \(f.owner)? remove what it installed (\(f.count)): " + st.bold(f.command)) }
            for p in r.pins { out.append("  " + st.shu("›") + " \(p.name): in \(p.declaredIn), replace the package name by name@version (for example some-mcp@1.4.2)") }
        }

        if let copies = r.secretCopies {
            out.append("")
            out.append(st.section("Secrets your agents copied: \(plural(copies, "copy", "copies"))",
                                  r.filesRead.map { "\(plural($0, "file")) read in \(r.secondsReading ?? 0) s" } ?? ""))
            out.append("  " + st.dim("Passwords, API keys and tokens that ended up in your agents' chats, their settings and your shell history."))
            out.append("  " + st.dim("Any program that reads those files can use them. What to do about each one is below."))
            if r.secretAreas.isEmpty {
                out.append("  " + st.ok("none found"))
            } else {
                out += Table(columns: [.init(title: "Where"), .init(title: "Copies", align: .right), .init(title: "Files", align: .right)],
                             rows: r.secretAreas.map { [$0.area, "\($0.copies)", "\($0.files)"] }).render(st)
            }
            if details, let exposure {
                out.append("")
                out.append(st.section("Every copy", "file and line; the value is never shown"))
                for f in exposure.findings.sorted(by: { ($0.file, $0.line) < ($1.file, $1.line) }) {
                    out.append("    \(safe(shown(f.file, home: home))):\(f.line)  \(f.rule)\(f.keyName.map { " (\(safe($0)))" } ?? "")")
                }
            }
            if !r.plan.isEmpty {
                out.append("")
                out.append(st.section("What to do, in order", "rotating a key makes every copy worthless; clean the copies after"))
                let urg: [String: SecretAction.Urgency] = ["now": .now, "soon": .soon, "check": .check, "done": .none]
                for s in r.plan {
                    out.append("  \(st.urgency(urg[s.urgency] ?? .check)) \(st.bold(s.title)) \(st.dim("· \(s.what), \(plural(s.copies, "copy", "copies")) in \(plural(s.places, "place"))"))")
                    for (i, p) in s.where_.enumerated() {
                        out.append((i == 0 ? "          \(st.dim("Where")) " : "                ") + p.place + (p.copies > 1 ? " ×\(p.copies)" : ""))
                    }
                    if s.places > s.where_.count { out.append("                " + st.dim("and \(s.places - s.where_.count) more: tegata scan --details")) }
                    if !s.names.isEmpty { out.append("          \(st.dim("Names")) " + s.names.joined(separator: ", ")) }
                    for (i, step) in s.steps.enumerated() {
                        let prefix = i == 0 ? "          \(st.dim("Do   ")) " : "                "
                        let n = s.steps.count > 1 ? "\(i + 1). " : ""
                        out.append(prefix + n + cmd(step) + (i == 0 ? s.rotateAt.map { " " + st.shu($0) } ?? "" : ""))
                    }
                }
            }
        }
        for n in r.notRead { out.append(st.dim("  not read: \(n)")) }

        out.append("")
        out.append("  " + st.shu("Next"))
        out.append("  " + st.shu("›") + " tegata inventory --why     " + st.dim("why each finding matters"))
        out.append("  " + st.shu("›") + " tegata clean               " + st.dim("after rotating keys, remove their copies"))
        out.append("  " + st.shu("›") + " tegata watch install       " + st.dim("be told when something changes"))
        out.append("  " + st.shu("›") + " tegata scan --export       " + st.dim("save this report as a file (Markdown, or .json)"))
        return out
    }
}
