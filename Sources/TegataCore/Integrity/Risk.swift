import Foundation

public enum RiskSeverity: Int, Sendable, Codable, Comparable, CaseIterable {
    /// `critical` is for what a script does (runs code it downloads, hides a payload, reads credentials and can reach
    /// the network), not for where an entry sits: an entry's place rates it at most `high`.
    case info, low, medium, high, critical
    public static func < (a: RiskSeverity, b: RiskSeverity) -> Bool { a.rawValue < b.rawValue }
}

/// One thing worth knowing about an entry, in words a non-expert can act on.
///
/// Severity describes the entry *as it stands*, not whether it changed: most of an installed Mac's hooks
/// and skills are there on purpose. What interrupts the user is a *change* to an entry of some severity,
/// which the diff step decides; the inventory view uses severity as a badge.
public struct RiskFinding: Sendable, Equatable, Identifiable, Codable {
    public var id: String
    public var rule: String
    public var severity: RiskSeverity
    public var extensionId: String
    public var title: String
    public var why: String

    public init(rule: String, severity: RiskSeverity, extensionId: String, title: String, why: String) {
        self.id = "\(rule)|\(extensionId)"
        self.rule = rule; self.severity = severity; self.extensionId = extensionId; self.title = title; self.why = why
    }
}

/// Pure rules over the inventory. The only outside fact it needs is whether a script path exists, which
/// is injected so tests need no disk.
public struct RiskClassifier: Sendable {
    public var home: String
    public var fileExists: @Sendable (String) -> Bool

    public init(home: String, fileExists: @escaping @Sendable (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }) {
        self.home = home; self.fileExists = fileExists
    }

    public func classify(_ inventory: AgentInventory) -> [RiskFinding] {
        inventory.extensions.flatMap(classify).sorted { ($1.severity, $0.id) < ($0.severity, $1.id) }
    }

    /// Highest severity among the findings for one entry; nil when there are none.
    public static func badge(_ findings: [RiskFinding], for extensionId: String) -> RiskSeverity? {
        findings.filter { $0.extensionId == extensionId }.map(\.severity).max()
    }

    public func classify(_ e: AgentExtension) -> [RiskFinding] {
        // Tegata's own entries, recognised by exact value (never by name), are not rated as foreign. Their integrity is
        // guarded differently: the diff alerts on any edit to them, and the agent checks the bundle's code signature.
        if e.tegataRole != nil { return [] }
        var out: [RiskFinding] = []
        func add(_ rule: String, _ s: RiskSeverity, _ title: String, _ why: String) {
            out.append(RiskFinding(rule: rule, severity: s, extensionId: e.id, title: title, why: why))
        }
        let agent = Self.agentName(e.agent)
        let who = e.owner.map { "“\($0)”" } ?? "an unidentified tool"

        switch e.detail {
        case let .hook(event, _, kind, command, script, _):
            let sees = Self.hookEvents[event]
            if let sees { add("hook.\(sees.rule)", sees.severity, sees.title(who), sees.why(agent)) }
            let traits = Set((e.traits ?? []).compactMap(ScriptTrait.init(rawValue:)))
            // Off this Mac, or somewhere the text does not say, is "sends data"; a hook that only talks to a program on
            // this Mac (the terminal or editor that installed it, usually) is told apart, not dropped.
            let commandNet = kind == "http" || (command.map(CommandAnalysis.reachesNetwork) ?? false)
            let netLines = command.map { $0.split(separator: "\n").map(String.init).filter(CommandAnalysis.reachesNetwork) } ?? []
            let commandLocal = !netLines.isEmpty && netLines.allSatisfy(ScriptAnalyzer.staysOnThisMac)
            let remote = (commandNet && !commandLocal) || traits.contains(.networkOut)
            let local = !remote && ((commandNet && commandLocal) || traits.contains(.networkLoopback))
            if remote {
                let wide = sees != nil && sees!.severity >= .medium
                add("hook.network", wide ? .high : .medium, "Sends data over the network",
                    "This hook (installed by \(who)) can contact a server. On an event that carries your prompts or tool results, that is a way for them to leave your Mac.")
            } else if local {
                add("hook.local-server", .low, "Talks to a program on this Mac",
                    "This hook (installed by \(who)) sends what the event carries to a program listening on this Mac, not to the internet. That is how an app like a terminal hears from its hooks; make sure it is an app you use, and remove the hook if it is not.")
            }
            if let script, !fileExists(script.hasPrefix("~") ? home + script.dropFirst() : script) {
                add("hook.missing-script", .medium, "Points at a file that does not exist",
                    "\(script) is gone. Whoever creates a file at that path runs code on every \(event) event; if the tool was uninstalled, remove the hook.")
            }
            scriptFindings(traits, who: who, agent: agent, add)
            if e.kind == .credentialHelper, e.tegataClaim == nil {
                add("credential.helper", .medium, "Supplies \(agent)'s credential",
                    "\(agent) runs this program (from \(who)) to get its API key, and whatever it prints is used as the key. A password manager or Tegata is a normal answer; anything else should be one you chose.")
            }
            if kind == "prompt" || kind == "agent" {
                add("hook.model-evaluated", .info, "Decided by a model, not by a script", "The hook asks a model what to do, so its behaviour can vary between runs.")
            }
            if script == nil, let command, command.count > 120, kind == "command" {
                add("hook.inline", .low, "Inline script, no file to inspect", "The command is written into the config itself, so there is no file to review or to attribute to a tool.")
            }
        case let .mcpServer(_, command, _, url, _, pinned):
            // A remote server has no launcher to pin; it gets its own rules below.
            if !pinned, url == nil {
                add("mcp.unpinned", .medium, "Downloads the newest version every time it starts",
                    "\(who) launches this server through a package runner without an exact version, so an update to that package runs on your Mac the next time \(agent) starts.")
            }
            if let url {
                let local = url.contains("://localhost") || url.contains("://127.0.0.1") || url.contains("://[::1]")
                if url.lowercased().hasPrefix("http://"), !local {
                    add("mcp.cleartext", .high, "Talks to a remote server without encryption", "Anyone on the network path can read and alter what this server exchanges with \(agent).")
                } else if !local {
                    add("mcp.remote", .low, "Runs on a server you do not control", "The server's code can change at any time without anything changing on your Mac.")
                }
            }
            scriptFindings(Set((e.traits ?? []).compactMap(ScriptTrait.init(rawValue:))), who: who, agent: agent, add)
            if let helper = e.headersHelper {
                add("mcp.headers-helper", .medium, "Runs a program to build this server's credentials",
                    "\(agent) runs \(helper) and sends what it prints to the server as request headers, usually a token. Whoever can change that program decides what is sent, and to whom.")
            }
            if url != nil, e.headersHelper != nil, e.contentDigest == "missing" {
                add("mcp.missing-helper", .medium, "Its credential helper does not exist",
                    "The headersHelper program is gone. Whoever puts a file at that path runs code every time \(agent) connects to this server.")
            }
            if url == nil, e.contentDigest == "missing" {
                add("mcp.missing-program", .medium, "Points at a program that does not exist",
                    "The file this server starts is gone. Whoever puts a file at that path runs code the next time \(agent) starts; if the tool was uninstalled, remove the server.")
            }
            if let command, ["sh", "bash", "zsh", "fish"].contains((command as NSString).lastPathComponent) {
                add("mcp.shell", .medium, "Starts through a shell command", "A shell string is harder to review than a program and its arguments.")
            }
        case let .fileBased(count, executables, _):
            if e.kind == .skill, !executables.isEmpty {
                add("skill.executables", .info, "Ships \(executables.count) script\(executables.count == 1 ? "" : "s")",
                    "The skill can ask \(agent) to run files it brings along (\(count) files in total). Most skills that do this are normal; a change is what matters.")
            }
        case let .permissions(allow, _, _, mode):
            if mode == "bypassPermissions" {
                add("perm.bypass", .high, "Asks for nothing before acting", "defaultMode bypassPermissions lets \(agent) run any tool without confirmation.")
            } else if mode == "acceptEdits" {
                add("perm.accept-edits", .low, "Edits files without asking", "defaultMode acceptEdits applies file changes without confirmation.")
            }
            let broad = allow.filter(Self.isBroadAllow)
            if !broad.isEmpty {
                add("perm.broad-allow", .high, "Pre-approves commands that can do anything",
                    "\(broad.count) allow rule\(broad.count == 1 ? "" : "s") (\(broad.prefix(3).joined(separator: ", "))) let \(agent) run arbitrary code or reach the network without asking.")
            }
        case let .policy(values):
            let approval = values["approval_policy"], sandbox = values["sandbox_mode"]
            if sandbox == "danger-full-access" {
                add("policy.no-sandbox", .high, "Runs with no sandbox", "sandbox_mode danger-full-access gives \(agent) the same reach as you.")
            }
            if approval == "never" {
                add("policy.no-approval", sandbox == "danger-full-access" ? .high : .medium, "Never asks before acting", "approval_policy never lets \(agent) run commands without confirmation.")
            }
            if e.kind == .permissions, e.id.hasSuffix("folder-trust") {
                let wide = values.filter { $0.value == "trusted" && ["~", "/", home].contains($0.key) }
                if !wide.isEmpty { add("policy.trust-home", .high, "Trusts your whole home folder", "Every project below it can load its own hooks, rules and MCP servers into \(agent).") }
                else if values.values.contains("trusted") { add("policy.trusted-folders", .info, "Trusts \(values.values.filter { $0 == "trusted" }.count) folders", "Those folders can load their own configuration into \(agent).") }
            }
        case let .envKeys(keys):
            let redirect = keys.filter { Self.redirectEnv.contains($0.uppercased()) }
            if !redirect.isEmpty {
                add("env.redirect", .high, "Can redirect or intercept the agent's traffic",
                    "\(redirect.joined(separator: ", ")) changes where \(agent) sends requests or which certificates it trusts. Check the value in the file; Tegata does not read it.")
            }
            let inject = keys.filter { k in Self.injectEnv.contains(k.uppercased()) || k.uppercased().hasPrefix("DYLD_") }
            if !inject.isEmpty {
                add("env.code-injection", .high, "Can load code into every program \(agent) starts", "\(inject.joined(separator: ", ")) is read by the runtime before the program's own code.")
            }
            let creds = keys.filter { Self.credentialEnv.contains($0.uppercased()) }
            if !creds.isEmpty {
                add("env.credential-in-file", .medium, "Keeps a credential in a plain file", "\(creds.joined(separator: ", ")) is stored in the config, readable by any program running as you.")
            }
        case let .plugin(_, enabled):
            if enabled { add("plugin.enabled", .info, "Plugin is on", "A plugin can bring hooks, MCP servers and skills of its own.") }
        case let .marketplace(_, sourceKind, location):
            if sourceKind != "path", sourceKind != "directory", sourceKind != nil || location != nil {
                add("marketplace.remote", .low, "Pulls plugins from \(location ?? "a remote source")", "Whoever controls that source can publish updates that your agent installs.")
            }
        }

        switch e.tegataClaim {
        case .impostor?:
            add("tegata.impostor", .critical, "Looks like Tegata but is not",
                "It uses the names of Tegata's own files outside Tegata's app. Nothing legitimate does that; something is trying to pass for Tegata.")
        case .tampered?:
            add("tegata.tampered", .high, "Uses Tegata's files in an entry Tegata did not write",
                "Tegata's own helper or guard script appears here with a different role, event or matcher. Either Tegata's entry was edited, or another tool borrows its files. Repair it from Tegata.")
        case .otherCopy?:
            add("tegata.other-copy", .high, "Uses a different copy of Tegata",
                "The path is a Tegata app, but not the one running now. A developer build or an old download is harmless; a copy you did not install is not. Tegata checks the copy's signature before trusting it.")
        case .staleCopy?:
            add("tegata.stale-copy", .medium, "Points at a copy of Tegata that is gone",
                "Tegata was moved or deleted after this entry was written, so \(agent) runs a file that does not exist. Repair it from Tegata, or remove it.")
        case nil: break
        }

        // A repository can ship its own agent configuration; one you only cloned is not yours.
        if e.scope == .project, e.kind == .hook || e.kind == .mcpServer {
            add("scope.project", .medium, "Comes from a project folder, not from you",
                "Anyone who controls this repository controls this entry, and it runs as soon as you open the folder in \(agent).")
        }
        return out
    }

    /// What a script does, rated by fixed rules. Where the entry sits (the event, the scope) is rated elsewhere; these
    /// are about the text that will run, and the worst of them are `critical` whatever the entry's own rating.
    func scriptFindings(_ t: Set<ScriptTrait>, who: String, agent: String, _ add: (String, RiskSeverity, String, String) -> Void) {
        if t.contains(.downloadsAndRuns) {
            add("script.downloads-code", .critical, "Downloads code and runs it",
                "The script (from \(who)) fetches something from the network and executes it, so whoever controls that address controls what runs on your Mac every time \(agent) triggers it.")
        }
        if t.contains(.executesDecodedPayload) {
            add("script.hidden-payload", .critical, "Runs code it hides in an encoded string",
                "The script decodes text and executes the result. Legitimate tools almost never need to hide what they run.")
        }
        // Credentials handed to a local program are treated like credentials sent out: what listens there is unknown.
        if t.contains(.readsCredentials), t.contains(.networkOut) || t.contains(.networkLoopback) {
            add("script.credentials-and-network", .critical, "Reads credentials and can reach the network",
                "The script names credential files or keychain commands and can also open connections, which is the shape of something that sends secrets away. Check what it does before trusting it.")
        } else if t.contains(.readsCredentials) {
            add("script.reads-credentials", .high, "Reads credential files",
                "The script names SSH keys, cloud credentials, the keychain or .env files.")
        }
        if t.contains(.persistence) {
            add("script.persistence", .high, "Installs itself to run later",
                "The script writes a LaunchAgent, a cron job or a shell startup file, so it keeps running when \(agent) is closed.")
        }
        if t.contains(.destructive) {
            add("script.destructive", .high, "Can delete your home folder",
                "The script contains a recursive delete of your home folder or of the disk root.")
        }
        if t.contains(.modifiesAgentConfig) {
            add("script.edits-agent-config", .medium, "Edits an agent's configuration",
                "The script writes to settings of Claude Code, Codex, Cursor or Gemini, which is how a tool adds more hooks or servers without asking.")
        }
        if t.contains(.encodedBlob), !t.contains(.executesDecodedPayload) {
            add("script.encoded-blob", .medium, "Carries a long encoded block",
                "A long run of encoded text is the usual way to ship a payload inside a script. It is not proof of anything; it is worth reading.")
        }
    }

    // MARK: tables

    struct EventRisk: Sendable {
        var rule: String, severity: RiskSeverity
        var title: @Sendable (String) -> String
        var why: @Sendable (String) -> String
    }

    /// Events by what the hook receives. Lifecycle events that carry no user content are left out on purpose.
    static let hookEvents: [String: EventRisk] = [
        "UserPromptSubmit": .init(rule: "prompts", severity: .medium,
                                  title: { "Receives every prompt you send (\($0))" },
                                  why: { "It runs before \($0) sees each prompt and gets its full text." }),
        "PreToolUse": .init(rule: "tool-input", severity: .high,
                            title: { "Can read, rewrite or block every tool call (\($0))" },
                            why: { "It runs before every command and file operation, sees what \($0) is about to do, and can change or stop it." }),
        "PermissionRequest": .init(rule: "permissions", severity: .high,
                                   title: { "Can approve or deny permission requests (\($0))" },
                                   why: { "A hook that approves or denies requests decides what \($0) is allowed to do." }),
        "PostToolUse": .init(rule: "tool-output", severity: .medium,
                             title: { "Receives the output of every tool call (\($0))" },
                             why: { "It sees what \($0) read and ran, including file contents and command output." }),
        "notify": .init(rule: "notify", severity: .low,
                        title: { "Runs a program on agent events (\($0))" },
                        why: { "\($0) starts it whenever a turn finishes." }),
    ]

    static let redirectEnv: Set<String> = [
        "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE", "GOOGLE_GEMINI_BASE_URL", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
        "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_TLS_REJECT_UNAUTHORIZED",
    ]
    static let injectEnv: Set<String> = ["NODE_OPTIONS", "LD_PRELOAD", "BASH_ENV", "ENV", "PYTHONSTARTUP", "PYTHONPATH", "RUBYOPT", "PERL5OPT"]
    static let credentialEnv: Set<String> = ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"]

    static let dangerousCommands: Set<String> = ["sh", "bash", "zsh", "python", "python3", "node", "npx", "curl", "wget", "ssh", "scp", "sudo", "rm", "eval", "env", "osascript", "perl", "ruby", "nc"]

    /// `Bash`, `Bash(*)`, `Bash(:*)`, `*`, and `Bash(curl:*)` / `Bash(sudo *)` style rules for commands that run
    /// arbitrary code or move data out. A narrow rule such as `Bash(git status)` is not broad.
    static func isBroadAllow(_ rule: String) -> Bool {
        let r = rule.trimmingCharacters(in: .whitespaces)
        if r == "*" || r == "Bash" || r == "Bash(*)" || r == "Bash(:*)" { return true }
        guard r.hasPrefix("Bash("), r.hasSuffix(")") else { return false }
        let inner = String(r.dropFirst(5).dropLast())
        guard inner.hasSuffix(":*") || inner.hasSuffix(" *") || inner.hasSuffix("*") else { return false }
        let command = inner.split(whereSeparator: { $0 == ":" || $0 == " " || $0 == "*" }).first.map(String.init) ?? ""
        return dangerousCommands.contains((command as NSString).lastPathComponent)
    }

    static func agentName(_ a: AgentKind) -> String {
        switch a {
        case .claudeCode: "Claude Code"
        case .codex: "Codex"
        case .cursor: "Cursor"
        case .claudeDesktop: "Claude Desktop"
        case .gemini: "Gemini CLI"
        }
    }
}
