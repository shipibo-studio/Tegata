import Foundation

/// Turns Claude Code's JSON configuration into inventory entries. Pure: it takes bytes and returns
/// entries, so tests need no disk. Unknown keys and wrong types are skipped, never fatal; the reader
/// of a customer's machine cannot assume the file is well formed or current.
public enum ClaudeCodeParser {
    public enum ParseError: Error, Equatable { case notAnObject, invalidJSON }

    /// `settings.json`, `settings.local.json` and `managed-settings.json`: hooks, permissions, env keys,
    /// enabled plugins, extra marketplaces and, for project files, MCP servers.
    public static func settings(_ data: Data, scope: ConfigScope, declaredIn: String, home: String, raw: RawCollector? = nil, digest: ContentDigester? = nil,
                                footprint: TegataFootprint? = nil) throws -> [AgentExtension] {
        let root = try object(data)
        var out: [AgentExtension] = []
        var ctx = Context(agent: .claudeCode, scope: scope, declaredIn: shown(declaredIn, home: home), home: home)
        ctx.file = declaredIn; ctx.raw = raw; ctx.digester = digest; ctx.footprint = footprint

        if let helper = root["apiKeyHelper"] as? String, !helper.isEmpty { out.append(credentialHelper(helper, ctx)) }
        if let hooks = root["hooks"] as? [String: Any] { out += self.hooks(hooks, ctx) }
        if let perms = root["permissions"] as? [String: Any] { out += permissions(perms, ctx) }
        if let env = root["env"] as? [String: Any], !env.isEmpty {
            // Names only. The values never leave `root`.
            let keys = env.keys.sorted()
            out.append(ctx.add(AgentExtension(agent: .claudeCode, scope: scope, kind: .env, key: "env", name: "env (\(keys.count))",
                                              declaredIn: ctx.declaredIn, detail: .envKeys(keys), owner: nil, fingerprint: Fingerprint.ofJSON(env)),
                               pointer: ["env"], json: env))
        }
        if let plugins = root["enabledPlugins"] as? [String: Any] { out += self.plugins(plugins, ctx) }
        if let markets = root["extraKnownMarketplaces"] as? [String: Any] { out += marketplaces(markets, ctx) }
        if let servers = root["mcpServers"] as? [String: Any] { out += mcpServers(servers, ctx) }
        return out
    }

    /// `~/.claude.json`: user-scope MCP servers, and per-project (`local` scope) servers.
    public static func userState(_ data: Data, declaredIn: String, home: String, raw: RawCollector? = nil, digest: ContentDigester? = nil) throws -> [AgentExtension] {
        let root = try object(data)
        var out: [AgentExtension] = []
        let shownPath = shown(declaredIn, home: home)
        if let servers = root["mcpServers"] as? [String: Any] {
            var ctx = Context(agent: .claudeCode, scope: .user, declaredIn: shownPath, home: home)
            ctx.file = declaredIn; ctx.raw = raw; ctx.digester = digest
            out += mcpServers(servers, ctx)
        }
        if let projects = root["projects"] as? [String: Any] {
            for project in projects.keys.sorted() {
                guard let p = projects[project] as? [String: Any], let servers = p["mcpServers"] as? [String: Any], !servers.isEmpty else { continue }
                var ctx = Context(agent: .claudeCode, scope: .local, declaredIn: shownPath, home: home)
                ctx.keyPrefix = shown(project, home: home)
                ctx.file = declaredIn; ctx.raw = raw; ctx.digester = digest; ctx.pointerPrefix = ["projects", project]
                out += mcpServers(servers, ctx)
            }
        }
        return out
    }

    /// `<project>/.mcp.json`, Cursor's `mcp.json` and Claude Desktop's `claude_desktop_config.json` share one shape.
    public static func mcpFile(_ data: Data, agent: AgentKind, scope: ConfigScope, declaredIn: String, home: String, raw: RawCollector? = nil, digest: ContentDigester? = nil) throws -> [AgentExtension] {
        let root = try object(data)
        guard let servers = root["mcpServers"] as? [String: Any] else { return [] }
        var ctx = Context(agent: agent, scope: scope, declaredIn: shown(declaredIn, home: home), home: home)
        ctx.file = declaredIn; ctx.raw = raw; ctx.digester = digest
        return mcpServers(servers, ctx)
    }

    /// `~/.claude/plugins/known_marketplaces.json`: name → `{ source: { source, repo | url }, installLocation }`.
    public static func knownMarketplaces(_ data: Data, declaredIn: String, home: String, raw: RawCollector? = nil) throws -> [AgentExtension] {
        let root = try object(data)
        var ctx = Context(agent: .claudeCode, scope: .user, declaredIn: shown(declaredIn, home: home), home: home)
        ctx.file = declaredIn; ctx.raw = raw; ctx.marketplacePointer = []
        return marketplaces(root, ctx)
    }

    // MARK: pieces

    struct Context {
        var agent: AgentKind, scope: ConfigScope, declaredIn: String, home: String
        var keyPrefix: String? = nil
        /// Raw capture: absolute file path, where project-level entries sit inside it, and where marketplaces do.
        var file = "", pointerPrefix: [String] = [], marketplacePointer = ["extraKnownMarketplaces"]
        var raw: RawCollector? = nil
        /// Hashes the files that hooks and local MCP servers run; nil in pure-parser tests (no disk access).
        var digester: ContentDigester? = nil
        /// What this copy of Tegata writes; nil when the caller does not know (then nothing is recognised as Tegata's own,
        /// and any use of Tegata's file names is a claim).
        var footprint: TegataFootprint? = nil
        /// Codex spells the MCP table `mcp_servers` and writes TOML.
        var mcpKey = "mcpServers", format = "json"

        /// Records the entry as the file wrote it and hands the entry back, so call sites stay one expression.
        @discardableResult
        func add(_ ext: AgentExtension, pointer: [String], json: Any, matcher: String? = nil) -> AgentExtension {
            let canonical = RawCollector.canonicalJSON(json)
            var e = ext
            e.entryHash = Fingerprint.ofBytes(Data((pointer.joined(separator: "\u{0}") + "\u{1}" + (matcher ?? "") + "\u{1}" + canonical).utf8))
            raw?.record(RawEntry(extensionId: e.id, file: file, pointer: pointer, hookMatcher: matcher, format: format, json: canonical))
            return e
        }
        func key(_ parts: String...) -> String { ([keyPrefix].compactMap { $0 } + parts).joined(separator: "/") }

        /// What a command line does, and what the first two scripts it names do. The command text is analysed even
        /// when this parser has no disk access; scripts are read only through the digester, which refuses credential
        /// folders and macOS-protected ones.
        func traits(of command: String?) -> [String]? {
            guard let command else { return nil }
            var found = ScriptAnalyzer.analyze(command)
            if let digester { for p in CommandAnalysis.scriptPaths(in: command, home: home).prefix(2) { found.formUnion(digester.traits(forFile: p)) } }
            return found.isEmpty ? nil : found.map(\.rawValue).sorted()
        }

        /// Recognises Tegata's own entry or a claim to be Tegata. For Tegata's own entry the digest becomes a fixed token:
        /// the file is inside the signed bundle, its integrity is the code signature's job (checked by the agent), and
        /// every Tegata update would otherwise read as "the script behind it changed".
        func tegata(_ command: String?, expected: TegataRole?, event: String? = nil, matcher: String? = nil,
                    digest: inout String?, owner: inout String?) -> (TegataRole?, TegataClaim?) {
            guard let command else { return (nil, nil) }
            let (role, claim) = TegataFootprint.mark(command: command, home: home, footprint: footprint, expected: expected,
                                                     event: event, matcher: matcher, contentDigest: digest)
            if role != nil { digest = Self.signedToken; owner = "tegata" }
            else if owner == "tegata" { owner = nil }   // a name is not an identity
            return (role, claim)
        }
        static let signedToken = "tegata-signed"

        /// Digest of the files a command names (the script and the config beside it); nil when it names none or when
        /// this parser runs without disk access.
        func content(of command: String?) -> String? {
            guard let digester, let command else { return nil }
            return digester.files(CommandAnalysis.scriptPaths(in: command, home: home))
        }
    }

    static func hooks(_ hooks: [String: Any], _ ctx: Context) -> [AgentExtension] {
        var out: [AgentExtension] = []
        var seen: [String: Int] = [:]
        for event in hooks.keys.sorted() {
            guard let groups = hooks[event] as? [Any] else { continue }
            for group in groups {
                guard let g = group as? [String: Any] else { continue }
                let matcher = g["matcher"] as? String
                let entries = (g["hooks"] as? [Any]) ?? []
                for e in entries {
                    guard let h = e as? [String: Any] else { continue }
                    let kind = (h["type"] as? String) ?? "command"
                    // Raw only long enough to hash and to find the script; the model gets the redacted text.
                    let rawCommand = (h["command"] as? String) ?? (h["url"] as? String)
                    let identity = Fingerprint.ofBytes(Data("\(kind)\u{0}\(rawCommand ?? (h["prompt"] as? String) ?? "")".utf8)).prefix(12)
                    var key = ctx.key(event, matcher ?? "*", String(identity))
                    seen[key, default: 0] += 1
                    if seen[key]! > 1 { key += "#\(seen[key]!)" }   // the same hook listed twice is two entries
                    let timeout = (h["timeout"] as? Int) ?? (h["timeout"] as? Double).map(Int.init)
                    let script = rawCommand.flatMap { CommandAnalysis.scriptPath(in: $0, home: ctx.home) }
                    var digest = ctx.content(of: rawCommand)
                    var owner = rawCommand.flatMap { CommandAnalysis.owner(of: $0, home: ctx.home) }
                    let (role, claim) = ctx.tegata(rawCommand, expected: .guardHook, event: event, matcher: matcher, digest: &digest, owner: &owner)
                    out.append(ctx.add(AgentExtension(
                        agent: ctx.agent, scope: ctx.scope, kind: .hook, key: key,
                        name: matcher.map { "\(event) · \($0)" } ?? event,
                        declaredIn: ctx.declaredIn,
                        detail: .hook(event: event, matcher: matcher, commandKind: kind,
                                      command: rawCommand.map { IntegrityRedaction.command($0, home: ctx.home) },
                                      scriptPath: script.map { shown($0, home: ctx.home) }, timeoutSeconds: timeout),
                        owner: owner,
                        fingerprint: Fingerprint.ofJSON(["entry": h, "content": digest ?? "-"]), contentDigest: digest,
                        traits: kind == "command" && role == nil ? ctx.traits(of: rawCommand) : nil,
                        tegataRole: role, tegataClaim: claim),
                        pointer: ["hooks", event], json: h, matcher: matcher))
                }
            }
        }
        return out
    }

    static func mcpServers(_ servers: [String: Any], _ ctx: Context) -> [AgentExtension] {
        servers.keys.sorted().compactMap { name in
            guard let s = servers[name] as? [String: Any] else { return nil }
            let command = s["command"] as? String
            let args = (s["args"] as? [Any])?.compactMap { $0 as? String } ?? []
            let url = (s["url"] as? String) ?? (s["httpUrl"] as? String)   // Gemini spells it httpUrl
            let declared = (s["type"] as? String) ?? (s["transport"] as? String)
            let transport = declared ?? (url != nil ? "http" : (command != nil ? "stdio" : "unknown"))
            let envKeys = ((s["env"] as? [String: Any])?.keys.sorted()) ?? []
            let full = ([command].compactMap { $0 } + args).joined(separator: " ")
            // What the agent runs for this server: the server itself when it is local, and its `headersHelper` either way (a
            // remote server's helper runs on this Mac and decides what credentials are sent).
            let headersHelper = (s["headersHelper"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            let headerKeys = (s["headers"] as? [String: Any]).map { $0.keys.sorted() }
            let runs = [url == nil ? (command == nil ? nil : full) : nil, headersHelper].compactMap { $0 }.joined(separator: " ; ")
            var owner = command == nil ? headersHelper.flatMap { CommandAnalysis.owner(of: $0, home: ctx.home) } : CommandAnalysis.owner(of: full, home: ctx.home)
            var digest = runs.isEmpty ? nil : ctx.content(of: runs)
            let (_, claim) = ctx.tegata(runs.isEmpty ? nil : runs, expected: nil, digest: &digest, owner: &owner)
            var server = AgentExtension(
                agent: ctx.agent, scope: ctx.scope, kind: .mcpServer, key: ctx.key(name), name: name,
                declaredIn: ctx.declaredIn,
                detail: .mcpServer(transport: transport,
                                   command: command.map { IntegrityRedaction.command($0, home: ctx.home) },
                                   args: args.map { IntegrityRedaction.command($0, home: ctx.home) },
                                   url: url.map { IntegrityRedaction.command($0, home: ctx.home) },
                                   envKeys: envKeys,
                                   // A remote server is not "pinned": whoever runs it can change it.
                                   pinned: url == nil && CommandAnalysis.isPinned(command: command, args: args)),
                owner: owner, fingerprint: Fingerprint.ofJSON(["entry": s, "content": digest ?? "-"]), contentDigest: digest,
                traits: runs.isEmpty ? nil : ctx.traits(of: runs), tegataClaim: claim)
            server.headersHelper = headersHelper.map { IntegrityRedaction.command($0, home: ctx.home) }
            server.headerKeys = headerKeys
            return ctx.add(server, pointer: ctx.pointerPrefix + [ctx.mcpKey, name], json: s)
        }
    }

    /// `apiKeyHelper`: Claude Code runs this program for its credential. Tegata's own helper is recognised by its exact path.
    static func credentialHelper(_ helper: String, _ ctx: Context) -> AgentExtension {
        var digest = ctx.content(of: helper)
        var owner = CommandAnalysis.owner(of: helper, home: ctx.home)
        let (role, claim) = ctx.tegata(helper, expected: .credentialHelper, digest: &digest, owner: &owner)
        return ctx.add(AgentExtension(
            agent: ctx.agent, scope: ctx.scope, kind: .credentialHelper, key: "apiKeyHelper", name: "apiKeyHelper",
            declaredIn: ctx.declaredIn,
            detail: .hook(event: "apiKeyHelper", matcher: nil, commandKind: "command",
                          command: IntegrityRedaction.command(helper, home: ctx.home),
                          scriptPath: CommandAnalysis.scriptPath(in: helper, home: ctx.home).map { shown($0, home: ctx.home) }, timeoutSeconds: nil),
            owner: owner, fingerprint: Fingerprint.ofJSON(["entry": helper, "content": digest ?? "-"]), contentDigest: digest,
            traits: role == nil ? ctx.traits(of: helper) : nil, tegataRole: role, tegataClaim: claim),
                       pointer: ["apiKeyHelper"], json: helper)
    }

    static func plugins(_ plugins: [String: Any], _ ctx: Context) -> [AgentExtension] {
        plugins.keys.sorted().map { id in
            let enabled = (plugins[id] as? Bool) ?? false
            // `name@marketplace`: the part after `@` is who distributes it.
            let owner = id.split(separator: "@", maxSplits: 1).dropFirst().first.map(String.init)
            return ctx.add(AgentExtension(agent: ctx.agent, scope: ctx.scope, kind: .plugin, key: ctx.key(id), name: id,
                                          declaredIn: ctx.declaredIn, detail: .plugin(id: id, enabled: enabled),
                                          owner: owner, fingerprint: Fingerprint.ofJSON([id: enabled])),
                           pointer: ["enabledPlugins", id], json: enabled)
        }
    }

    /// Bookkeeping Claude Code rewrites on its own (found on a real Mac: refreshing a marketplace bumps `lastUpdated`
    /// in known_marketplaces.json). Where plugins come from is the source and the install location, not when they were
    /// last fetched; a refresh must not read as "the marketplace changed".
    static let volatileKeys: Set<String> = ["lastUpdated", "lastChecked", "updatedAt", "lastFetched"]

    static func marketplaces(_ markets: [String: Any], _ ctx: Context) -> [AgentExtension] {
        markets.keys.sorted().compactMap { name in
            guard let m = markets[name] as? [String: Any] else { return nil }
            let src = m["source"] as? [String: Any]
            let kind = src?["source"] as? String
            let location = (src?["repo"] as? String) ?? (src?["url"] as? String) ?? (src?["path"] as? String)
            return ctx.add(AgentExtension(agent: ctx.agent, scope: ctx.scope, kind: .marketplace, key: ctx.key(name), name: name,
                                          declaredIn: ctx.declaredIn,
                                          detail: .marketplace(name: name, sourceKind: kind,
                                                               location: location.map { IntegrityRedaction.command($0, home: ctx.home) }),
                                          owner: nil, fingerprint: Fingerprint.ofJSON(m.filter { !volatileKeys.contains($0.key) })),
                           pointer: ctx.marketplacePointer + [name], json: m)
        }
    }

    static func permissions(_ perms: [String: Any], _ ctx: Context) -> [AgentExtension] {
        func list(_ k: String) -> [String] { (perms[k] as? [Any])?.compactMap { $0 as? String } ?? [] }
        let allow = list("allow"), deny = list("deny"), ask = list("ask")
        let mode = perms["defaultMode"] as? String
        guard !(allow.isEmpty && deny.isEmpty && ask.isEmpty && mode == nil) else { return [] }
        // Rules are patterns, but a rule can embed a literal (`Bash(curl -H "Authorization: …")`): redact the text.
        func safe(_ l: [String]) -> [String] { l.map { IntegrityRedaction.command($0, home: ctx.home) } }
        return [ctx.add(AgentExtension(agent: ctx.agent, scope: ctx.scope, kind: .permissions, key: ctx.key("permissions"),
                                       name: "permissions", declaredIn: ctx.declaredIn,
                                       detail: .permissions(allow: safe(allow), deny: safe(deny), ask: safe(ask), defaultMode: mode),
                                       owner: nil, fingerprint: Fingerprint.ofJSON(perms)),
                        pointer: ["permissions"], json: perms)]
    }

    // MARK: helpers

    static func object(_ data: Data) throws -> [String: Any] {
        // An empty file is a valid "nothing configured" for every file this reads.
        if data.allSatisfy({ $0 == 0x20 || $0 == 0x0A || $0 == 0x0D || $0 == 0x09 }) { return [:] }
        guard let any = try? JSONSerialization.jsonObject(with: data) else { throw ParseError.invalidJSON }
        guard let obj = any as? [String: Any] else { throw ParseError.notAnObject }
        return obj
    }

    /// The home directory shown as `~`.
    static func shown(_ path: String, home: String) -> String {
        guard !home.isEmpty, home != "/" else { return path }
        if path == home { return "~" }
        return path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path
    }
}
