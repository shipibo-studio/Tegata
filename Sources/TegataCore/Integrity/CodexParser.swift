import Foundation

/// Codex keeps MCP servers, `notify`, sandbox and approval policy and folder trust in `~/.codex/config.toml`
/// and its lifecycle hooks in `~/.codex/hooks.json` (the same shape as Claude Code's `hooks`).
public enum CodexParser {
    public enum ParseError: Error, Equatable { case unreadable }

    public struct Parsed {
        public var entries: [AgentExtension]
        /// TOML statements that were skipped. A non-zero count means the inventory of this file is partial.
        public var problems: Int
    }

    /// Keys copied into a `.policy` entry. Nothing else from the file is kept besides what the dedicated
    /// readers below extract.
    static let policyKeys = ["approval_policy", "sandbox_mode", "approvals_reviewer"]

    public static func config(_ data: Data, scope: ConfigScope, declaredIn: String, home: String, raw: RawCollector? = nil, digest: ContentDigester? = nil) throws -> Parsed {
        let parsed = TOMLLite.parse(data)
        guard !parsed.tooLarge else { throw ParseError.unreadable }
        let root = parsed.root
        var ctx = ClaudeCodeParser.Context(agent: .codex, scope: scope, declaredIn: ClaudeCodeParser.shown(declaredIn, home: home), home: home)
        ctx.file = declaredIn; ctx.raw = raw; ctx.digester = digest
        var out: [AgentExtension] = []

        if let servers = root["mcp_servers"] as? [String: Any] {
            var c = ctx; c.mcpKey = "mcp_servers"; c.format = "toml"
            out += ClaudeCodeParser.mcpServers(servers, c)
        }

        // `notify = ["program", "arg"]` runs a program on agent events: a hook by another name.
        if let argv = (root["notify"] as? [Any])?.compactMap({ $0 as? String }), !argv.isEmpty {
            let joined = argv.joined(separator: " ")
            var notifyDigest = ctx.content(of: joined)
            var notifyOwner = CommandAnalysis.owner(of: joined, home: home)
            let (_, notifyClaim) = ctx.tegata(joined, expected: nil, digest: &notifyDigest, owner: &notifyOwner)
            out.append(ctx.add(AgentExtension(
                agent: .codex, scope: scope, kind: .hook, key: "notify", name: "notify", declaredIn: ctx.declaredIn,
                detail: .hook(event: "notify", matcher: nil, commandKind: "command",
                              command: IntegrityRedaction.command(joined, home: home),
                              scriptPath: CommandAnalysis.scriptPath(in: joined, home: home).map { ClaudeCodeParser.shown($0, home: home) },
                              timeoutSeconds: nil),
                owner: notifyOwner, fingerprint: Fingerprint.ofJSON(["entry": argv, "content": notifyDigest ?? "-"]), contentDigest: notifyDigest,
                           traits: ctx.traits(of: joined), tegataClaim: notifyClaim),
                           pointer: ["notify"], json: argv))
        }

        var policy: [String: String] = [:]
        for k in policyKeys { if let v = root[k] as? String { policy[k] = IntegrityRedaction.truncate(v, to: 60) } }
        if let ws = root["sandbox_workspace_write"] as? [String: Any], let net = ws["network_access"] as? Bool { policy["sandbox_workspace_write.network_access"] = String(net) }
        if !policy.isEmpty {
            out.append(ctx.add(AgentExtension(agent: .codex, scope: scope, kind: .permissions, key: "policy", name: "approval and sandbox policy",
                                              declaredIn: ctx.declaredIn, detail: .policy(values: policy), owner: nil, fingerprint: Fingerprint.ofJSON(policy)),
                               pointer: ["policy"], json: policy))
        }

        // `[projects."/path"] trust_level = "trusted"`: folders whose own config Codex will load.
        if let projects = root["projects"] as? [String: Any] {
            var trust: [String: String] = [:]
            for (path, v) in projects { if let t = (v as? [String: Any])?["trust_level"] as? String { trust[ClaudeCodeParser.shown(path, home: home)] = IntegrityRedaction.truncate(t, to: 30) } }
            if !trust.isEmpty {
                out.append(ctx.add(AgentExtension(agent: .codex, scope: scope, kind: .permissions, key: "folder-trust", name: "trusted folders (\(trust.count))",
                                                  declaredIn: ctx.declaredIn, detail: .policy(values: trust), owner: nil, fingerprint: Fingerprint.ofJSON(trust)),
                                   pointer: ["projects"], json: trust))
            }
        }
        return Parsed(entries: out, problems: parsed.problems)
    }

    public static func hooksFile(_ data: Data, scope: ConfigScope, declaredIn: String, home: String, raw: RawCollector? = nil, digest: ContentDigester? = nil) throws -> [AgentExtension] {
        let root = try ClaudeCodeParser.object(data)
        guard let hooks = root["hooks"] as? [String: Any] else { return [] }
        var ctx = ClaudeCodeParser.Context(agent: .codex, scope: scope, declaredIn: ClaudeCodeParser.shown(declaredIn, home: home), home: home)
        ctx.file = declaredIn; ctx.raw = raw; ctx.digester = digest
        return ClaudeCodeParser.hooks(hooks, ctx)
    }
}
