import Foundation

/// What a person can do about a finding, in a few words. A finding says what an entry can do; advice says what to do
/// about it. Shared by the command line and the app so both give the same answer.
public enum RiskAdvice {
    public enum Action: String, Sendable { case removeNow, removeIfUnused, pinVersion, review, reinstall, none }

    public struct Advice: Sendable, Equatable {
        public var action: Action
        /// Short enough for a table cell.
        public var short: String
    }

    public static func advice(for rule: String) -> Advice {
        switch rule {
        // What a script does: remove it unless you wrote it.
        case "script.downloads-code", "script.hidden-payload", "script.credentials-and-network", "script.destructive", "env.code-injection":
            return .init(action: .removeNow, short: "Remove it unless you wrote it")
        case "tegata.impostor", "tegata.tampered":
            return .init(action: .removeNow, short: "Remove it; reinstall Tegata")
        case "tegata.other-copy", "tegata.stale-copy":
            return .init(action: .reinstall, short: "Reinstall Tegata, then re-run")
        // Pointing at nothing: nothing to lose by removing it.
        case "hook.missing-script", "mcp.missing-program", "mcp.missing-helper":
            return .init(action: .removeIfUnused, short: "Remove: it points at nothing")
        case "mcp.unpinned":
            return .init(action: .pinVersion, short: "Pin a version in its config")
        case "mcp.cleartext":
            return .init(action: .review, short: "Use https, or remove it")
        // What an entry can see or change: fine for a tool you use, not for one you forgot.
        case "hook.permissions", "hook.tool-input", "hook.tool-output", "hook.prompts", "hook.network", "hook.local-server",
             "hook.inline", "hook.model-evaluated", "mcp.shell", "mcp.remote", "mcp.headers-helper", "plugin.enabled",
             "marketplace.remote", "skill.executables", "script.reads-credentials", "script.persistence", "script.edits-agent-config",
             "script.encoded-blob", "credential.helper":
            return .init(action: .removeIfUnused, short: "Keep if you use it; else remove")
        case "perm.bypass", "perm.broad-allow", "perm.accept-edits", "policy.no-approval", "policy.no-sandbox", "policy.trust-home",
             "policy.trusted-folders":
            return .init(action: .review, short: "Narrow it in the agent's settings")
        case "env.redirect", "env.credential-in-file":
            return .init(action: .review, short: "Check where it points")
        default:
            return .init(action: .none, short: "Good to know")
        }
    }
}
