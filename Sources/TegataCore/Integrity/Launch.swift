import Foundation

/// Reads what a command line launches: which file it runs, who plausibly installed it, and whether a
/// package launcher pins a version. Pure string work; nothing is executed or read from disk.
public enum CommandAnalysis {
    /// Directories under the home that belong to the OS or to generic toolchains, not to an agent
    /// helper. A path below one of these says nothing about who installed the entry.
    static let genericHomeDirs: Set<String> = [
        ".claude", ".local", ".config", ".cache", ".npm", ".bun", ".cargo", ".rustup", ".nvm", ".volta",
        ".pyenv", ".rbenv", ".asdf", ".mise", ".deno", ".pnpm", ".yarn", ".gem", ".go", ".sdkman",
        ".docker", ".ssh", ".zsh", ".oh-my-zsh", "bin", "Library", "Applications", "Documents",
        "Desktop", "Downloads", "Sites", "Developer", "Projects", "src", "code",
    ]

    /// Splits like a shell would for display purposes: whitespace separates, single and double quotes group.
    /// It is not a shell parser; an unbalanced quote just ends at the end of the text.
    public static func tokens(_ command: String) -> [String] {
        var out: [String] = [], cur = "", quote: Character? = nil, has = false
        for ch in command {
            if let q = quote {
                if ch == q { quote = nil } else { cur.append(ch) }
            } else if ch == "'" || ch == "\"" {
                quote = ch; has = true
            } else if ch.isWhitespace {
                if has || !cur.isEmpty { out.append(cur); cur = ""; has = false }
            } else {
                cur.append(ch)
            }
        }
        if has || !cur.isEmpty { out.append(cur) }
        return out
    }

    /// First token that is an absolute or home-relative path, with `~`, `$HOME` and `${HOME}` expanded.
    public static func scriptPath(in command: String, home: String) -> String? {
        scriptPaths(in: command, home: home, limit: 1).first
    }

    /// Up to `limit` distinct paths a command names, in order: the script and the config or helper beside it. Each
    /// is expanded and filtered like `scriptPath`; whether it exists is the caller's business.
    public static func scriptPaths(in command: String, home: String, limit: Int = 4) -> [String] {
        var out: [String] = []
        var previous = "", afterTee = false
        for t in tokens(command) {
            defer { previous = t }
            // Where output goes is not what runs: `>> ~/.tool/hook.log`, `2>/tmp/err`, `| tee -a out.txt`. Hashing a log
            // would report "the script changed" on every run.
            if outputRedirects.contains(previous) || outputRedirectPrefixes.contains(where: { t.hasPrefix($0) }) { continue }
            if t == "tee" { afterTee = true; continue }
            if afterTee { if t.hasPrefix("-") { continue }; afterTee = false; continue }
            guard out.count < limit, let p = expand(t, home: home), looksLikeFile(p), !out.contains(p) else { continue }
            out.append(p)
        }
        return out
    }
    static let outputRedirects: Set<String> = [">", ">>", "1>", "2>", "&>", "1>>", "2>>", "&>>", ">|"]
    static let outputRedirectPrefixes = [">", "1>", "2>", "&>"]

    static func expand(_ token: String, home: String) -> String? {
        // `/x/hook.sh;` and `(/x/hook.sh)` name the file without the shell punctuation stuck to it.
        var t = token
        while let first = t.first, "(<>".contains(first) { t.removeFirst() }
        if let cut = t.firstIndex(where: { ";|&)(><`,".contains($0) }) { t = String(t[..<cut]) }   // `b.sh|cat` is b.sh
        if t.hasPrefix("~/") { t = home + t.dropFirst(1) }
        else if t.hasPrefix("$HOME/") { t = home + t.dropFirst(5) }
        else if t.hasPrefix("${HOME}/") { t = home + t.dropFirst(7) }
        guard t.hasPrefix("/") else { return nil }
        return t
    }

    /// A path with a file-like last component and no shell metacharacters left in it.
    static func looksLikeFile(_ path: String) -> Bool {
        guard !path.contains("$"), !path.contains("`"), path.count > 1, !path.hasSuffix("/") else { return false }
        // Reject devices and the system's own programs (`/dev/null`, `/usr/bin/env`, `/bin/sh`): they are not what a tool
        // installed. `/tmp` is kept on purpose: a script dropped there is exactly what should be hashed and read.
        let system = ["/dev/", "/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/opt/homebrew/bin/", "/System/"]
        if system.contains(where: { path.hasPrefix($0) }) { return false }
        // Files that change on every run by nature.
        let ext = (path as NSString).pathExtension.lowercased()
        if ["log", "pid", "lock", "sock", "out", "err"].contains(ext) { return false }
        return true
    }

    /// Who installed the entry, from the first path that points at something installed under the home or in
    /// `/Applications`, else from a package launcher. nil when the command does not say.
    public static func owner(of command: String, home: String) -> String? {
        let toks = tokens(command)
        for t in toks {
            if let o = ownerFromPath(t, home: home) { return o }
        }
        if let pkg = launcherPackage(toks) { return packageName(pkg) }
        return ownerFromVariables(command)
    }

    /// Inline scripts have no path to read, but they often use a variable named after their tool
    /// (`ACME_AGENT_HOOK_TOKEN`, `ACME_HOOK_PORT`). The prefix of a variable that mentions HOOK or AGENT is the
    /// best remaining hint; it is only used when nothing else names an owner.
    static func ownerFromVariables(_ command: String) -> String? {
        let regex = try! NSRegularExpression(pattern: #"\b([A-Z][A-Z0-9]{2,})_[A-Z0-9_]*(?:HOOK|AGENT)[A-Z0-9_]*"#)
        let ns = command as NSString
        guard let m = regex.firstMatch(in: command, range: NSRange(location: 0, length: ns.length)) else { return nil }
        let prefix = ns.substring(with: m.range(at: 1))
        // Variables every agent defines are not a tool's name.
        if ["CLAUDE", "ANTHROPIC", "OPENAI", "CODEX", "GEMINI", "CURSOR", "MCP", "HOME", "PATH"].contains(prefix) { return nil }
        return prefix.lowercased()
    }

    static func ownerFromPath(_ token: String, home: String) -> String? {
        guard let p = expand(token, home: home) else {
            if token.hasPrefix("/Applications/") { return appName(token.dropFirst("/Applications/".count)) }
            return nil
        }
        if p.hasPrefix("/Applications/") { return appName(p.dropFirst("/Applications/".count)) }
        guard !home.isEmpty, p.hasPrefix(home + "/") else { return nil }
        let rel = p.dropFirst(home.count + 1).split(separator: "/").map(String.init)
        guard let first = rel.first else { return nil }
        // `~/.local/share/<tool>/…`, `~/.config/<tool>/…`, `~/Library/Application Support/<tool>/…`
        if first == ".local", rel.count > 3, rel[1] == "share" { return clean(rel[2]) }
        if first == ".config", rel.count > 2 { return clean(rel[1]) }
        if first == "Library", rel.count > 3, rel[1] == "Application Support" { return clean(rel[2]) }
        // `~/.claude/hooks/<tool>-something.sh`: a helper dropped into the agent's own folder. The file's
        // name prefix is the only hint of who put it there.
        if first == ".claude", rel.count >= 3, rel[1] == "hooks" { return filePrefix(rel[2]) }
        if genericHomeDirs.contains(first) { return nil }
        if first.hasPrefix(".") { return clean(first) }
        return nil
    }

    static func appName(_ rest: Substring) -> String? {
        guard let comp = rest.split(separator: "/").first else { return nil }
        return clean(comp.hasSuffix(".app") ? String(comp.dropLast(4)) : String(comp))
    }

    /// `zap-rewrite.sh` → `zap`. Only `-` and `_` separate a tool name from the rest; a prefix shorter than
    /// three characters or a file with no separator says nothing about who wrote it.
    static func filePrefix(_ file: String) -> String? {
        guard let i = file.firstIndex(where: { $0 == "-" || $0 == "_" }), file.distance(from: file.startIndex, to: i) >= 3 else { return nil }
        return clean(String(file[..<i]))
    }

    static func clean(_ s: String) -> String? {
        let t = s.hasPrefix(".") ? String(s.dropFirst()) : s
        return t.isEmpty ? nil : t.lowercased()
    }

    // MARK: package launchers

    /// The package argument of `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `uvx`, `pipx run`, `deno run` — nil when the
    /// command is not a launcher of that kind. Flags are skipped; `-p`/`--package` take the next token.
    public static func launcherPackage(_ toks: [String]) -> String? {
        guard let first = toks.first else { return nil }
        let exe = (first as NSString).lastPathComponent
        var rest = Array(toks.dropFirst())
        switch exe {
        case "npx", "bunx", "uvx": break
        case "pnpm", "yarn", "bun": guard rest.first == "dlx" || rest.first == "x" else { return nil }; rest.removeFirst()
        case "pipx": guard rest.first == "run" else { return nil }; rest.removeFirst()
        default: return nil
        }
        var i = 0
        while i < rest.count {
            let t = rest[i]
            if t == "-p" || t == "--package" || t == "--from" { if i + 1 < rest.count { return rest[i + 1] }; return nil }
            if t.hasPrefix("-") { i += 1; continue }
            return t
        }
        return nil
    }

    /// `@scope/name@1.2.3` → `@scope/name`; `name==1.0` → `name`.
    static func packageName(_ spec: String) -> String {
        var s = spec
        if let r = s.range(of: "==") { s = String(s[..<r.lowerBound]) }
        let start = s.hasPrefix("@") ? s.index(after: s.startIndex) : s.startIndex
        if let at = s[start...].firstIndex(of: "@") { s = String(s[..<at]) }
        return s
    }

    /// True when the launch names an exact version (`pkg@1.2.3`, `pkg==1.2.3`) or is not a package
    /// launcher at all (a local binary or script). `@latest`, ranges and a bare name are not pinned.
    public static func isPinned(command: String?, args: [String]) -> Bool {
        guard let command else { return true }
        let toks = [command] + args
        guard let spec = launcherPackage(toks) else { return true }
        if let r = spec.range(of: "==") { return exactVersion(String(spec[r.upperBound...])) }
        let start = spec.hasPrefix("@") ? spec.index(after: spec.startIndex) : spec.startIndex
        guard let at = spec[start...].firstIndex(of: "@") else { return false }
        return exactVersion(String(spec[spec.index(after: at)...]))
    }

    /// `1.2.3`, `1.2.3-beta.1`, `v2.0.0`; not `latest`, `^1.2.3`, `~1`, `>=1`, `1.x`, `*`, or empty.
    static func exactVersion(_ v: String) -> Bool {
        let s = v.hasPrefix("v") ? String(v.dropFirst()) : v
        guard let f = s.first, f.isNumber else { return false }
        return !s.contains(where: { "^~><=*x| ".contains($0) })
    }

    /// Hook or server commands that reach the network by themselves: fetchers and shells piping them.
    public static func reachesNetwork(_ command: String) -> Bool {
        let toks = tokens(command).map { ($0 as NSString).lastPathComponent }
        let fetchers: Set<String> = ["curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "rsync", "telnet", "http", "httpie", "xh"]
        if toks.contains(where: { fetchers.contains($0) }) { return true }
        let lower = command.lowercased()
        return lower.contains("http://") || lower.contains("https://") || lower.contains("urllib") || lower.contains("fetch(")
            || lower.contains("requests.post") || lower.contains("/dev/tcp/")
    }
}
