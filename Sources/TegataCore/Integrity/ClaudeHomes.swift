import Foundation

/// Claude Code reads its whole configuration from `CLAUDE_CONFIG_DIR` when it is set, so apps that run it for you
/// (one folder per account, say) keep a second, complete config root next to `~/.claude`: settings and hooks, MCP
/// servers in its own `.claude.json`, skills, plugins, transcripts. Everything Tegata watches in `~/.claude` has to be
/// watched there too, or a hook added there goes unseen.
public struct ClaudeHome: Sendable, Equatable, Hashable {
    public var root: URL
    /// Where Tegata learnt about it, in words: "MonoCode account", "CLAUDE_CONFIG_DIR in ~/.zshrc", "added by you".
    public var origin: String
    public init(root: URL, origin: String) { self.root = root; self.origin = origin }
}

public enum ClaudeHomes {
    /// Apps known to run Claude Code with their own config roots: a folder whose subfolders are roots.
    static let knownParents: [(path: String, origin: String)] = [
        ("Library/Application Support/com.monocode.desktop/provider-accounts/claude", "MonoCode account"),
    ]
    static let startupFiles = [".zshenv", ".zprofile", ".zshrc", ".bash_profile", ".bashrc", ".profile"]
    static let exportLine = try! NSRegularExpression(pattern: #"^\s*(?:export\s+)?CLAUDE_CONFIG_DIR=["']?([^"'\s#;]+)"#, options: [.anchorsMatchLines])

    /// A folder looks like a Claude Code root when it holds one of the files Claude Code writes there.
    static func looksLikeRoot(_ url: URL, _ fm: FileManager) -> Bool {
        [".claude.json", "settings.json", "projects", "skills"].contains { fm.fileExists(atPath: url.appendingPathComponent($0).path) }
    }

    /// Extra roots, `~/.claude` excluded, each once. `added` are folders the user chose.
    public static func discover(home: URL, added: [URL] = [], fileManager fm: FileManager = .default) -> [ClaudeHome] {
        var out: [ClaudeHome] = []
        var seen: Set<String> = [home.appendingPathComponent(".claude").standardizedFileURL.path]
        func add(_ url: URL, _ origin: String) {
            let p = url.standardizedFileURL.path
            guard !seen.contains(p), looksLikeRoot(url, fm) else { return }
            seen.insert(p); out.append(ClaudeHome(root: URL(fileURLWithPath: p, isDirectory: true), origin: origin))
        }
        for (rel, origin) in knownParents {
            let parent = home.appendingPathComponent(rel)
            let children = (try? fm.contentsOfDirectory(at: parent, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey])) ?? []
            for c in children.sorted(by: { $0.path < $1.path }) {
                let v = try? c.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
                if v?.isDirectory == true, v?.isSymbolicLink != true { add(c, origin) }
            }
        }
        for name in startupFiles {
            for value in exportedConfigDirs(in: home.appendingPathComponent(name)) {
                guard let url = expand(value, home: home) else { continue }
                add(url, "CLAUDE_CONFIG_DIR in ~/\(name)")
            }
        }
        for u in added { add(u, "added by you") }
        return out
    }

    /// Values assigned to `CLAUDE_CONFIG_DIR` in a shell startup file. Only that variable is looked at.
    static func exportedConfigDirs(in file: URL) -> [String] {
        guard let data = FileManager.default.contents(atPath: file.path), data.count <= 1_048_576,
              let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else { return [] }
        let ns = text as NSString
        return exportLine.matches(in: text, range: NSRange(location: 0, length: ns.length)).map { ns.substring(with: $0.range(at: 1)) }
    }

    /// `~/x`, `$HOME/x`, `${HOME}/x` and absolute paths; anything with another variable is left out (unknown).
    static func expand(_ value: String, home: URL) -> URL? {
        var v = value
        for prefix in ["~/", "$HOME/", "${HOME}/"] where v.hasPrefix(prefix) { v = home.path + "/" + v.dropFirst(prefix.count) }
        guard v.hasPrefix("/"), !v.contains("$") else { return nil }
        return URL(fileURLWithPath: v, isDirectory: true)
    }
}
