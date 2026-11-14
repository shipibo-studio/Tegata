import Foundation

/// Where a file came from, which decides what the report tells the user to do about it.
public struct ExposureSource: Sendable, Equatable {
    public enum Kind: String, Sendable, Codable, CaseIterable {
        /// Claude Code transcripts and history: copies the agent kept.
        case agentTranscript = "agent-transcript"
        /// `~/.claude.json` and its backups: MCP tokens and settings.
        case agentConfig = "agent-config"
        /// Shell startup files and history.
        case shell
        /// `.env*` files under the user's project roots.
        case projectEnv = "project-env"
    }
    public var kind: Kind
    public var roots: [URL]
    /// File name filter; nil = every regular file.
    public var include: (@Sendable (URL) -> Bool)?
    public var maxFileBytes: Int
    public var skipDirectories: Set<String>

    public init(kind: Kind, roots: [URL], include: (@Sendable (URL) -> Bool)? = nil, maxFileBytes: Int = 8 * 1024 * 1024,
                skipDirectories: Set<String> = ["node_modules", ".git", ".build", "build", "dist", "DerivedData", ".venv", "venv", "Pods", ".next", "target", ".cache"]) {
        self.kind = kind; self.roots = roots; self.include = include; self.maxFileBytes = maxFileBytes; self.skipDirectories = skipDirectories
    }

    public static func == (a: ExposureSource, b: ExposureSource) -> Bool { a.kind == b.kind && a.roots == b.roots }

    // MARK: default sources for a macOS home

    public static func claudeTranscripts(home: URL) -> ExposureSource {
        let claude = home.appendingPathComponent(".claude")
        return ExposureSource(kind: .agentTranscript, roots: [claude.appendingPathComponent("projects"), claude.appendingPathComponent("history.jsonl")],
                              include: { $0.pathExtension == "jsonl" }, skipDirectories: [])
    }
    public static func claudeConfig(home: URL) -> ExposureSource {
        ExposureSource(kind: .agentConfig, roots: [home.appendingPathComponent(".claude.json"), home.appendingPathComponent(".claude/backups")],
                       include: { $0.lastPathComponent.hasPrefix(".claude.json") || $0.pathExtension == "json" || $0.pathExtension == "backup" || $0.lastPathComponent.contains(".claude.json.backup") },
                       skipDirectories: [])
    }
    /// Transcripts and `.claude.json` copies kept under other Claude Code config roots (`CLAUDE_CONFIG_DIR`).
    public static func otherClaudeHomes(_ homes: [ClaudeHome]) -> [ExposureSource] {
        guard !homes.isEmpty else { return [] }
        let roots = homes.map(\.root)
        return [
            ExposureSource(kind: .agentTranscript, roots: roots.map { $0.appendingPathComponent("projects") },
                           include: { $0.pathExtension == "jsonl" }, skipDirectories: []),
            ExposureSource(kind: .agentConfig, roots: roots.flatMap { [$0.appendingPathComponent(".claude.json"), $0.appendingPathComponent("backups")] },
                           include: { $0.lastPathComponent.hasPrefix(".claude.json") || $0.pathExtension == "json" || $0.pathExtension == "backup" || $0.lastPathComponent.contains(".claude.json.backup") },
                           skipDirectories: []),
        ]
    }

    /// Every default source for a home: `~/.claude`, other Claude Code roots, shell files.
    public static func defaults(home: URL, homes: [ClaudeHome]? = nil) -> [ExposureSource] {
        [claudeTranscripts(home: home), claudeConfig(home: home), shellFiles(home: home)] + otherClaudeHomes(homes ?? ClaudeHomes.discover(home: home))
    }

    public static func shellFiles(home: URL) -> ExposureSource {
        let names = [".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile", ".zsh_history", ".bash_history", ".netrc"]
        return ExposureSource(kind: .shell, roots: names.map { home.appendingPathComponent($0) }, skipDirectories: [])
    }
    public static func projectEnv(roots: [URL]) -> ExposureSource {
        ExposureSource(kind: .projectEnv, roots: roots, include: { url in
            let n = url.lastPathComponent
            return n == ".env" || (n.hasPrefix(".env.") && !n.hasSuffix(".example") && !n.hasSuffix(".sample") && !n.hasSuffix(".schema") && !n.hasSuffix(".template"))
        })
    }

    /// Enumerates the regular files this source covers. Symlinks are not followed.
    public func files(fileManager fm: FileManager = .default) -> [URL] {
        var out: [URL] = []
        for root in roots {
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: root.path, isDirectory: &isDir) else { continue }
            if !isDir.boolValue { if include?(root) ?? true { out.append(root) }; continue }
            guard let e = fm.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .isDirectoryKey, .fileSizeKey], options: [.skipsPackageDescendants]) else { continue }
            for case let url as URL in e {
                let v = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .isDirectoryKey, .fileSizeKey])
                if v?.isSymbolicLink == true { e.skipDescendants(); continue }
                if v?.isDirectory == true {
                    if skipDirectories.contains(url.lastPathComponent) { e.skipDescendants() }
                    continue
                }
                guard v?.isRegularFile == true, (v?.fileSize ?? 0) <= maxFileBytes else { continue }
                if include?(url) ?? true { out.append(url) }
            }
        }
        return out
    }
}
