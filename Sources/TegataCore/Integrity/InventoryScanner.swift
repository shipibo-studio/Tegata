import Foundation

/// Reads the agents' configuration from disk and builds the inventory. Read-only: it never writes,
/// never follows a symlink below the top level of a skill, and reports what it could not read.
public struct AgentInventoryScanner: Sendable {
    public var home: URL
    /// Directories that are projects (each may hold `.claude/`, `.mcp.json`). Chosen by the user, like Exposure's roots.
    public var projectRoots: [URL]
    public var managedSettings: URL
    public var maxConfigBytes: Int
    public var maxFilesPerEntry: Int
    public var clock: any TimeSource
    /// Shared across scans so a rescan rereads only the files whose size, times or inode changed.
    public let digester: ContentDigester
    /// What this copy of Tegata writes, so its own entries are recognised; the app passes the one for its own bundle.
    public var footprint: TegataFootprint?
    /// Other Claude Code config roots (`CLAUDE_CONFIG_DIR`). nil means "discover them at every scan", so a root an
    /// app creates later is seen without a restart.
    public var claudeHomes: [ClaudeHome]?

    public init(home: URL, projectRoots: [URL] = [],
                managedSettings: URL = URL(fileURLWithPath: ClaudeSettingsFile.managedSettingsPath),
                maxConfigBytes: Int = 32 * 1024 * 1024, maxFilesPerEntry: Int = 500, clock: any TimeSource = SystemClock(),
                digester: ContentDigester? = nil, footprint: TegataFootprint? = nil, claudeHomes: [ClaudeHome]? = nil) {
        self.home = home; self.projectRoots = projectRoots; self.managedSettings = managedSettings
        self.claudeHomes = claudeHomes
        self.maxConfigBytes = maxConfigBytes; self.maxFilesPerEntry = maxFilesPerEntry; self.clock = clock
        self.digester = digester ?? ContentDigester(policy: .forHome(home.path))
        self.footprint = footprint
    }

    public func scan() -> AgentInventory { scan(raw: nil) }

    /// The inventory plus every entry exactly as its file wrote it, keyed by extension id. The raw side can hold
    /// secrets: it is for the encrypted snapshot only and must never be logged, shown or sent.
    public func scanWithRaw() -> (inventory: AgentInventory, raw: [String: RawEntry]) {
        let collector = RawCollector()
        let inventory = scan(raw: collector)
        return (inventory, collector.entries)
    }

    func scan(raw: RawCollector?) -> AgentInventory {
        var out: [AgentExtension] = []
        var incomplete: [String] = []
        let h = home.path
        let fm = FileManager.default

        func json(_ url: URL, _ parse: (Data) throws -> [AgentExtension]) {
            switch read(url, fm) {
            case .missing: return
            case .failed(let why): incomplete.append("\(ClaudeCodeParser.shown(url.path, home: h)): \(why)")
            case .data(let d):
                do { out += try parse(d) }
                catch { incomplete.append("\(ClaudeCodeParser.shown(url.path, home: h)): not valid JSON configuration") }
            }
        }

        // Claude Code, user level.
        let claude = home.appendingPathComponent(".claude")
        json(managedSettings) { try ClaudeCodeParser.settings($0, scope: .managed, declaredIn: managedSettings.path, home: h, raw: raw, digest: digester, footprint: footprint) }
        for name in ["settings.json", "settings.local.json"] {
            let u = claude.appendingPathComponent(name)
            json(u) { try ClaudeCodeParser.settings($0, scope: name == "settings.json" ? .user : .local, declaredIn: u.path, home: h, raw: raw, digest: digester, footprint: footprint) }
        }
        let state = home.appendingPathComponent(".claude.json")
        json(state) { try ClaudeCodeParser.userState($0, declaredIn: state.path, home: h, raw: raw, digest: digester) }
        let known = claude.appendingPathComponent("plugins/known_marketplaces.json")
        json(known) { try ClaudeCodeParser.knownMarketplaces($0, declaredIn: known.path, home: h, raw: raw) }
        for (dir, kind) in [("skills", ExtensionKind.skill), ("agents", .subagent), ("commands", .command)] {
            let (found, gaps) = fileBased(claude.appendingPathComponent(dir), kind: kind, agent: .claudeCode, scope: .user, fm)
            out += found; incomplete += gaps
        }

        // Claude Code under other config roots: the same files, read the same way, declared under that root.
        for other in claudeHomes ?? ClaudeHomes.discover(home: home) {
            let r = other.root
            for name in ["settings.json", "settings.local.json"] {
                let u = r.appendingPathComponent(name)
                json(u) { try ClaudeCodeParser.settings($0, scope: name == "settings.json" ? .user : .local, declaredIn: u.path, home: h, raw: raw, digest: digester, footprint: footprint) }
            }
            let st = r.appendingPathComponent(".claude.json")
            json(st) { try ClaudeCodeParser.userState($0, declaredIn: st.path, home: h, raw: raw, digest: digester) }
            let km = r.appendingPathComponent("plugins/known_marketplaces.json")
            json(km) { try ClaudeCodeParser.knownMarketplaces($0, declaredIn: km.path, home: h, raw: raw) }
            for (dir, kind) in [("skills", ExtensionKind.skill), ("agents", .subagent), ("commands", .command)] {
                let (found, gaps) = fileBased(r.appendingPathComponent(dir), kind: kind, agent: .claudeCode, scope: .user, fm)
                out += found; incomplete += gaps
            }
        }

        // Claude Code, project level.
        for root in projectRoots {
            let c = root.appendingPathComponent(".claude")
            for name in ["settings.json", "settings.local.json"] {
                let u = c.appendingPathComponent(name)
                json(u) { try ClaudeCodeParser.settings($0, scope: name == "settings.json" ? .project : .local, declaredIn: u.path, home: h, raw: raw, digest: digester, footprint: footprint) }
            }
            let mcp = root.appendingPathComponent(".mcp.json")
            json(mcp) { try ClaudeCodeParser.mcpFile($0, agent: .claudeCode, scope: .project, declaredIn: mcp.path, home: h, raw: raw, digest: digester) }
            for (dir, kind) in [("skills", ExtensionKind.skill), ("agents", .subagent), ("commands", .command)] {
                let (found, gaps) = fileBased(c.appendingPathComponent(dir), kind: kind, agent: .claudeCode, scope: .project, fm)
                out += found; incomplete += gaps
            }
        }

        // Codex: `config.toml` (MCP servers, notify, policy, folder trust), `hooks.json`, skills.
        let codex = home.appendingPathComponent(".codex")
        codexConfig(codex.appendingPathComponent("config.toml"), scope: .user, raw, fm, &out, &incomplete)
        let codexHooks = codex.appendingPathComponent("hooks.json")
        json(codexHooks) { try CodexParser.hooksFile($0, scope: .user, declaredIn: codexHooks.path, home: h, raw: raw, digest: digester) }
        let (codexSkills, codexGaps) = fileBased(codex.appendingPathComponent("skills"), kind: .skill, agent: .codex, scope: .user, fm)
        out += codexSkills; incomplete += codexGaps
        for root in projectRoots {
            let c = root.appendingPathComponent(".codex")
            codexConfig(c.appendingPathComponent("config.toml"), scope: .project, raw, fm, &out, &incomplete)
            let ph = c.appendingPathComponent("hooks.json")
            json(ph) { try CodexParser.hooksFile($0, scope: .project, declaredIn: ph.path, home: h, raw: raw, digest: digester) }
        }

        // Other agents that share the `mcpServers` shape.
        let cursor = home.appendingPathComponent(".cursor/mcp.json")
        json(cursor) { try ClaudeCodeParser.mcpFile($0, agent: .cursor, scope: .user, declaredIn: cursor.path, home: h, raw: raw, digest: digester) }
        let desktop = home.appendingPathComponent("Library/Application Support/Claude/claude_desktop_config.json")
        json(desktop) { try ClaudeCodeParser.mcpFile($0, agent: .claudeDesktop, scope: .user, declaredIn: desktop.path, home: h, raw: raw, digest: digester) }
        let gemini = home.appendingPathComponent(".gemini/settings.json")
        json(gemini) { try ClaudeCodeParser.mcpFile($0, agent: .gemini, scope: .user, declaredIn: gemini.path, home: h, raw: raw, digest: digester) }

        attachPluginContent(&out, fm)
        // Say what is not being watched, once, instead of leaving the user to assume everything is.
        let guarded = digester.protectedPaths
        if !guarded.isEmpty {
            incomplete.append("\(guarded.count) path(s) are in folders macOS protects (Documents, Desktop, Downloads); their content is not read, so edits there are not seen")
        }
        out.sort { $0.id < $1.id }
        return AgentInventory(scannedAt: clock.now, extensions: out, incomplete: incomplete.sorted())
    }

    func codexConfig(_ url: URL, scope: ConfigScope, _ raw: RawCollector?, _ fm: FileManager, _ out: inout [AgentExtension], _ incomplete: inout [String]) {
        let shown = ClaudeCodeParser.shown(url.path, home: home.path)
        switch read(url, fm) {
        case .missing: return
        case .failed(let why): incomplete.append("\(shown): \(why)")
        case .data(let d):
            do {
                let r = try CodexParser.config(d, scope: scope, declaredIn: url.path, home: home.path, raw: raw, digest: digester)
                out += r.entries
                if r.problems > 0 { incomplete.append("\(shown): \(r.problems) statement(s) could not be read") }
            } catch { incomplete.append("\(shown): too large or not readable as TOML") }
        }
    }

    // MARK: files

    /// Claude Code records where each plugin is installed (`installed_plugins.json`, `installPath`). Enabling a plugin
    /// by name says nothing about what is in it; pinning a commit does not pin content either, so the installed files
    /// are hashed and become part of the entry's fingerprint.
    func attachPluginContent(_ out: inout [AgentExtension], _ fm: FileManager) {
        guard out.contains(where: { $0.kind == .plugin }) else { return }
        var installs: [String: [String]] = [:]
        if case .data(let d) = read(home.appendingPathComponent(".claude/plugins/installed_plugins.json"), fm),
           let root = try? ClaudeCodeParser.object(d), let plugins = root["plugins"] as? [String: Any] {
            for (id, records) in plugins {
                installs[id] = ((records as? [Any]) ?? []).compactMap { ($0 as? [String: Any])?["installPath"] as? String }.sorted()
            }
        }
        for i in out.indices where out[i].kind == .plugin {
            guard case let .plugin(id, enabled) = out[i].detail else { continue }
            let dirs = installs[id] ?? []
            let digest: String
            if dirs.isEmpty { digest = "missing" }
            else if dirs.count == 1 { digest = digester.directory(dirs[0]) }
            else { digest = Fingerprint.ofBytes(Data(dirs.map { "\($0)\u{0}\(digester.directory($0))" }.joined(separator: "\n").utf8)) }
            out[i].contentDigest = digest
            out[i].fingerprint = Fingerprint.ofJSON(["entry": [id: enabled], "content": digest])
        }
    }

    enum Read { case missing, failed(String), data(Data) }

    func read(_ url: URL, _ fm: FileManager) -> Read {
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: url.path, isDirectory: &isDir) else { return .missing }
        if isDir.boolValue { return .failed("is a directory") }
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        if size > maxConfigBytes { return .failed("larger than \(maxConfigBytes / 1_048_576) MB, not read") }
        do { return .data(try Data(contentsOf: url)) }
        catch { return .failed("unreadable (\((error as NSError).code))") }
    }

    /// Script extensions and the executable bit: what would run, as opposed to text the agent reads.
    static let scriptExtensions: Set<String> = ["sh", "bash", "zsh", "fish", "py", "rb", "pl", "js", "mjs", "cjs", "ts", "command", "ps1", "php", "lua", "swift", "applescript", "scpt"]
    static let skippedDirs: Set<String> = ["node_modules", ".git", "__pycache__", ".venv", "venv"]

    /// `skills/<name>/…`, `agents/<name>.md`, `commands/[dir/]<name>.md`. One entry per skill, agent or command.
    func fileBased(_ dir: URL, kind: ExtensionKind, agent: AgentKind, scope: ConfigScope, _ fm: FileManager) -> ([AgentExtension], [String]) {
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: dir.path, isDirectory: &isDir), isDir.boolValue else { return ([], []) }
        let shownDir = ClaudeCodeParser.shown(dir.path, home: home.path)
        guard let names = try? fm.contentsOfDirectory(atPath: dir.path) else { return ([], ["\(shownDir): unreadable"]) }
        var found: [AgentExtension] = [], gaps: [String] = []
        for name in names.sorted() where !name.hasPrefix(".") {
            let url = dir.appendingPathComponent(name)
            let resolved = url.resolvingSymlinksInPath()   // top level only: skills are often links into a shared checkout
            var d: ObjCBool = false
            guard fm.fileExists(atPath: resolved.path, isDirectory: &d) else { gaps.append("\(shownDir)/\(name): broken link"); continue }
            if kind == .skill {
                guard d.boolValue else { continue }
                let (files, exec, newest, truncated) = walk(resolved, fm)
                if truncated { gaps.append("\(shownDir)/\(name): more than \(maxFilesPerEntry) files, listed the first ones") }
                found.append(entry(kind, agent, scope, key: name, name: name, in: shownDir, count: files, exec: exec, modified: newest, content: digester.directory(resolved.path)))
            } else if d.boolValue {
                // commands/<group>/<name>.md
                for (sub, file) in markdownFiles(in: resolved, fm) {
                    let m = (try? file.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? nil
                    found.append(entry(kind, agent, scope, key: "\(name)/\(sub)", name: "\(name)/\(sub)", in: shownDir, count: 1, exec: [], modified: m, content: digester.file(file.path)))
                }
            } else if resolved.pathExtension.lowercased() == "md" {
                let m = (try? resolved.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? nil
                let stem = (name as NSString).deletingPathExtension
                found.append(entry(kind, agent, scope, key: stem, name: stem, in: shownDir, count: 1, exec: [], modified: m, content: digester.file(resolved.path)))
            }
        }
        return (found, gaps)
    }

    func entry(_ kind: ExtensionKind, _ agent: AgentKind, _ scope: ConfigScope, key: String, name: String, in shownDir: String,
               count: Int, exec: [String], modified: Date?, content: String) -> AgentExtension {
        // The fingerprint covers what is in the files, not when they were last touched: editing a SKILL.md in place is a
        // change, and `touch` is not. `modified` stays in the detail for display only.
        let fp = Fingerprint.ofJSON(["kind": kind.rawValue, "name": name, "files": count, "exec": exec, "content": content])
        return AgentExtension(agent: agent, scope: scope, kind: kind, key: key, name: name, declaredIn: shownDir,
                              detail: .fileBased(fileCount: count, executables: exec, modified: modified?.wholeSeconds), owner: nil, fingerprint: fp, contentDigest: content)
    }

    /// Counts regular files below `root` (not following nested links), lists the runnable ones relative to it.
    /// The relative path comes from the enumerator's depth (`level`), not from a string prefix, so a `/var` →
    /// `/private/var` style difference between the root and the URLs it yields cannot skew it. Properties are
    /// prefetched in bulk by the enumerator; one `stat` per file made this four times slower on a large skills folder.
    func walk(_ root: URL, _ fm: FileManager) -> (files: Int, executables: [String], newest: Date?, truncated: Bool) {
        let keys: [URLResourceKey] = [.isRegularFileKey, .isSymbolicLinkKey, .isDirectoryKey, .isExecutableKey, .contentModificationDateKey]
        var files = 0, exec: [String] = [], newest: Date? = nil, truncated = false
        guard let e = fm.enumerator(at: root, includingPropertiesForKeys: keys, options: []) else { return (0, [], nil, false) }
        for case let url as URL in e {
            guard let v = try? url.resourceValues(forKeys: Set(keys)) else { continue }
            if v.isSymbolicLink == true { e.skipDescendants(); continue }
            if v.isDirectory == true { if Self.skippedDirs.contains(url.lastPathComponent) { e.skipDescendants() }; continue }
            guard v.isRegularFile == true else { continue }
            files += 1
            if files > maxFilesPerEntry { truncated = true; break }
            if let m = v.contentModificationDate, newest == nil || m > newest! { newest = m }
            if Self.scriptExtensions.contains(url.pathExtension.lowercased()) || v.isExecutable == true {
                exec.append(url.pathComponents.suffix(e.level).joined(separator: "/"))
            }
        }
        return (files, exec.sorted(), newest, truncated)
    }

    /// `<dir>/**/*.md` as (path below `dir` without the extension, file).
    func markdownFiles(in dir: URL, _ fm: FileManager) -> [(String, URL)] {
        guard let e = fm.enumerator(atPath: dir.path) else { return [] }
        var out: [(String, URL)] = []
        while let rel = e.nextObject() as? String {
            let name = (rel as NSString).lastPathComponent
            if name.hasPrefix(".") { e.skipDescendants(); continue }
            guard (name as NSString).pathExtension.lowercased() == "md" else { continue }
            out.append(((rel as NSString).deletingPathExtension, dir.appendingPathComponent(rel)))
            if out.count >= maxFilesPerEntry { break }
        }
        return out.sorted { $0.0 < $1.0 }
    }
}
