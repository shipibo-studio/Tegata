import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Hashes what a hook, an MCP server, a skill or a plugin would actually run or read, so that editing a file in
/// place is a change even when the entry that points at it is not. Only digests leave this type: file content is
/// read in chunks, hashed and dropped, never kept or logged.
///
/// A digest is 64 hex characters, or one of these tokens (they cannot collide with hex), so a script that goes
/// missing, or comes back, is itself a change:
/// `missing`, `unreadable`, `special` (a directory, pipe or device where a file was expected), `partial:<hex>` (a file
/// over `maxFileBytes`: the first `maxFileBytes` and the size are hashed), `too-many-files`, and the two that mean
/// "deliberately not opened" (see `Policy`): `sensitive`, `protected`.
public final class ContentDigester: @unchecked Sendable {
    public let maxFileBytes: Int
    public let maxFilesPerDirectory: Int
    public let maxDirectoryEntries: Int
    public let policy: Policy

    /// Files this type must not open, because a hook can name any path (`ssh -i ~/.ssh/id_ed25519`) and a security
    /// tool has no business reading key material, and because reading Documents, Desktop or Downloads makes macOS ask
    /// the user for a permission Tegata has no other reason to need.
    public struct Policy: Sendable {
        /// Folders (absolute prefixes) of credentials and key material: `sensitive`.
        public var sensitivePrefixes: [String] = []
        /// Folders macOS guards with a permission prompt: `protected`. Their content is not watched.
        public var protectedPrefixes: [String] = []

        public init(sensitivePrefixes: [String] = [], protectedPrefixes: [String] = []) {
            self.sensitivePrefixes = sensitivePrefixes; self.protectedPrefixes = protectedPrefixes
        }

        /// The defaults for a macOS home folder.
        public static func forHome(_ home: String) -> Policy {
            func under(_ rel: [String]) -> [String] { rel.map { home + "/" + $0 } }
            return Policy(
                sensitivePrefixes: under([".ssh", ".aws", ".gnupg", ".kube", ".azure", ".config/gcloud", ".docker", "Library/Keychains", "Library/Cookies"]),
                protectedPrefixes: under(["Desktop", "Documents", "Downloads", "Library/Mobile Documents", "Library/Containers", "Library/Group Containers"]))
        }

        /// Names that mean a credential wherever they are. A path that merely contains one of them is not matched;
        /// the file's own name is.
        static let sensitiveNames: Set<String> = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "auth.json", ".netrc", ".npmrc", ".pypirc", "credentials", "secrets"]
        static let sensitiveExtensions: Set<String> = ["pem", "p12", "pfx", "key", "keychain", "keychain-db", "kdbx", "jks", "ppk"]

        func token(for path: String) -> String? {
            func hits(_ prefixes: [String]) -> Bool { prefixes.contains { path == $0 || path.hasPrefix($0 + "/") } }
            if hits(sensitivePrefixes) { return "sensitive" }
            let name = (path as NSString).lastPathComponent.lowercased()
            if name.hasPrefix(".env") || Self.sensitiveNames.contains(name) || Self.sensitiveExtensions.contains((name as NSString).pathExtension) { return "sensitive" }
            if hits(protectedPrefixes) { return "protected" }
            return nil
        }
    }

    private let lock = NSLock()
    private var cache: [String: String] = [:]
    private var traitCache: [String: Set<ScriptTrait>] = [:]
    private var _hits = 0, _misses = 0, _protected = Set<String>()
    /// Rereads avoided and files actually read, for tests and for the scan report.
    public var hits: Int { lock.withLock { _hits } }
    public var misses: Int { lock.withLock { _misses } }
    /// Paths left unread because macOS guards their folder; reported so the user knows what is not being watched.
    public var protectedPaths: [String] { lock.withLock { _protected.sorted() } }

    static let skippedDirectories: Set<String> = ["node_modules", ".git", "__pycache__", ".venv", "venv"]
    /// State that tools write while they run, not content. Found on a real Mac: Claude Code keeps a `.in_use` folder
    /// inside an installed plugin's folder for the sessions using it, so hashing it reported "the plugin's files changed"
    /// at every session. Finder's `.DS_Store` and lock or pid files behave the same way. Nothing here is loaded as code.
    static let runtimeMarkers: Set<String> = [".in_use", ".DS_Store", ".localized"]
    static let runtimeExtensions: Set<String> = ["lock", "pid"]

    public init(maxFileBytes: Int = 4 * 1024 * 1024, maxFilesPerDirectory: Int = 500, maxDirectoryEntries: Int = 20_000, policy: Policy = Policy()) {
        self.maxFileBytes = maxFileBytes; self.maxFilesPerDirectory = maxFilesPerDirectory; self.maxDirectoryEntries = maxDirectoryEntries; self.policy = policy
    }

    /// The policy is checked on the path as given and on where it leads, so a link in an ordinary folder cannot be used
    /// to make Tegata open something in a forbidden one.
    func denied(_ path: String, _ resolved: String) -> String? {
        let t = policy.token(for: resolved) ?? policy.token(for: path)
        if t == "protected" { lock.withLock { _ = _protected.insert(resolved) } }
        return t
    }

    // MARK: files

    /// Digest of one file, following a symlink at the top (a hook script that is a link to the real script).
    public func file(_ path: String) -> String {
        let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        if let t = denied(path, resolved) { return t }
        var st = stat()
        guard stat(resolved, &st) == 0 else { return errno == ENOENT || errno == ENOTDIR ? "missing" : "unreadable" }
        // A pipe or a device would block or never end: only regular files are opened.
        guard (st.st_mode & S_IFMT) == S_IFREG else { return "special" }
        let key = Self.cacheKey(resolved, st)
        if let hit = lock.withLock({ cache[key] }) { lock.withLock { _hits += 1 }; return hit }
        guard let digest = hashFile(resolved, size: Int(st.st_size)) else { return "unreadable" }
        lock.withLock { _misses += 1; cache[key] = digest }
        return digest
    }

    /// The cache is keyed by path, size, mtime, **ctime** and inode. mtime alone can be put back with `touch -r`
    /// after an edit; ctime cannot be set by user code, so an edit always changes the key.
    static func cacheKey(_ path: String, _ st: stat) -> String {
        #if canImport(Darwin)
        let m = st.st_mtimespec, c = st.st_ctimespec
        #else
        let m = st.st_mtim, c = st.st_ctim
        #endif
        return "\(path)|\(st.st_size)|\(m.tv_sec).\(m.tv_nsec)|\(c.tv_sec).\(c.tv_nsec)|\(st.st_ino)"
    }

    func hashFile(_ path: String, size: Int) -> String? {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? h.close() }
        var hasher = SHA256()
        var remaining = min(size, maxFileBytes)
        while remaining > 0 {
            guard let chunk = try? h.read(upToCount: min(64 * 1024, remaining)), !chunk.isEmpty else { break }
            hasher.update(data: chunk)
            remaining -= chunk.count
        }
        if size > maxFileBytes { hasher.update(data: Data("size:\(size)".utf8)) }
        let hex = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        return size > maxFileBytes ? "partial:\(hex)" : hex
    }

    // MARK: script traits

    /// What the text of a script does (see `ScriptAnalyzer`), for a regular text file the policy allows. Cached on the
    /// same key as the digest, so an unchanged script is analysed once. A binary, a missing or a forbidden file has
    /// no traits; the digest still says it changed.
    public func traits(forFile path: String) -> Set<ScriptTrait> {
        let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        if denied(path, resolved) != nil { return [] }
        var st = stat()
        guard stat(resolved, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return [] }
        let key = Self.cacheKey(resolved, st)
        if let hit = lock.withLock({ traitCache[key] }) { return hit }
        var result = Set<ScriptTrait>()
        if let h = FileHandle(forReadingAtPath: resolved) {
            defer { try? h.close() }
            if let data = try? h.read(upToCount: ScriptAnalyzer.maxBytes), !data.isEmpty,
               !data.prefix(8192).contains(0)   // a NUL byte means a binary: not text to read
            { result = ScriptAnalyzer.analyze(String(decoding: data, as: UTF8.self)) }
        }
        lock.withLock { traitCache[key] = result }
        return result
    }

    // MARK: directories

    /// One digest for a folder: every regular file's relative path and content digest, sorted, hashed together.
    /// Nested symlinks are not followed but are part of the digest (name and destination), so swapping a file for a
    /// link to a script elsewhere is a change. `.git`, `node_modules` and similar are skipped.
    public func directory(_ path: String) -> String {
        let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        if let t = denied(path, resolved) { return t }
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: resolved, isDirectory: &isDir) else { return "missing" }
        guard isDir.boolValue else { return "special" }
        guard let e = FileManager.default.enumerator(atPath: resolved) else { return "unreadable" }

        var files: [String] = [], links: [String] = []
        var seen = 0
        while let rel = e.nextObject() as? String {
            seen += 1
            if seen > maxDirectoryEntries { return "too-many-files" }
            let name = (rel as NSString).lastPathComponent
            var st = stat()
            guard lstat(resolved + "/" + rel, &st) == 0 else { continue }
            if Self.runtimeMarkers.contains(name) || Self.runtimeExtensions.contains((name as NSString).pathExtension.lowercased()) {
                if (st.st_mode & S_IFMT) == S_IFDIR { e.skipDescendants() }
                continue
            }
            switch st.st_mode & S_IFMT {
            case S_IFDIR: if Self.skippedDirectories.contains(name) { e.skipDescendants() }
            case S_IFLNK:
                e.skipDescendants()
                let dest = (try? FileManager.default.destinationOfSymbolicLink(atPath: resolved + "/" + rel)) ?? "?"
                links.append("\(rel)->\(dest)")
            case S_IFREG: files.append(rel)
            default: break
            }
        }
        files.sort(); links.sort()
        var hasher = SHA256()
        for rel in files.prefix(maxFilesPerDirectory) {
            hasher.update(data: Data("F\u{0}\(rel)\u{0}\(file(resolved + "/" + rel))\n".utf8))
        }
        if files.count > maxFilesPerDirectory { hasher.update(data: Data("truncated:\(files.count)\n".utf8)) }
        for l in links { hasher.update(data: Data("L\u{0}\(l)\n".utf8)) }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    // MARK: several paths

    /// One digest for the handful of files a command names (a script and the config next to it): each path with its
    /// own digest, in the order given. nil when there is nothing to hash.
    public func files(_ paths: [String]) -> String? {
        guard !paths.isEmpty else { return nil }
        if paths.count == 1 { return file(paths[0]) }
        var hasher = SHA256()
        for p in paths { hasher.update(data: Data("\(p)\u{0}\(file(p))\n".utf8)) }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
