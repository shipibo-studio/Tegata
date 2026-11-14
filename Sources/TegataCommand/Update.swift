import Foundation
import TegataCore
#if os(macOS)
import TegataDarwin
#endif

/// Is there a newer tegata? The only network request the command line makes, and only from `tegata status` and
/// `tegata update`: an anonymous GET to GitHub's public releases API, nothing about the user in it, four seconds at
/// most. It never downloads or runs anything by itself; updating goes through Homebrew (which checks the cask's
/// sha256) or through the release page. `--offline` or `TEGATA_NO_UPDATE_CHECK=1` skips it.
public struct ReleaseInfo: Sendable, Equatable {
    public var version: String
    public var url: String
    public var published: Date?
}

/// What a check found.
public enum UpdateCheck: Sendable, Equatable {
    case found(ReleaseInfo)
    case failed(String)
}

public enum Updates {
    public static let latestURL = URL(string: "https://api.github.com/repos/shipibo-studio/Tegata/releases/latest")!
    public static let releasesPage = "https://github.com/shipibo-studio/Tegata/releases"

    /// Tests replace this; nothing else does.
    nonisolated(unsafe) static var fetcher: () -> UpdateCheck = fetchLatest

    static func fetchLatest() -> UpdateCheck {
        var req = URLRequest(url: latestURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 4)
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        req.setValue("tegata", forHTTPHeaderField: "User-Agent")           // a name, nothing about the user
        let box = ResultBox<UpdateCheck>(), done = DispatchSemaphore(value: 0)
        let config = URLSessionConfiguration.ephemeral                     // no cookies, no cache on disk
        config.timeoutIntervalForResource = 5
        URLSession(configuration: config).dataTask(with: req) { data, response, error in
            defer { done.signal() }
            if let error { box.result = .success(.failed("offline or unreachable (\(error.localizedDescription))")); return }
            guard let http = response as? HTTPURLResponse else { box.result = .success(.failed("no answer")); return }
            guard http.statusCode == 200, let data else {
                box.result = .success(.failed(http.statusCode == 404 ? "no public release yet" : "GitHub answered \(http.statusCode)")); return
            }
            box.result = .success(parse(data).map { .found($0) } ?? .failed("unreadable answer"))
        }.resume()
        _ = done.wait(timeout: .now() + 6)
        return (try? box.result?.get()) ?? .failed("timed out")
    }

    static func parse(_ data: Data) -> ReleaseInfo? {
        guard let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let tag = o["tag_name"] as? String else { return nil }
        let url = (o["html_url"] as? String).flatMap { $0.hasPrefix("https://github.com/") ? $0 : nil } ?? releasesPage
        let published = (o["published_at"] as? String).flatMap { ISO8601DateFormatter().date(from: $0) }
        return ReleaseInfo(version: tag.hasPrefix("v") ? String(tag.dropFirst()) : tag, url: url, published: published)
    }

    /// Semantic order: 0.2.0 > 0.1.10 > 0.1.2; a pre-release (0.2.0-dev) comes before its release (0.2.0).
    public static func isNewer(_ candidate: String, than current: String) -> Bool {
        func split(_ v: String) -> ([Int], String?) {
            let parts = v.split(separator: "-", maxSplits: 1).map(String.init)
            return (parts[0].split(separator: ".").map { Int($0) ?? 0 }, parts.count > 1 ? parts[1] : nil)
        }
        let (a, pa) = split(candidate), (b, pb) = split(current)
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0, y = i < b.count ? b[i] : 0
            if x != y { return x > y }
        }
        switch (pa, pb) {
        case (nil, .some): return true       // 0.2.0 after 0.2.0-dev
        case (.some, nil): return false
        case let (.some(x), .some(y)): return x > y
        default: return false
        }
    }

    /// Installed through Homebrew's cask (the bundle Homebrew put in /Applications, with brew on this Mac).
    static var brew: String? {
        ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"].first { FileManager.default.isExecutableFile(atPath: $0) }
    }
    static func installedByBrew() -> Bool {
        guard let brew else { return false }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: brew)
        p.arguments = ["list", "--cask", "tegata"]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return false }
        p.waitUntilExit()
        return p.terminationStatus == 0
    }

    static func checkingDisabled(_ o: TegataCommand.Options) -> Bool {
        o.flags.contains("--offline") || ProcessInfo.processInfo.environment["TEGATA_NO_UPDATE_CHECK"] != nil
    }
}

extension TegataCommand {
    /// The "Tegata" block of `tegata status` and all of `tegata update`: version, protection, newer release, offer.
    static func versionBlock(_ o: Options, offer: Bool, out: (String) -> Void, ask: (String) -> Bool, style st: Style) {
        out(st.section("Tegata"))
        #if os(macOS)
        let kind = ProcessEntitlements.keychainAccessGroup != nil ? "signed build" : "build from source"
        #else
        let kind = "build from source"
        #endif
        out("  " + st.ok("Version \(version) (\(kind))"))
        if Updates.checkingDisabled(o) {
            out("  " + st.dim("· update check skipped (--offline or TEGATA_NO_UPDATE_CHECK)"))
            return
        }
        switch Updates.fetcher() {
        case .failed(let why):
            out("  " + st.dim("· could not check for a newer version: \(why). \(Updates.releasesPage)"))
        case .found(let latest) where !Updates.isNewer(latest.version, than: version):
            out("  " + st.ok("Up to date" + (latest.version == version ? "" : " (latest release \(Render.safe(latest.version)))")))
        case .found(let latest):
            let when = latest.published.map { " (" + $0.formatted(date: .abbreviated, time: .omitted) + ")" } ?? ""
            out("  " + st.yellow("◆") + " " + st.bold("Version \(Render.safe(latest.version)) is out\(when).") + " " + st.dim(Render.safe(latest.url)))
            let viaBrew = Updates.installedByBrew()
            let how = viaBrew ? "brew upgrade --cask tegata" : "download it from the release page and check it (see the page's verify steps)"
            guard offer, isatty(STDIN_FILENO) != 0 else {
                out("    update: " + st.bold(how))
                return
            }
            guard ask(viaBrew ? "Update now with Homebrew?" : "Open the release page?") else {
                out("    when you want: " + st.bold(how)); return
            }
            if viaBrew, let brew = Updates.brew {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: brew)
                p.arguments = ["upgrade", "--cask", "tegata"]
                do { try p.run(); p.waitUntilExit() } catch { out("    " + st.red("could not run Homebrew: \(error.localizedDescription)")); return }
                guard p.terminationStatus == 0 else { out("    " + st.red("Homebrew did not finish the update.")); return }
                out("  " + st.ok("Updated."))
                #if os(macOS)
                if CommandLineWatch.installed {
                    // The background watcher still runs the old binary: start it again from the new one.
                    try? CommandLineWatch.install(logDirectory: stateDirectory(home: FileManager.default.homeDirectoryForCurrentUser))
                    out("  " + st.ok("Watcher restarted with the new version."))
                }
                #endif
            } else {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: "/usr/bin/open")
                p.arguments = [latest.url]
                try? p.run()
            }
        }
    }
}
