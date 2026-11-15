import Foundation
import TegataCore
#if os(macOS)
import TegataDarwin
#endif

/// The `tegata` command. Read-only, no network, no root. Arguments are parsed by hand on purpose: one less
/// dependency in a security tool's supply chain.
public enum TegataCommand {
    public static let version = "0.2.0"
    /// The team that signs Tegata's releases. Public: it is in every signature.
    public static let releaseTeam = "34BRMF8X9A"

    public enum Exit: Int32 { case ok = 0, findings = 2, usage = 64 }

    /// The help text without colour (for `tegata help | less`, logs and tests).
    public static var usage: String { Render.help(.plain, version: version).joined(separator: "\n") }

    struct Options {
        var command = "help"
        var flags: Set<String> = []
        var failOn: RiskSeverity?
        var owner: String?
        var export = false
        var exportPath: String?
        var paths: [String] = []
    }

    static func parse(_ args: [String]) throws -> Options {
        var o = Options()
        var rest = args[...]
        if let first = rest.first, !first.hasPrefix("-") { o.command = first; rest = rest.dropFirst() }
        else if rest.contains("--version") { o.command = "version" }
        let known: Set<String> = ["--why", "--all", "--json", "--details", "--help", "-h", "--version", "--dry-run", "--yes", "--ids", "--replace", "--no-color", "--list", "--offline"]
        while let a = rest.first {
            rest = rest.dropFirst()
            if a == "--export" {
                o.export = true
                // Only a value that names a report file is taken as the file; anything else stays a project folder.
                if let v = rest.first, [".md", ".markdown", ".json"].contains(where: { v.lowercased().hasSuffix($0) }) { o.exportPath = v; rest = rest.dropFirst() }
            } else if a == "--owner" {
                guard let v = rest.first, !v.hasPrefix("-") else { throw UsageError("--owner needs a name (the owner column of tegata inventory)") }
                o.owner = v; rest = rest.dropFirst()
            } else if a == "--fail-on" {
                guard let v = rest.first, let s = RiskSeverity.allCases.first(where: { "\($0)" == v }) else {
                    throw UsageError("--fail-on needs one of: \(RiskSeverity.allCases.map { "\($0)" }.joined(separator: ", "))")
                }
                o.failOn = s; rest = rest.dropFirst()
            } else if a.hasPrefix("-") {
                guard known.contains(a) else { throw UsageError("unknown option \(a)") }
                o.flags.insert(a)
            } else {
                o.paths.append(a)
            }
        }
        if o.flags.contains("--help") || o.flags.contains("-h") { o.command = "help" }
        return o
    }

    struct UsageError: Error { let message: String; init(_ m: String) { message = m } }

    /// The installed Tegata.app whose signature holds, if any.
    static func installedApp() -> URL? {
        #if os(macOS)
        let fm = FileManager.default
        let candidates = ["/Applications/Tegata.app", fm.homeDirectoryForCurrentUser.appendingPathComponent("Applications/Tegata.app").path]
        for path in candidates where fm.fileExists(atPath: path) {
            let url = URL(fileURLWithPath: path)
            if BundleSignature.isValid(url, team: releaseTeam) { return url }
        }
        #endif
        return nil
    }

    /// Tegata's own entries (the app's helper and guard) are recognised only when the installed app's signature holds.
    static func footprint() -> TegataFootprint? { installedApp().map { TegataFootprint(appBundle: $0) } }

    /// What `--json` prints for an entry. `fingerprint` and `entryHash` are unkeyed SHA-256 over the entry's raw text,
    /// values included, so a printed one would let anyone check a guess of a weak secret in it (an env value, a token in
    /// an inline command). They stay on this machine; `contentDigest` (whole files, useful against known-bad lists) stays.
    static func shareable(_ e: AgentExtension) -> AgentExtension {
        var e = e
        e.fingerprint = ""
        e.entryHash = nil
        return e
    }

    /// Runs the command and returns the exit status. `out` and `err` receive whole lines.
    /// Asks on the terminal; anything but "y"/"yes" is no. Without a terminal there is no one to ask: no.
    public static func askOnTerminal(_ question: String) -> Bool {
        guard isatty(STDIN_FILENO) != 0 else { return false }
        FileHandle.standardError.write(Data((question + " [y/N] ").utf8))
        return ["y", "yes"].contains(readLine()?.trimmingCharacters(in: .whitespaces).lowercased() ?? "")
    }

    public static func run(_ args: [String], home: URL = FileManager.default.homeDirectoryForCurrentUser,
                           out: (String) -> Void = { print($0) }, err: (String) -> Void = { FileHandle.standardError.write(Data(($0 + "\n").utf8)) },
                           ask: (String) -> Bool = askOnTerminal, presence: Presence = touchID, style: Style = .plain) -> Int32 {
        let o: Options
        do { o = try parse(args) } catch let e as UsageError {
            err("tegata: \(e.message)"); err("try: tegata help"); return Exit.usage.rawValue
        } catch { return Exit.usage.rawValue }

        switch o.command {
        case "help":
            if o.paths.first == "agents" { agentGuide(style).forEach(out); return Exit.ok.rawValue }
            Banner.stamp(style, version: version, tagline: Render.tagline)
            Render.help(style, version: version).forEach(out)
            return Exit.ok.rawValue
        case "version":
            out("\(style.shu("tegata")) \(version) · \(Render.tagline)")
            #if os(macOS)
            // Which protection `tegata watch` gets from this build: a keychain access group needs the signed bundle.
            out(ProcessEntitlements.keychainAccessGroup != nil
                ? "keychain: access group (signed build); the watcher's secrets are out of other apps' reach"
                : "keychain: login keychain and a Secure Enclave key file (build from source; the signed build is stronger)")
            #endif
            return Exit.ok.rawValue
        case "scan", "inventory":
            let json = o.flags.contains("--json")
            let spinner = Spinner("Reading your agents' configuration", style: json ? .plain : style)
            spinner.start()
            let scanner = AgentInventoryScanner(home: home, footprint: footprint())
            let inventory = scanner.scan()
            let findings = RiskClassifier(home: home.path).classify(inventory)
            if o.command != "scan" { spinner.stop() }
            if o.command == "scan" {
                var sources = ExposureSource.defaults(home: home)
                let roots = o.paths.map { URL(fileURLWithPath: ($0 as NSString).expandingTildeInPath) }
                if !roots.isEmpty { sources.append(.projectEnv(roots: roots)) }
                spinner.relabel("Looking for secrets your agents copied")
                let exposure = ExposureScanner().scan(sources) { n in spinner.update(n) }
                spinner.stop()
                if json {
                    // The whole report on stdout, every notable entry (the terminal shows the first twelve).
                    let report = ScanReport(inventory: inventory, findings: findings, exposure: exposure, home: home.path, version: version, top: .max)
                    guard let data = try? report.json() else { err("tegata: could not encode the report"); return 1 }
                    out(String(decoding: data, as: UTF8.self))
                } else {
                    Render.scan(inventory, findings: findings, exposure: exposure, details: o.flags.contains("--details"), home: home.path,
                                style: style, version: version).forEach(out)
                }
                if o.export {
                    let report = ScanReport(inventory: inventory, findings: findings, exposure: exposure, home: home.path, version: version)
                    do {
                        let url = try report.write(to: o.exportPath, cwd: URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true))
                        // With --json, stdout is the report alone; the note goes to stderr.
                        let saved = "Saved \(Render.safe(Render.shown(url.path, home: home.path)))"
                        if json { err("tegata: " + saved) } else {
                            out("")
                            out("  " + style.ok(saved) + style.dim("  (readable only by you: it says where your secrets are, never what they are)"))
                        }
                    } catch {
                        err("tegata: \(error.localizedDescription)"); return 1
                    }
                }
            } else if json {
                let dto = IntegrityInventoryDTO(scannedAt: inventory.scannedAt, extensions: inventory.extensions.map(shareable),
                                                findings: findings, notes: inventory.incomplete)
                let enc = SealedCoding.makeEncoder()
                enc.outputFormatting = [.sortedKeys, .prettyPrinted]
                guard let data = try? enc.encode(dto), let text = String(data: data, encoding: .utf8) else { err("tegata: could not encode the inventory"); return 1 }
                out(text)
            } else {
                Render.inventory(inventory, findings: findings, why: o.flags.contains("--why"), all: o.flags.contains("--all"), ids: o.flags.contains("--ids"), style: style).forEach(out)
            }
            if let level = o.failOn, findings.contains(where: { $0.severity >= level }) { return Exit.findings.rawValue }
            return Exit.ok.rawValue
        case "status", "update":
            if o.command == "status" && o.flags.contains("--json") { return statusJSON(o, home: home, out: out, err: err) }
            #if os(macOS)
            style.header(o.command, o.command == "status" ? "version, updates, and the record of what your agents load"
                                                          : "is there a newer tegata?").forEach(out)
            versionBlock(o, offer: true, out: out, ask: ask, style: style)
            if o.command == "update" { return Exit.ok.rawValue }
            out("")
            var w = o
            w.command = "status"; w.paths = ["status"]
            return watch(w, home: home, out: out, err: err, ask: ask, style: style)
            #else
            err("tegata: \(o.command) is not available on this system yet"); return Exit.usage.rawValue
            #endif
        case "watch", "fix":
            #if os(macOS)
            if o.command == "fix" { style.header("fix", "take out what a scan reported; a backup of each file is kept").forEach(out) }
            return o.command == "watch" ? watch(o, home: home, out: out, err: err, ask: ask, style: style) : fix(o, home: home, out: out, err: err, ask: ask, presence: presence)
            #else
            err("tegata: \(o.command) is not available on this system yet"); return Exit.usage.rawValue
            #endif
        case "clean":
            style.header("clean", "remove copies of secrets from agent transcripts and shell history").forEach(out)
            let spinner = Spinner("Looking for copies of secrets", style: style)
            spinner.start()
            let report = ExposureScanner().scan(ExposureSource.defaults(home: home)) { n in spinner.update(n) }
            spinner.stop()
            let (copies, files) = SecretRedactor.plan(report.findings)
            Render.cleanPlan(report.findings, home: home.path, list: o.flags.contains("--list"), style: style).forEach(out)
            guard copies > 0 else { return Exit.ok.rawValue }
            let dry = o.flags.contains("--dry-run")
            if !dry {
                out("")
                let question = "Clean \(Render.plural(copies, "copy", "copies")) in \(Render.plural(files, "file")) now? Your chats stay; only the values change. There is no backup."
                guard personConfirms(question: question, reason: "Tegata will remove \(Render.plural(copies, "copy", "copies")) of secrets from your agents' chats and shell history.",
                                     yes: o.flags.contains("--yes"), ask: ask, presence: presence, err: err) else {
                    out("")
                    out(isatty(STDIN_FILENO) != 0
                        ? "  Nothing changed. When you have rotated the keys, run " + style.bold("tegata clean") + " again."
                        : "  Nothing changed: cleaning needs you at the terminal and Touch ID. An agent can rehearse it with --dry-run.")
                    return Exit.ok.rawValue
                }
            }
            let spin = Spinner(dry ? "Rehearsing" : "Cleaning", style: style)
            spin.start()
            let r = SecretRedactor.redact(report.findings, dryRun: dry)
            spin.stop()
            out("")
            out("  " + style.ok(dry ? "Would clean \(Render.plural(r.cleanedCopies, "copy", "copies")) in \(Render.plural(r.cleanedFiles, "file")) (rehearsal, nothing written)."
                                    : "Cleaned \(Render.plural(r.cleanedCopies, "copy", "copies")) in \(Render.plural(r.cleanedFiles, "file"))."))
            for (why, n) in r.skipped.sorted(by: { $0.key < $1.key }) { out("    \(style.dim("·")) skipped \(n): \(why)" + (why.contains("in use") ? style.dim(" (run it again later)") : "")) }
            if !dry && r.cleanedCopies > 0 { out("  " + style.ok("Your chats are all there; only the secret values were replaced.")) }
            if !dry && r.cleanedShellHistory {
                out("  " + style.yellow("◆") + " Terminal windows open now still remember the old lines and may write them back when they tidy their history.")
                out("    Close your other terminal windows, open a new one, and run " + style.bold("tegata clean") + " once more later to be sure.")
            }
            out("  " + style.dim("Your agents' providers may still hold these in their own history: rotating the keys is what makes them useless."))
            return Exit.ok.rawValue
        default:
            err("tegata: unknown command \(o.command)"); err("try: tegata help")
            return Exit.usage.rawValue
        }
    }
}
