import Foundation
import TegataCore
#if os(macOS)
import TegataDarwin

/// Carries a result out of a detached task; written once, read after the semaphore.
final class ResultBox<T>: @unchecked Sendable { var result: Result<T, Error>? }

/// `tegata watch …` and `tegata fix …`: the watcher from the command line. Only one watcher runs on a Mac; when
/// Tegata.app's agent is there, these commands point to it instead of starting a second record.
extension TegataCommand {
    static let cliService = "app.tegata.cli-integrity"
    static let cliKeyTag = "app.tegata.cli-integrity-kek"

    /// What the user's own confirmation looks like when there is no baseline to unlock (fix without a watcher).
    struct ConfirmedAtPrompt: UnlockAuthorization {}

    /// Tests only: a monitor that keeps its secrets in memory, and whether the app is watching. Never set elsewhere.
    struct TestOverrides {
        var appIsWatching: Bool
        var makeMonitor: (URL) -> (IntegrityMonitor, String)
    }
    nonisolated(unsafe) static var testOverrides: TestOverrides?

    static var appIsWatching: Bool { testOverrides?.appIsWatching ?? CommandLineWatch.appIsWatching }

    static func stateDirectory(home: URL) -> URL {
        home.appendingPathComponent("Library/Application Support/Tegata CLI", isDirectory: true)
    }

    /// Where the watcher keeps its secrets depends on how this binary was built: a keychain access group is an
    /// entitlement macOS honours only inside a signed bundle with its profile (also when launched through a symlink).
    static func makeMonitor(home: URL, emit: @escaping @Sendable (IntegrityEvent) async -> Void) -> (monitor: IntegrityMonitor, protection: String) {
        if let t = testOverrides { return t.makeMonitor(home) }
        let state = stateDirectory(home: home)
        try? FileManager.default.createDirectory(at: state, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let provider: any KeyProvider
        let secrets: any IntegritySecrets
        let protection: String
        let keys: String
        if ProcessEntitlements.keychainAccessGroup != nil {
            keys = "the signed build (keychain access group)"
            provider = SecureEnclaveKeyProvider()
            secrets = DataProtectionIntegritySecrets(service: cliService)
            protection = "Secure Enclave key and a keychain access group only this signed build can use"
        } else {
            keys = "a build from source (login keychain and key file)"
            provider = SecureEnclaveBlobKeyProvider(directory: state.appendingPathComponent("keys", isDirectory: true))
            secrets = LoginKeychainIntegritySecrets(service: cliService)
            protection = "Secure Enclave key file and the login keychain (a build from source: other apps asking for these items get a macOS prompt; the signed build keeps them in an access group)"
        }
        let check: FootprintCheck? = footprint().map { f in
            let app = URL(fileURLWithPath: (f.helperPath as NSString).deletingLastPathComponent).deletingLastPathComponent().deletingLastPathComponent()
            return FootprintCheck(appBundle: app) { BundleSignature.isValid(app, team: releaseTeam) }
        }
        let monitor = IntegrityMonitor(home: home, directory: state.appendingPathComponent("integrity", isDirectory: true),
                                       quarantineDir: state.appendingPathComponent("quarantine", isDirectory: true), keyTag: cliKeyTag,
                                       provider: provider, secrets: secrets, footprintCheck: check, keysLabel: keys, emit: emit)
        return (monitor, protection)
    }

    /// Runs async work from the synchronous command. Nothing here needs the main thread.
    static func blocking<T: Sendable>(_ body: @escaping @Sendable () async throws -> T) throws -> T {
        let box = ResultBox<T>(), done = DispatchSemaphore(value: 0)
        Task.detached { do { box.result = .success(try await body()) } catch { box.result = .failure(error) }; done.signal() }
        done.wait()
        return try box.result!.get()
    }

    static let subtitles: [String: String] = [
        "status": "the record of what your agents load, and what changed since",
        "install": "be told when your agents' configuration changes",
        "uninstall": "stop watching (the record stays)",
        "establish": "take the record Tegata compares against",
        "accept": "keep a change: it becomes part of the record",
        "revert": "undo a change", "remove": "undo a change", "quarantine": "move an added skill aside",
        "quarantined": "what was moved aside", "restore": "put back what was moved aside",
        "refresh": "after a Tegata update, record how it now reads your configuration",
        "forget": "drop the record",
    ]

    /// The changes a person meant: an id as shown by --ids, or a name as shown in the table ("tegata-prueba").
    /// `many` lets one name pick several changes (accept); undoing needs one, so several matches list their files
    /// and nothing is done.
    static func resolve(_ args: [String], in changes: [IntegrityChange], many: Bool, err: (String) -> Void) -> [String]? {
        var ids: [String] = []
        for a in args {
            if changes.contains(where: { $0.extensionId == a }) { ids.append(a); continue }
            let exact = changes.filter { $0.name == a }
            let hits = exact.isEmpty ? changes.filter { $0.name.lowercased() == a.lowercased() } : exact
            switch hits.count {
            case 0:
                err("tegata: no pending change is named \(Render.safe(a)); tegata watch status lists them")
                return nil
            case 1:
                ids.append(hits[0].extensionId)
            default:
                if many { ids += hits.map(\.extensionId); continue }
                err("tegata: \(hits.count) changes are named \(Render.safe(a)); choose one by its id:")
                for h in hits { err("  '\(Render.safe(h.extensionId))'   in \(Render.safe(h.declaredIn))") }
                return nil
            }
        }
        var seen = Set<String>()
        return ids.filter { seen.insert($0).inserted }
    }

    static func describe(_ s: IntegrityStatus, protection: String, installed: Bool? = nil, ids: Bool = false, style st: Style = .plain) -> [String] {
        var out: [String] = []
        out.append(st.section("What this is"))
        out.append("  " + st.dim("Tegata keeps a record of what your agents load and checks it against what is there, in the background."))
        out.append("  " + st.dim("When a hook, an MCP server, a plugin or a skill is added or changed, you are told and decide what to do."))
        out.append("")
        out.append(st.section("Your record"))
        switch s.baseline {
        case .present:
            let taken = s.baselineCreatedAt.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? "?"
            out.append("  " + st.ok("Taken \(taken) · \(Render.plural(s.entries, "extension")) now"))
        case .none:
            out.append("  " + st.yellow("◆") + " Not taken yet. Look first (" + st.bold("tegata scan") + "), then " + st.bold("tegata watch establish") + " (Touch ID).")
        case .missing:
            out.append("  " + st.wrap("●", "1;31") + " The record is gone although one was taken. Deleting it is a way to hide changes:")
            out.append("    review with " + st.bold("tegata scan") + ", then take a new one: " + st.bold("tegata watch establish --replace"))
        case .tampered:
            out.append("  " + st.wrap("●", "1;31") + " The record was altered outside Tegata, so it cannot be trusted:")
            out.append("    review with " + st.bold("tegata scan") + ", then take a new one: " + st.bold("tegata watch establish --replace"))
        case .otherBuild:
            // Not an alarm: two builds of Tegata on one Mac, each with its own keys (see IntegrityMonitor.otherBuildsKeys).
            out.append("  " + st.yellow("◆") + " Taken by another build of Tegata: " + Render.safe(s.recordKeys ?? "another copy") + ".")
            out.append("    This copy keeps its keys elsewhere, so it cannot read that record; nothing suggests it was altered.")
            out.append("    Use the build that took it" + (CommandLineWatch.installedProgram.map { " (" + st.bold(Render.safe($0)) + ")" } ?? "") + " for status, accept and fix.")
        }
        if let installed {
            out.append("  " + (installed ? st.ok("Watching in the background (starts with your Mac)")
                                         : st.yellow("◆") + " Not watching in the background: " + st.bold("tegata watch install")))
        }
        out.append("  " + st.ok("Keys: \(protection)"))

        guard s.baseline == .present else { return out }
        out.append("")
        let groups = IntegrityDiffer.grouped(s.changes)
        if groups.isEmpty {
            out.append(st.section("Changes since the record") + "  " + st.ok("none"))
            out.append("  " + st.dim("Your agents load exactly what they loaded when the record was taken."))
        } else {
            out.append(st.section("Changes since the record", Render.plural(s.changes.count, "change")))
            var rows: [[String]] = []
            for c in s.changes {
                let alert = c.alert == .notify ? "● notify" : c.alert == .review ? "◆ review" : "· quiet"
                let can = (IntegrityRemedy.options(for: c).map(\.rawValue) + ["accept"]).joined(separator: " · ")
                rows.append([alert, Render.safe(c.summary), can])
            }
            out += Table(columns: [.init(title: "Alert", color: st.severityCell), .init(title: "What changed", flexible: true, minWidth: 20),
                                   .init(title: "You can", color: st.bold)], rows: rows).render(st)
            out.append("  " + st.shu("›") + " keep them all: " + st.bold("tegata watch accept --all") + st.dim(" (Touch ID)"))
            out.append("  " + st.shu("›") + " one at a time, by the name in the table: " + st.bold("tegata watch accept|remove|revert <name>"))
            if ids { for c in s.changes { out.append("      " + st.dim("id") + " '\(Render.safe(c.extensionId))'  " + st.dim(Render.safe(c.name))) } }
        }
        return out
    }

    static func watch(_ o: Options, home: URL, out: (String) -> Void, err: (String) -> Void, ask: (String) -> Bool, style st: Style = .plain) -> Int32 {
        let sub = o.paths.first ?? "status"
        let args = Array(o.paths.dropFirst())
        // `tegata status` prints its own header and the version block first.
        if sub != "run" && o.command != "status" { st.header("watch \(sub)", subtitles[sub] ?? "the record of your agents' configuration").forEach(out) }
        if appIsWatching && sub != "uninstall" {
            out("Tegata.app is watching this Mac; one watcher is enough. Its Extensions tab has the record, the changes and the fixes.")
            if CommandLineWatch.installed { out("This command line's own watcher is installed too and stays idle; tegata watch uninstall removes it.") }
            return Exit.ok.rawValue
        }
        // Only the background watcher notifies; a command run by hand shows the same thing on screen. (Before this,
        // every `tegata watch status` sent notifications too.)
        let notifies = sub == "run"
        let (monitor, protection) = makeMonitor(home: home) { e in
            guard notifies else { return }
            CommandLineWatch.notify(title: e.critical ? "Tegata: your agents' configuration changed" : "Tegata", message: e.message)
        }
        do {
            switch sub {
            case "status":
                let s = try blocking { await monitor.status(rescan: true) }
                describe(s, protection: protection, installed: CommandLineWatch.installed, ids: o.flags.contains("--ids"), style: st).forEach(out)
                if CommandLineWatch.installed, let program = CommandLineWatch.installedProgram, program != CommandLineWatch.executablePath {
                    out("  " + st.yellow("◆") + " The watcher runs \(Render.safe(program)), not this copy: " + st.bold("tegata watch install") + " again after an update.")
                }
            case "install":
                try CommandLineWatch.install(logDirectory: stateDirectory(home: home))
                out("  " + st.ok("Watching in the background. It starts with your Mac and tells you when your agents' configuration changes."))
                out("  " + st.dim("Runs \(Render.safe(CommandLineWatch.executablePath))"))
                let s = try blocking { await monitor.status(rescan: false) }
                out("")
                out("  " + st.shu("Next"))
                if s.baseline == .present {
                    out("  " + st.ok("Your record is already taken (\(s.baselineCreatedAt.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? "earlier")). Nothing else to do."))
                } else {
                    out("  " + st.shu("›") + " " + st.bold("tegata watch establish") + "   " + st.dim("take the record it compares against (Touch ID); look first with tegata scan"))
                }
            case "uninstall":
                CommandLineWatch.uninstall()
                out("Removed the watcher. Its record stays; tegata watch forget removes it too.")
            case "establish":
                let replace = o.flags.contains("--replace")
                // Say so before asking for Touch ID, not after.
                let before = try blocking { await monitor.status(rescan: false) }
                if before.baseline == .present && !replace {
                    out("  " + st.ok("You already have a record, taken \(before.baselineCreatedAt.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? "earlier"). Nothing to do: Tegata is watching."))
                    out("  " + st.shu("›") + " what changed since: " + st.bold("tegata watch status"))
                    out("  " + st.shu("›") + " start over from now: " + st.bold("tegata watch establish --replace") + st.dim(" (Touch ID)"))
                    return Exit.ok.rawValue
                }
                let auth = try blocking { try await TouchID.authorize(reason: replace ? "Tegata will forget its record and trust your agents' configuration as it is now." : "Tegata will trust your agents' configuration as it is now.") }
                try blocking { try await monitor.establish(replace: replace, authorization: auth) }
                let s = try blocking { await monitor.status(rescan: false) }
                out("  " + st.ok("Record taken: \(Render.plural(s.entries, "extension")). From now on, a new or changed hook, MCP server, plugin or skill is reported."))
                out("  " + st.ok("Keys: \(protection)"))
                out("")
                out("  " + st.shu("Next"))
                out("  " + st.shu("›") + " " + st.bold(CommandLineWatch.installed ? "nothing: it is watching" : "tegata watch install") + "   " + st.dim(CommandLineWatch.installed ? "you will get a notification when something changes" : "watch in the background"))
                out("  " + st.shu("›") + " " + st.bold("tegata watch status") + "   " + st.dim("look at the record any time"))
            case "accept":
                let pending = try blocking { await monitor.status(rescan: true) }.changes
                var ids: [String]
                if o.flags.contains("--all") {
                    ids = pending.map(\.extensionId)
                } else {
                    guard !args.isEmpty else { err("tegata: accept needs a name or id from tegata watch status, or --all"); return Exit.usage.rawValue }
                    guard let found = resolve(args, in: pending, many: true, err: err) else { return Exit.usage.rawValue }
                    ids = found
                }
                guard !ids.isEmpty else { out("  " + st.ok("No changes to accept.")); return Exit.ok.rawValue }
                let chosen = ids
                let auth = try blocking { try await TouchID.authorize(reason: "Tegata will keep \(chosen.count) change\(chosen.count == 1 ? "" : "s") to your agents' configuration as part of its record.") }
                try blocking { try await monitor.accept(Set(chosen), authorization: auth) }
                out("  " + st.ok("Kept \(Render.plural(chosen.count, "change")): \(chosen.count == 1 ? "it is" : "they are") part of the record now."))
                describe(try blocking { await monitor.status(rescan: false) }, protection: protection, installed: CommandLineWatch.installed, style: st).forEach(out)
            case "revert", "remove", "quarantine":
                guard args.count == 1, let option = IntegrityRemedy.Option(rawValue: sub) else { err("tegata: \(sub) needs one name or id from tegata watch status"); return Exit.usage.rawValue }
                let pending = try blocking { await monitor.status(rescan: true) }.changes
                guard let id = resolve(args, in: pending, many: false, err: err)?.first else { return Exit.usage.rawValue }
                let auth = try blocking { try await TouchID.authorize(reason: "Tegata will \(sub) one entry of your agents' configuration.") }
                out("  " + st.ok(Render.safe(try blocking { try await monitor.remedy(id, option: option, authorization: auth) })))
            case "restore":
                guard args.count == 1 else { err("tegata: restore needs the stored path from tegata watch quarantined"); return Exit.usage.rawValue }
                try blocking { try await monitor.restore(stored: args[0]) }
                out("restored")
            case "quarantined":
                let rs = Quarantine.records(in: monitor.quarantineDir)
                if rs.isEmpty { out("nothing in quarantine") }
                for r in rs { out("\(r.at.formatted(date: .abbreviated, time: .shortened))  \(Render.shown(r.original, home: home.path))\n    tegata watch restore '\(r.stored)'") }
            case "refresh":
                let auth = try blocking { try await TouchID.authorize(reason: "Tegata was updated and will record how it now reads your agents' configuration.") }
                let n = try blocking { try await monitor.refreshRules(authorization: auth) }
                out("Recorded \(n) entr\(n == 1 ? "y" : "ies") as this version reads them.")
            case "forget":
                guard o.flags.contains("--yes") || ask("Forget the record of your agents' configuration? Changes made until a new one is taken will not be noticed.") else {
                    err("tegata: nothing changed"); return Exit.ok.rawValue
                }
                try blocking { try await monitor.forget() }
                out("Record forgotten.")
            case "run":
                // The background process. Exits quietly if the app took over since it was installed.
                NativeNotifications.prepare()        // the first run asks macOS for permission to notify as Tegata
                let watcher = IntegrityWatcher(monitor: monitor)
                watcher.start()
                dispatchMain()
            default:
                err("tegata: unknown watch command \(sub)"); err("try: tegata help"); return Exit.usage.rawValue
            }
        } catch {
            err("tegata: \(error)")
            return 1
        }
        return Exit.ok.rawValue
    }

    /// `tegata fix remove|quarantine <id>… | --owner <name>`: what a scan reports, not only what changed. One Touch ID
    /// covers the batch either way; with a record, the record follows.
    static func fix(_ o: Options, home: URL, out: (String) -> Void, err: (String) -> Void, ask: (String) -> Bool, presence: Presence) -> Int32 {
        guard let first = o.paths.first, let option = IntegrityRemedy.Option(rawValue: first), option != .revert else {
            err("tegata: fix needs remove or quarantine, then ids (tegata inventory --ids) or --owner <name>"); return Exit.usage.rawValue
        }
        if appIsWatching {
            err("tegata: Tegata.app is watching this Mac; fix from its Extensions tab so its record stays in step"); return Exit.usage.rawValue
        }
        let (monitor, _) = makeMonitor(home: home) { _ in }
        do {
            var ids = Array(o.paths.dropFirst())
            if let owner = o.owner {
                let inv = try blocking { await monitor.inventory() }
                ids = inv.extensions.filter { $0.owner == owner && IntegrityRemedy.options(forEntry: $0).contains(option) }.map(\.id)
                guard !ids.isEmpty else { err("tegata: nothing from \(owner) that can be \(option == .remove ? "removed" : "moved aside")"); return Exit.usage.rawValue }
            }
            guard !ids.isEmpty else { err("tegata: fix needs at least one id"); return Exit.usage.rawValue }
            let what = "\(ids.count) entr\(ids.count == 1 ? "y" : "ies")"
            let hasRecord = try blocking { await monitor.status(rescan: false).baseline == .present }
            let auth: any UnlockAuthorization
            if hasRecord {
                auth = try blocking { try await TouchID.authorize(reason: "Tegata will \(option == .remove ? "remove" : "move aside") \(what) of your agents' configuration (a backup is kept).") }
            } else {
                // No record to unlock, so no Touch ID on the way: ask for it here. --yes skips the question, not the person
                // (before, `fix --yes` let an agent remove hooks on a Mac without a record).
                guard personConfirms(question: "\(option == .remove ? "Remove" : "Move aside") \(what)? A backup of each file is kept next to it.",
                                     reason: "Tegata will \(option == .remove ? "remove" : "move aside") \(what) of your agents' configuration (a backup is kept).",
                                     yes: o.flags.contains("--yes"), ask: ask, presence: presence, err: err) else {
                    err("tegata: nothing changed"); return Exit.ok.rawValue
                }
                auth = ConfirmedAtPrompt()
            }
            let chosen = ids
            out(try blocking { try await monitor.fix(chosen, option: option, authorization: auth) })
            return Exit.ok.rawValue
        } catch {
            err("tegata: \(error)")
            return 1
        }
    }
}
#endif
