import Foundation
import Darwin
import UserNotifications

/// The command line's own LaunchAgent for `tegata watch run`, and the checks around it. Only one watcher may run on a
/// Mac: when Tegata.app's agent is there, the command line defers to it.
public enum CommandLineWatch {
    public static let label = "app.tegata.cli-watch"
    public static let appAgentLabel = "app.tegata.tegatad"

    static var uid: String { String(getuid()) }
    public static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    /// The real path of this executable (through any symlink), so launchd starts the copy inside the signed bundle.
    public static var executablePath: String {
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let n = proc_pidpath(getpid(), &buf, UInt32(buf.count))
        return n > 0 ? String(cString: buf) : CommandLine.arguments[0]
    }

    @discardableResult
    static func launchctl(_ args: [String]) -> (status: Int32, output: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe; p.standardError = pipe
        do { try p.run() } catch { return (-1, "\(error)") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    public static func isLoaded(_ label: String) -> Bool { launchctl(["print", "gui/\(uid)/\(label)"]).status == 0 }
    public static var appIsWatching: Bool { isLoaded(appAgentLabel) }
    public static var installed: Bool { FileManager.default.fileExists(atPath: plistURL.path) }

    /// The program the installed LaunchAgent runs, if any (to tell when an upgrade moved the binary).
    public static var installedProgram: String? {
        guard let d = FileManager.default.contents(atPath: plistURL.path),
              let p = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any] else { return nil }
        return (p["ProgramArguments"] as? [String])?.first
    }

    public static func install(logDirectory: URL) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: plistURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try fm.createDirectory(at: logDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [executablePath, "watch", "run"],
            "RunAtLoad": true,
            "KeepAlive": ["SuccessfulExit": false],
            "ProcessType": "Background",
            "StandardErrorPath": logDirectory.appendingPathComponent("watch.log").path,
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try data.write(to: plistURL, options: [.atomic])
        launchctl(["bootout", "gui/\(uid)/\(label)"])
        let r = launchctl(["bootstrap", "gui/\(uid)", plistURL.path])
        guard r.status == 0 else { throw CocoaError(.fileWriteUnknown, userInfo: [NSLocalizedDescriptionKey: "launchctl bootstrap failed: \(r.output)"]) }
    }

    public static func uninstall() {
        launchctl(["bootout", "gui/\(uid)/\(label)"])
        try? FileManager.default.removeItem(at: plistURL)
    }

    /// A notification: Tegata's own when running from its bundle and allowed, else through osascript (shown as
    /// Script Editor). The text is already redacted.
    public static func notify(title: String, message: String) {
        if NativeNotifications.post(title: title, message: message) { return }
        func q(_ s: String) -> String { "\"" + s.prefix(400).replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\"" }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", "display notification \(q(message)) with title \(q(title))"]
        try? p.run()
    }
}

/// Notifications with Tegata's own name and icon. Only a process running from inside its app bundle can use the
/// system's notification centre (the background watcher is launched by launchd from the bundle's real path); a build
/// from source, or a command run through a symlink, falls back to osascript.
public enum NativeNotifications {
    static var available: Bool {
        Bundle.main.bundleIdentifier != nil && Bundle.main.bundleURL.pathExtension == "app"
    }

    /// Asks once for permission; macOS shows "Tegata CLI would like to send notifications" the first time.
    public static func prepare() {
        guard available else { return }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    /// Posts and returns true when the user allowed notifications for Tegata; false means use the fallback.
    public static func post(title: String, message: String) -> Bool {
        guard available else { return false }
        let center = UNUserNotificationCenter.current()
        let done = DispatchSemaphore(value: 0)
        final class Flag: @unchecked Sendable { var allowed = false }
        let flag = Flag()
        center.getNotificationSettings { s in
            flag.allowed = s.authorizationStatus == .authorized || s.authorizationStatus == .provisional
            done.signal()
        }
        _ = done.wait(timeout: .now() + 2)
        guard flag.allowed else { return false }
        let content = UNMutableNotificationContent()
        content.title = String(title.prefix(120))
        content.body = String(message.prefix(400))
        content.sound = .default
        center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
        return true
    }
}
