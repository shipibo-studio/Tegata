import Foundation
import TegataCore

/// How output looks. Colour and motion only for a person at a terminal: never in a pipe, a file, CI, with `NO_COLOR`,
/// `TERM=dumb` or `--no-color`. What is printed is the same text either way, so a pasted report never carries escape
/// codes, and every symbol has a word next to it for people who do not see colour.
public struct Style: Sendable {
    public var color: Bool
    /// Spinners and the stamp, on standard error only.
    public var motion: Bool
    var truecolor: Bool

    public static let plain = Style(color: false, motion: false, truecolor: false)

    /// For the real command: decided from the process's terminals and environment.
    public static func detect(arguments: [String] = CommandLine.arguments, environment: [String: String] = ProcessInfo.processInfo.environment) -> Style {
        let tty = isatty(STDOUT_FILENO) != 0
        let ttyErr = isatty(STDERR_FILENO) != 0
        let dumb = environment["TERM"] == "dumb"
        let ci = environment["CI"] != nil
        let off = environment["NO_COLOR"] != nil || arguments.contains("--no-color") || dumb
        let forced = environment["FORCE_COLOR"].map { $0 != "0" } ?? false
        let colorTerm = (environment["COLORTERM"] ?? "").lowercased()
        return Style(color: !off && (tty || forced), motion: !off && !ci && ttyErr && tty,
                     truecolor: colorTerm == "truecolor" || colorTerm == "24bit")
    }

    func wrap(_ s: String, _ code: String) -> String { color ? "\u{1B}[\(code)m\(s)\u{1B}[0m" : s }

    // The brand's one accent: shu, the seal's vermilion (#e14d2a). Used sparingly.
    public func shu(_ s: String) -> String { wrap(s, truecolor ? "38;2;225;77;42" : "38;5;202") }
    public func bold(_ s: String) -> String { wrap(s, "1") }
    public func dim(_ s: String) -> String { wrap(s, "2") }
    public func green(_ s: String) -> String { wrap(s, "32") }
    public func yellow(_ s: String) -> String { wrap(s, "33") }
    public func blue(_ s: String) -> String { wrap(s, "34") }
    public func red(_ s: String) -> String { wrap(s, "31") }

    /// "● critical", "▲ high", "◆ medium", "· low", "  info": a shape and a word, coloured when colour is on.
    public func severity(_ s: RiskSeverity?, width: Int = 10) -> String {
        guard let s else { return String(repeating: " ", count: width) }
        let (mark, word): (String, String)
        switch s {
        case .critical: (mark, word) = ("●", "critical")
        case .high: (mark, word) = ("▲", "high")
        case .medium: (mark, word) = ("◆", "medium")
        case .low: (mark, word) = ("·", "low")
        case .info: (mark, word) = (" ", "info")
        }
        let text = "\(mark) \(word)"
        let padded = text.count >= width ? text + " " : text.padding(toLength: width, withPad: " ", startingAt: 0)
        switch s {
        case .critical: return wrap(padded, "1;31")
        case .high: return red(padded)
        case .medium: return yellow(padded)
        case .low: return blue(padded)
        case .info: return dim(padded)
        }
    }

    public func urgency(_ u: SecretAction.Urgency) -> String {
        switch u {
        case .now: return wrap("● now  ", "1;31")
        case .soon: return yellow("▲ soon ")
        case .check: return blue("◆ check")
        case .none: return green("✓ done ")
        }
    }

    public func heading(_ s: String) -> String { bold(s) }
    public func ok(_ s: String) -> String { green("✓ ") + s }
}

/// The wordmark: a seal with 手形 and TEGATA in block letters. Plain text without colour, so it also reads in a log.
enum Banner {
    static let seal = ["┏━━━━┓", "┃手形┃", "┗━━━━┛"]
    static let word = ["▀█▀ █▀▀ █▀▀ ▄▀█ ▀█▀ ▄▀█", " █  ██▄ █▄█ █▀█  █  █▀█"]

    static func lines(_ st: Style, version: String, tagline: String) -> [String] {
        [
            "  \(st.shu(seal[0]))  \(st.bold(word[0]))",
            "  \(st.shu(seal[1]))  \(st.bold(word[1]))",
            "  \(st.shu(seal[2]))  \(st.dim("v\(version)")) · \(tagline)",
        ]
    }

    /// The seal is stamped, in about six tenths of a second, terminal only: the name types in next to an empty seal,
    /// then 手形 lands in shu with a one-beat inverse flash, like a stamp lifting. Drawn on standard error and
    /// cleared, so standard output carries only the final banner.
    static func stamp(_ st: Style, version: String, tagline: String) {
        guard st.motion else { return }
        let err = FileHandle.standardError
        func put(_ s: String) { err.write(Data(s.utf8)) }
        func frame(letters: Int, seal: String, tag: Bool) {
            let cut = { (line: String) -> String in String(line.prefix(letters * 4)) }
            put("  \(seal == "empty" ? st.dim(Banner.seal[0]) : st.shu(Banner.seal[0]))  \(st.bold(cut(word[0])))\u{1B}[K\n")
            let middle: String
            switch seal {
            case "empty": middle = st.dim("┃    ┃")
            case "flash": middle = st.wrap(Banner.seal[1], "7;1") // inverse: the stamp pressed down
            default: middle = st.shu(Banner.seal[1])
            }
            put("  \(middle)  \(st.bold(cut(word[1])))\u{1B}[K\n")
            put("  \(seal == "empty" ? st.dim(Banner.seal[2]) : st.shu(Banner.seal[2]))  \(tag ? "\(st.dim("v\(version)")) · \(tagline)" : "")\u{1B}[K\n")
            put("\u{1B}[3A")
        }
        put("\u{1B}[?25l")                                   // hide the cursor while drawing
        for k in 0...6 { frame(letters: k, seal: "empty", tag: false); usleep(55_000) }
        frame(letters: 6, seal: "flash", tag: false); usleep(110_000)
        frame(letters: 6, seal: "shu", tag: false); usleep(90_000)
        frame(letters: 6, seal: "shu", tag: true); usleep(70_000)
        put("\u{1B}[J\u{1B}[?25h")                          // clear what was drawn, show the cursor
    }
}

/// A spinner with a counter on standard error, for work that takes seconds (an Exposure scan reads every transcript).
final class Spinner: @unchecked Sendable {
    private let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    private let lock = NSLock()
    private var label: String
    private var count = 0
    private var running = false
    private let style: Style
    private var thread: Thread?

    init(_ label: String, style: Style) { self.label = label; self.style = style }

    func start() {
        guard style.motion else { return }
        lock.withLock { running = true }
        let t = Thread { [weak self] in
            var i = 0
            while let self, self.lock.withLock({ self.running }) {
                let (text, n) = self.lock.withLock { (self.label, self.count) }
                let line = "\r\u{1B}[2K  \(self.style.shu(self.frames[i % self.frames.count])) \(text)\(n > 0 ? self.style.dim(" · \(n) files") : "")"
                FileHandle.standardError.write(Data(line.utf8))
                i += 1
                usleep(80_000)
            }
        }
        thread = t
        t.start()
    }

    func update(_ n: Int) { lock.withLock { count = n } }
    func relabel(_ s: String) { lock.withLock { label = s } }

    func stop() {
        guard style.motion else { return }
        lock.withLock { running = false }
        usleep(90_000)
        FileHandle.standardError.write(Data("\r\u{1B}[2K".utf8))
    }
}
