import Foundation
import TegataCore

/// Width of the terminal, or a sensible width for pipes and files.
enum Terminal {
    static var width: Int {
        var w = winsize()
        if isatty(STDOUT_FILENO) != 0, ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0, w.ws_col >= 40 { return Int(w.ws_col) }
        return 110
    }

    /// Columns a string takes on screen: escape codes take none, East Asian wide characters take two.
    static func displayWidth(_ s: String) -> Int {
        var n = 0
        var inEscape = false
        for u in s.unicodeScalars {
            if inEscape { if (0x40...0x7E).contains(u.value) && u != "[" { inEscape = false }; continue }
            if u.value == 0x1B { inEscape = true; continue }
            n += isWide(u) ? 2 : 1
        }
        return n
    }

    static func isWide(_ u: Unicode.Scalar) -> Bool {
        switch u.value {
        case 0x1100...0x115F, 0x2E80...0x303E, 0x3041...0x33FF, 0x3400...0x4DBF, 0x4E00...0x9FFF, 0xA000...0xA4CF,
             0xAC00...0xD7A3, 0xF900...0xFAFF, 0xFE30...0xFE4F, 0xFF00...0xFF60, 0xFFE0...0xFFE6, 0x1F300...0x1F64F, 0x1F900...0x1F9FF:
            return true
        default: return false
        }
    }

    /// Cuts plain text to `width` columns, ending in "…" when something was cut.
    static func fit(_ s: String, _ width: Int) -> String {
        guard displayWidth(s) > width, width > 1 else { return s }
        var out = "", used = 0
        for ch in s {
            let w = displayWidth(String(ch))
            if used + w > width - 1 { break }
            out.append(ch); used += w
        }
        return out + "…"
    }
}

/// A table with light rounded borders. Cells are plain text (already made safe); each column may colour its cells
/// after they are measured and padded, so colour never breaks the alignment.
struct Table {
    enum Align { case left, right }
    struct Column {
        var title: String
        var align: Align = .left
        /// Columns that may shrink to fit the terminal, and how narrow they may get.
        var flexible = false
        var minWidth = 6
        var color: ((String) -> String)? = nil
    }
    var columns: [Column]
    var rows: [[String]]

    func render(_ st: Style, indent: Int = 2, maxWidth: Int = Terminal.width) -> [String] {
        guard !columns.isEmpty else { return [] }
        var widths = columns.indices.map { i in
            max(Terminal.displayWidth(columns[i].title), rows.map { i < $0.count ? Terminal.displayWidth($0[i]) : 0 }.max() ?? 0)
        }
        // Shrink the flexible columns, widest first, until the table fits.
        let frame = indent + 1 + columns.count * 3
        while widths.reduce(0, +) + frame > maxWidth {
            guard let i = columns.indices.filter({ columns[$0].flexible && widths[$0] > columns[$0].minWidth }).max(by: { widths[$0] < widths[$1] }) else { break }
            widths[i] -= 1
        }
        let pad = String(repeating: " ", count: indent)
        func border(_ l: String, _ m: String, _ r: String) -> String {
            pad + st.dim(l + widths.map { String(repeating: "─", count: $0 + 2) }.joined(separator: m) + r)
        }
        func cell(_ text: String, _ i: Int, header: Bool) -> String {
            let fitted = Terminal.fit(text, widths[i])
            let space = String(repeating: " ", count: max(0, widths[i] - Terminal.displayWidth(fitted)))
            let padded = columns[i].align == .right ? space + fitted : fitted + space
            if header { return st.bold(padded) }
            return columns[i].color?(padded) ?? padded
        }
        func line(_ cells: [String], header: Bool) -> String {
            pad + st.dim("│") + columns.indices.map { " " + cell($0 < cells.count ? cells[$0] : "", $0, header: header) + " " }.joined(separator: st.dim("│")) + st.dim("│")
        }
        var out = [border("╭", "┬", "╮"), line(columns.map(\.title), header: true), border("├", "┼", "┤")]
        out += rows.map { line($0, header: false) }
        out.append(border("╰", "┴", "╯"))
        return out
    }
}

extension Style {
    /// Colours a padded severity cell by its leading mark ("● critical", "▲ high"…).
    func severityCell(_ s: String) -> String {
        switch s.first {
        case "●": return wrap(s, "1;31")
        case "▲": return red(s)
        case "◆": return yellow(s)
        case "·": return blue(s)
        default: return dim(s)
        }
    }

    /// The command's own line: a small seal, the command, what it does.
    func header(_ command: String, _ what: String) -> [String] {
        ["  " + shu("┃手形┃") + " " + bold(command) + "  " + dim(what), ""]
    }

    /// A section title: small capitals by spacing, the shu accent kept for the seal and "Next".
    func section(_ title: String, _ note: String = "") -> String {
        "  " + bold(title.uppercased()) + (note.isEmpty ? "" : "  " + dim(note))
    }
}

extension RiskSeverity {
    /// "● critical", "▲ high"…: the text form used in tables.
    var label: String {
        switch self {
        case .critical: return "● critical"
        case .high: return "▲ high"
        case .medium: return "◆ medium"
        case .low: return "· low"
        case .info: return "  info"
        }
    }
}
