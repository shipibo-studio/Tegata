import Foundation

/// The version of the rules that turn configuration into fingerprints and digests. Bump it whenever a change to the
/// scanner, the parsers or the digester can change a fingerprint for an entry that did not change, so an updated Tegata
/// tells "I read this differently now" apart from "this was edited" (see `IntegrityDiffer`).
///
/// History: 1 = first baselines (2026-10-24). 2 = runtime markers skipped in folder digests, marketplace timestamps
/// ignored, `entryHash` recorded (2026-10-25). 3 = an MCP server's `headersHelper` script is hashed and read
/// (2026-11-01); only servers that have one get a new fingerprint. 4 = other Claude Code config roots
/// (`CLAUDE_CONFIG_DIR`, apps such as MonoCode) are read (2026-11-11); their entries appear as possibly pre-existing.
public enum IntegrityRules {
    public static let version = 4
    /// A baseline written before versions were recorded.
    public static let unversioned = 1
}

/// Why a change may come from a Tegata update rather than from an edit.
public enum RulesAttribution: String, Codable, Sendable {
    /// The entry as written is byte-for-byte what the baseline recorded; only Tegata's reading of it changed.
    case explained
    /// Nothing recorded can tell (a file-based entry, or a baseline from before entry hashes): shown, not interrupted.
    case possible
}
