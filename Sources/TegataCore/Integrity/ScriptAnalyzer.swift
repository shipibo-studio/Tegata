import Foundation

/// What a script or a command line does, found by fixed rules over its text. No model, no network, nothing run:
/// the same text always gives the same traits. It reads text that is about to be run on the user's behalf, so it
/// is cautious in both directions: a pattern has to be clear to count, and a comment is not code.
public enum ScriptTrait: String, Sendable, Codable, CaseIterable, Comparable {
    /// Fetches something from the network and runs it (`curl … | sh`, `eval "$(curl …)"`, a download followed by
    /// `chmod +x`, a fetch handed to `exec`).
    case downloadsAndRuns = "downloads-and-runs"
    /// Decodes a hidden payload and runs it (`base64 -d | sh`, `exec(b64decode(…))`).
    case executesDecodedPayload = "executes-decoded-payload"
    /// A long run of encoded text, the usual way to carry a payload in a script.
    case encodedBlob = "encoded-blob"
    /// Names credential stores (`~/.ssh`, `~/.aws`, `security find-generic-password`, `cat .env`).
    case readsCredentials = "reads-credentials"
    /// Can open a connection (`curl`, `nc`, `requests.post`, `/dev/tcp/…`) to somewhere off this Mac, or somewhere the
    /// text does not say (`curl $URL`).
    case networkOut = "network-out"
    /// Opens connections, and every one of them names this Mac (`localhost`, `127.0.0.1`, `::1`, a Unix socket): the
    /// usual way a terminal or editor app hears from its own hooks. What listens there still gets what is sent.
    case networkLoopback = "network-loopback"
    /// Installs itself to run later (LaunchAgents, cron, shell startup files).
    case persistence
    /// Writes to another agent's configuration (`~/.claude/settings.json`, `~/.codex/config.toml`).
    case modifiesAgentConfig = "modifies-agent-config"
    /// Deletes the home folder or the root (`rm -rf ~`).
    case destructive

    public static func < (a: ScriptTrait, b: ScriptTrait) -> Bool { a.rawValue < b.rawValue }
}

public enum ScriptAnalyzer {
    /// A script is read up to this many bytes, and a line up to this many characters; the rest is not looked at.
    /// A hostile file must not make the rules run for long.
    public static let maxBytes = 256 * 1024
    static let maxLine = 4_000

    /// Fetchers that matter in the rules below.
    private static let fetch = #"(?:curl|wget|aria2c)\b"#
    private static let shell = #"(?:sudo\s+)?(?:ba|z|da|k|c|tc|fi)?sh\b|python[0-9.]*\b|node\b|perl\b|ruby\b|php\b|osascript\b"#

    private static func rx(_ p: String) -> NSRegularExpression { try! NSRegularExpression(pattern: p, options: [.caseInsensitive]) }

    // Each rule is applied to one line at a time, so a pattern can never span the whole file.
    static let pipeToInterpreter = rx(#"\b\#(fetch)[^\n|;&]{0,600}\|\s*(?:\#(shell))"#)
    static let processSubstitution = rx(#"\b(?:\#(shell))\s*(?:-[a-z]+\s+)*<\(\s*\#(fetch)|\b(?:source|\.)\s+<\(\s*\#(fetch)"#)
    static let evalOfFetch = rx(#"\beval\b[^\n]{0,40}(?:\$\(|`)\s*\#(fetch)"#)
    /// Where a fetch writes its output: `-o file`, `-sSLo file`, `-O file`, `--output file`, or `> file`. Output sent
    /// to `/dev/null`, to stdout (`-O-`) or to another descriptor (`2>&1`) is not a saved download.
    static let fetchTargetFlag = rx(#"\b\#(fetch)[^\n]{0,400}?\s-[A-Za-z]*[oO]\s+(?!/dev/null\b|-)(["']?)([^\s"'|;&]+)|\b\#(fetch)[^\n]{0,400}?--(?:output|output-document)[ =](?!/dev/null\b)(["']?)([^\s"'|;&]+)"#)
    static let fetchTargetRedirect = rx(#"\b\#(fetch)[^\n|]{0,400}?[^0-9&>]>\s?(?!/dev/null|&)(["']?)([^\s"'|;&]+)"#)
    /// Makes a file executable for others too (`+x`, 755, 775, 777). `chmod 700` and `600` harden a file; they are
    /// not what a download does next.
    static let chmodExec = rx(#"\bchmod\s+(?:-[A-Za-z]+\s+)*(?:[ugoa]*\+x[A-Za-z]*|0?(?:7[5-7][0-7]|[75]55|777))\s+(["']?)([^\s"'|;&]+)"#)
    /// `exec(urllib…urlopen(…).read())`, and `x = urlopen(…).read()` followed by `exec(x)`.
    static let pythonFetchExecInline = rx(#"\b(?:exec|eval)\s*\([^\n]{0,200}(?:urlopen|requests\.get)"#)
    static let pythonFetchAssign = rx(#"\b([A-Za-z_]\w*)\s*=\s*[^\n]{0,200}(?:urlopen|requests\.get)[^\n]{0,200}\.(?:read|text|content)"#)

    static let decodeToShell = rx(#"\bbase64\s+(?:-d\b|--decode\b|-D\b)[^\n]{0,200}\|\s*(?:\#(shell))"#)
    static let decodedExec = rx(#"\b(?:exec|eval|compile)\s*\([^\n]{0,120}(?:b64decode|base64\.|atob\s*\(|fromCharCode|unhexlify|bytes\.fromhex|decode\s*\()"#)
    static let echoDecodeRun = rx(#"\becho\s+["']?[A-Za-z0-9+/=]{40,}["']?\s*\|\s*base64\s+(?:-d|--decode|-D)"#)
    static let blob = rx(#"[A-Za-z0-9+/]{200,}={0,2}"#)

    /// Credential locations. Naming one is not reading one (`ssh -i ~/.ssh/id_ed25519 host` is ordinary use), so a path only
    /// counts after a verb that reads or moves a file; `security find-generic-password` and friends count on their own.
    private static let endOfPath = #"(?=[\s"'*|;&)]|$)"#
    private static let credentialPath = #"(?:~|\$HOME|\$\{HOME\}|/Users/[^/\s]+)?/?\.(?:ssh(?:/id_|/?\#(endOfPath))|aws(?:/(?:credentials|sso)|/?\#(endOfPath))|gnupg(?:/|\#(endOfPath))|kube(?:/config|/?\#(endOfPath))|config/gcloud(?:/|/?\#(endOfPath))|azure(?:/|/?\#(endOfPath))|docker/config\.json|netrc\b|npmrc\b|pypirc\b|git-credentials\b|claude\.json\b|claude/\.credentials\.json|codex/auth\.json|gemini/oauth_creds\.json|local/share/opencode/auth\.json)|Library/Keychains|login\.keychain"#
    private static let readVerb = #"(?:\b(?:cat|head|tail|less|more|cp|mv|tar|zip|gzip|base64|xxd|openssl|scp|rsync|sftp|curl|wget|source|grep|strings|dd|nc|jq|open|readFileSync|read_text|python[0-9.]*|node|ruby|perl)\b|<)"#
    static let credentialRead = rx(#"\#(readVerb)[^\n]{0,300}(?:\#(credentialPath))"#)
    static let keychainCommand = rx(#"\bsecurity\s+(?:find|dump|export|unlock|add)-"#)
    static let readsDotEnv = rx(#"\b(?:cat|source|\.|grep|head|tail|less|more|cp|tar|zip|scp|rsync|base64|xxd|openssl)\s+[^|;&\n]{0,200}\.env(?:\.[a-z]+)?\b"#)
    static let envDump = rx(#"(?:^|[|;&]\s*)(?:printenv|env|set|export\s+-p)\s*(?:\||>|$)"#)

    static let network = rx(#"(?:^|[\s|;&(`])(?:curl|wget|nc|ncat|socat|scp|sftp|rsync|ftp|telnet|ssh)\s|requests\.(?:post|put|get)|urllib|http\.client|\bfetch\s*\(|XMLHttpRequest|\bnet\.connect|https?\.request|/dev/tcp/|Invoke-WebRequest|\bwebsocket\b"#)

    static let persistence = rx(#"LaunchAgents|LaunchDaemons|launchctl\s+(?:load|bootstrap|submit|enable)|\bcrontab\s+(?:-|[a-z0-9./~])|>>?\s*(?:~|\$HOME|\$\{HOME\})?/?\.(?:zshrc|zprofile|zshenv|bashrc|bash_profile|profile)\b|\blaunchd\b[^\n]{0,40}\.plist"#)
    static let agentConfigPath = rx(#"\.claude/settings(?:\.local)?\.json|\.claude\.json|\.codex/config\.toml|\.cursor/mcp\.json|\.gemini/settings\.json|claude_desktop_config\.json"#)
    static let writeVerb = rx(#"(?:>>?|\btee\b|\bsed\s+-i|\bjq\b[^\n]{0,200}>|json\.dump|writeFile|write_text|open\([^)]*['"]w|\bmv\b|\bcp\b)"#)
    static let destructive = rx(#"\brm\s+(?:-[a-z]*r[a-z]*f?[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s+(?:--\s+)?(?:["']?(?:~|\$HOME|\$\{HOME\})["']?/?\s*(?:$|[;&|])|/\s*(?:$|[;&|])|/\*)"#)

    // Where a network line goes. A line is local only when it names a host and every host it names is this Mac; a line
    // with two network calls, or a host it does not spell out, counts as going out.
    static let urlHost = rx(#"\b(?:https?|wss?)://(\[[0-9a-f:]+\]|[^/\s:'"`$@]+)(?=[:/\s'"`]|$)"#)
    static let devTcpHost = rx(#"/dev/tcp/([^/\s]+)/"#)
    static let unixSocket = rx(#"--unix-socket\b|\bunix://"#)
    static let bareLoopback = rx(#"(?:^|[\s'"@=(])(localhost|127(?:\.[0-9]{1,3}){3}|\[::1\]|::1|0\.0\.0\.0)(?::[0-9]+)?(?=[/\s'"),]|$)"#)
    static let domainToken = rx(#"(?<![\w./@-])(?:[a-z0-9-]+\.)+([a-z]{2,})(?![\w.-])"#)
    static let fileExtensions: Set<String> = ["json", "js", "mjs", "cjs", "ts", "py", "sh", "zsh", "bash", "txt", "log", "md", "yml", "yaml", "toml", "plist", "lock", "pid", "sock"]

    public static func isLoopback(_ host: String) -> Bool {
        let h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if h == "localhost" || h.hasSuffix(".localhost") || h == "::1" || h == "0.0.0.0" { return true }
        let parts = h.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts[0] == "127" && parts.allSatisfy { UInt8($0) != nil }
    }

    /// true when the line's connections all stay on this Mac; false otherwise, including when it cannot tell.
    public static func staysOnThisMac(_ line: String) -> Bool {
        let ns = line as NSString
        guard network.numberOfMatches(in: line, range: NSRange(location: 0, length: ns.length)) <= 1 else { return false }
        // `curl --unix-socket` talks to the socket whatever host its URL names.
        if hit(unixSocket, line) { return true }
        let hosts = captures(urlHost, line, groups: [1]).union(captures(devTcpHost, line, groups: [1]))
        // A name that looks like a domain and is not a file and not one of the hosts above: an unnamed destination.
        let domains = domainToken.matches(in: line, range: NSRange(location: 0, length: ns.length)).filter { m in
            let tld = ns.substring(with: m.range(at: 1)).lowercased()
            let whole = ns.substring(with: m.range).lowercased()
            return !fileExtensions.contains(tld) && !hosts.contains(where: { $0.lowercased() == whole }) && !isLoopback(whole)
        }
        if !domains.isEmpty { return false }
        if !hosts.isEmpty { return hosts.allSatisfy(isLoopback) }
        return !captures(bareLoopback, line, groups: [1]).isEmpty
    }

    static func captures(_ r: NSRegularExpression, _ line: String, groups: [Int]) -> Set<String> {
        var out = Set<String>()
        let ns = line as NSString
        for m in r.matches(in: line, range: NSRange(location: 0, length: ns.length)) {
            for g in groups where g < m.numberOfRanges && m.range(at: g).location != NSNotFound { out.insert(ns.substring(with: m.range(at: g))) }
        }
        return out
    }

    static func hit(_ r: NSRegularExpression, _ line: String) -> Bool {
        r.firstMatch(in: line, range: NSRange(location: 0, length: (line as NSString).length)) != nil
    }

    /// Traits of a command line or script text. Comment-only lines are skipped (`#`, `//`, but not `#!`).
    public static func analyze(_ text: String) -> Set<ScriptTrait> {
        let bounded = text.utf8.count > maxBytes ? String(decoding: Array(text.utf8.prefix(maxBytes)), as: UTF8.self) : text
        var out = Set<ScriptTrait>()
        var fetched = Set<String>(), chmodded = Set<String>(), fetchVars = Set<String>()
        var cleaned: [String] = []
        var remote = false, local = false

        for raw in bounded.split(separator: "\n", omittingEmptySubsequences: true) {
            var line = String(raw.prefix(maxLine))
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if (trimmed.hasPrefix("#") && !trimmed.hasPrefix("#!")) || trimmed.hasPrefix("//") { continue }
            // A trailing `# comment` is cut so `echo ok # curl x | sh` is not read as code.
            if let r = line.range(of: " #") , !line[..<r.lowerBound].contains("'"), !line[..<r.lowerBound].contains("\"") { line = String(line[..<r.lowerBound]) }

            if hit(pipeToInterpreter, line) || hit(processSubstitution, line) || hit(evalOfFetch, line) { out.insert(.downloadsAndRuns) }
            fetched.formUnion(captures(fetchTargetFlag, line, groups: [2, 5]))
            fetched.formUnion(captures(fetchTargetRedirect, line, groups: [2]))
            chmodded.formUnion(captures(chmodExec, line, groups: [2]))
            if hit(pythonFetchExecInline, line) { out.insert(.downloadsAndRuns) }
            if fetchVars.count < 8 { fetchVars.formUnion(captures(pythonFetchAssign, line, groups: [1])) }
            if !fetchVars.isEmpty { cleaned.append(line) }

            if hit(decodeToShell, line) || hit(decodedExec, line) || hit(echoDecodeRun, line) { out.insert(.executesDecodedPayload) }
            if hit(blob, line) { out.insert(.encodedBlob) }

            if hit(credentialRead, line) || hit(keychainCommand, line) || hit(readsDotEnv, line) || hit(envDump, line) { out.insert(.readsCredentials) }
            if hit(network, line) { if staysOnThisMac(line) { local = true } else { remote = true } }
            if hit(persistence, line) { out.insert(.persistence) }
            if hit(agentConfigPath, line), hit(writeVerb, line) { out.insert(.modifiesAgentConfig) }
            if hit(destructive, line) { out.insert(.destructive) }
        }
        // Two-step forms that no single line shows, tied together by the name they share: the file a fetch wrote is the
        // file that was made executable; the variable a fetch filled is the one handed to exec or eval.
        if !fetched.isDisjoint(with: chmodded) || fetched.contains(where: { f in chmodded.contains { ($0 as NSString).lastPathComponent == (f as NSString).lastPathComponent && !($0 as NSString).lastPathComponent.isEmpty } }) {
            out.insert(.downloadsAndRuns)
        }
        for v in fetchVars where cleaned.contains(where: { hit(rx(#"\b(?:exec|eval)\s*\(\s*(?:compile\s*\()?(?:[A-Za-z_.]*\.)?\#(NSRegularExpression.escapedPattern(for: v))\b"#), $0) }) {
            out.insert(.downloadsAndRuns)
        }
        if remote || out.contains(.downloadsAndRuns) { out.insert(.networkOut) } else if local { out.insert(.networkLoopback) }
        return out
    }
}
