import Foundation

/// What to do about the secrets a scan found, in order. Copies of one value count once: the same key pasted into forty
/// transcripts is one key to rotate. Rotation comes first because it makes every copy worthless, wherever it is;
/// cleaning the copies comes after. Names, counts and where to rotate; never a value.
/// One file holding copies, and how many.
public struct SecretPlace: Sendable, Equatable {
    public var file: String
    public var copies: Int
}

public struct SecretAction: Sendable, Equatable {
    public enum Urgency: Int, Sendable, Comparable, CaseIterable {
        case now = 0, soon, check, none
        public static func < (a: Urgency, b: Urgency) -> Bool { a.rawValue < b.rawValue }
    }
    public var urgency: Urgency
    public var title: String
    public var rules: [String]
    /// Distinct values (keys to rotate); private keys count once per file.
    public var distinct: Int
    public var copies: Int
    public var files: Int
    /// Variable names the values were assigned to, most frequent first (for generic assignments). Names only.
    public var names: [String]
    public var how: String
    public var rotateAt: String?
    /// Where the copies are, most first.
    public var places: [SecretPlace] = []
}

public enum SecretTriage {
    struct Provider { let title: String; let urgency: SecretAction.Urgency; let how: String; let url: String? }

    static let providers: [String: Provider] = [
        "private-key-block": .init(title: "Private keys", urgency: .now,
            how: "Make a new key pair, put its public half where the old one was trusted (servers, GitHub, deploy keys), then remove the old one.", url: nil),
        "aws-access-key": .init(title: "AWS access keys", urgency: .now,
            how: "Create a new access key for that user, switch to it, then deactivate and delete the old one.", url: "https://console.aws.amazon.com/iam/home#/security_credentials"),
        "anthropic-key": .init(title: "Anthropic API keys and tokens", urgency: .now,
            how: "Create a new key, switch to it, delete the old one. An OAuth token (sk-ant-oat…) is revoked by signing out of Claude Code and in again.", url: "https://console.anthropic.com/settings/keys"),
        "openai-key": .init(title: "OpenAI API keys", urgency: .now, how: "Create a new key, switch to it, revoke the old one.", url: "https://platform.openai.com/api-keys"),
        "openai-legacy-key": .init(title: "OpenAI API keys (older format)", urgency: .now, how: "Create a new key, switch to it, revoke the old one.", url: "https://platform.openai.com/api-keys"),
        "github-token": .init(title: "GitHub tokens", urgency: .now, how: "Regenerate or delete the token; for an app's token, revoke the app's access.", url: "https://github.com/settings/tokens"),
        "github-fine-grained": .init(title: "GitHub fine-grained tokens", urgency: .now, how: "Regenerate or delete the token.", url: "https://github.com/settings/personal-access-tokens"),
        "google-api-key": .init(title: "Google API keys", urgency: .now, how: "Regenerate the key, or delete it and create a restricted one.", url: "https://console.cloud.google.com/apis/credentials"),
        "slack-token": .init(title: "Slack tokens", urgency: .now, how: "Regenerate the token in the app's settings, or revoke the app.", url: "https://api.slack.com/apps"),
        "stripe-key": .init(title: "Stripe keys", urgency: .now, how: "Roll the key; a test key matters less than a live one.", url: "https://dashboard.stripe.com/apikeys"),
        "sendgrid-key": .init(title: "SendGrid keys", urgency: .now, how: "Delete the key and create a new one.", url: "https://app.sendgrid.com/settings/api_keys"),
        "npm-token": .init(title: "npm tokens", urgency: .now, how: "Delete the token on npmjs.com (Access Tokens) and create a new one.", url: "https://www.npmjs.com/"),
        "vercel-token": .init(title: "Vercel tokens", urgency: .now, how: "Delete the token and create a new one.", url: "https://vercel.com/account/tokens"),
        "fly-token": .init(title: "Fly.io tokens", urgency: .now, how: "Revoke it (`fly tokens revoke`) and create a new one.", url: "https://fly.io/user/personal_access_tokens"),
        "hf-token": .init(title: "Hugging Face tokens", urgency: .now, how: "Invalidate and refresh the token.", url: "https://huggingface.co/settings/tokens"),
        "connection-url-with-password": .init(title: "Database and queue passwords in connection URLs", urgency: .soon,
            how: "Change that user's password on the server, then update the URL where the app reads it (ideally from a secret store, not a file).", url: nil),
        "env-schema-sensitive": .init(title: "Values your .env schema marks as sensitive", urgency: .soon,
            how: "Rotate them where they were issued if they are real, then keep them out of plain .env files.", url: nil),
        "secret-assignment": .init(title: "Values assigned to secret-looking names", urgency: .check,
            how: "Not every one is a live secret. For each name you recognise, rotate it where it was issued; ignore test values.", url: nil),
    ]

    public static func plan(_ findings: [SecretFinding], now: Date = Date()) -> [SecretAction] {
        var groups: [String: [SecretFinding]] = [:]
        for f in findings {
            var key = f.rule
            if f.rule == "jwt" { key = f.expiresAt.map { $0 <= now ? "jwt-expired" : "jwt-active" } ?? "jwt-unknown" }
            groups[key, default: []].append(f)
        }
        var out: [SecretAction] = []
        for (key, list) in groups {
            let distinct = Set(list.map { $0.valueID ?? "\($0.file)#\($0.line)" }).count
            let files = Set(list.map(\.file)).count
            var names: [String] = []
            if key == "secret-assignment" || key == "env-schema-sensitive" {
                let counts = Dictionary(grouping: list.compactMap(\.keyName), by: { $0 }).mapValues(\.count)
                names = counts.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }.map(\.key)
            }
            let action: SecretAction
            switch key {
            case "jwt-active":
                let last = list.compactMap(\.expiresAt).max()
                action = SecretAction(urgency: .soon, title: "Session tokens (JWT) still valid", rules: ["jwt"], distinct: distinct, copies: list.count, files: files, names: [],
                    how: "Sign out of the service that issued them, or revoke them there\(last.map { "; the last one expires \($0.formatted(date: .abbreviated, time: .omitted))" } ?? "").", rotateAt: nil)
            case "jwt-unknown":
                action = SecretAction(urgency: .check, title: "Tokens (JWT) with no expiry", rules: ["jwt"], distinct: distinct, copies: list.count, files: files, names: [],
                    how: "A token without an expiry stays valid until it is revoked: revoke it where it was issued if you recognise it.", rotateAt: nil)
            case "jwt-expired":
                action = SecretAction(urgency: .none, title: "Expired tokens (JWT)", rules: ["jwt"], distinct: distinct, copies: list.count, files: files, names: [],
                    how: "Already expired; nothing to rotate. Clean the copies when convenient.", rotateAt: nil)
            default:
                let p = providers[key] ?? Provider(title: key, urgency: .check, how: "Rotate it where it was issued if it is real.", url: nil)
                action = SecretAction(urgency: p.urgency, title: p.title, rules: [key], distinct: distinct, copies: list.count, files: files,
                                      names: names, how: p.how, rotateAt: p.url)
            }
            var placed = action
            placed.places = Dictionary(grouping: list, by: \.file).map { SecretPlace(file: $0.key, copies: $0.value.count) }
                .sorted { $0.copies != $1.copies ? $0.copies > $1.copies : $0.file < $1.file }
            out.append(placed)
        }
        return out.sorted { a, b in a.urgency != b.urgency ? a.urgency < b.urgency : (a.distinct != b.distinct ? a.distinct > b.distinct : a.title < b.title) }
    }
}
