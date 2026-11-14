import Foundation
import Security

/// Tegata's own entries are not content-hashed (an update would read as "the script changed"); this is what guards
/// them instead. With resources checked, an edited `tegata-guard.sh` (a script bash runs whatever the seal says) fails.
public enum BundleSignature {
    public static func isValid(_ app: URL, team: String) -> Bool {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(app as CFURL, [], &code) == errSecSuccess, let code else { return false }
        var req: SecRequirement?
        let text = "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and identifier \"app.tegata.Tegata\""
        guard SecRequirementCreateWithString(text as CFString, [], &req) == errSecSuccess, let req else { return false }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode)
        return SecStaticCodeCheckValidity(code, flags, req) == errSecSuccess
    }
}
