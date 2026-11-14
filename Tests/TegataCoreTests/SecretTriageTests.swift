import Testing
import Foundation
@testable import TegataCore

@Suite struct SecretTriageTests {
    // Synthetic values in real shapes; none works anywhere.
    let key = "sk-ant-api03-TestOnlyNotARealKeyZZZZ0123456789abcdefghijkl"
    let other = "sk-ant-api03-TestOnlyAnotherFakeKeyYYYY9876543210zyxwvutsr"

    func jwt(exp: TimeInterval?) -> String {
        func b64(_ s: String) -> String { Data(s.utf8).base64EncodedString().replacingOccurrences(of: "=", with: "").replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_") }
        let payload = exp.map { #"{"sub":"test-only","exp":\#(Int($0))}"# } ?? #"{"sub":"test-only"}"#
        return b64(#"{"alg":"HS256","typ":"JWT"}"#) + "." + b64(payload) + ".c2lnbmF0dXJlVGVzdE9ubHlOb3RSZWFs"
    }

    func scan(_ files: [String: String]) -> [SecretFinding] {
        files.flatMap { SecretDetector().scan(text: $0.value, file: $0.key, source: .agentTranscript) }
    }

    @Test func copiesOfOneKeyCountAsOneKeyToRotate() {
        let f = scan(["/a": "export ANTHROPIC_API_KEY=\(key)", "/b": "key is \(key)", "/c": "and \(key) again\nplus \(other)"])
        let plan = SecretTriage.plan(f)
        let anthropic = try! #require(plan.first { $0.rules == ["anthropic-key"] })
        #expect(anthropic.distinct == 2 && anthropic.copies == 4 && anthropic.files == 3)
        #expect(anthropic.urgency == .now && anthropic.rotateAt != nil)
    }

    @Test func valueIDsMatchWithinARunAndCarryNoValue() {
        let f = scan(["/a": key, "/b": key])
        #expect(f.count == 2 && f[0].valueID == f[1].valueID && f[0].valueID != nil)
        #expect(!(f[0].valueID ?? "").contains("sk-ant"))
        #expect(f[0].valueID?.count == 24)
    }

    @Test func expiredTokensNeedNothingAndLiveOnesComeFirst() {
        let now = Date(timeIntervalSince1970: 1_900_000_000)
        let f = scan(["/a": "token \(jwt(exp: 1_800_000_000))", "/b": "token \(jwt(exp: 2_000_000_000))", "/c": "token \(jwt(exp: nil))"])
        #expect(f.compactMap(\.expiresAt).count == 2)
        let plan = SecretTriage.plan(f, now: now)
        #expect(plan.contains { $0.title.hasPrefix("Expired") && $0.urgency == .none })
        #expect(plan.contains { $0.title.contains("still valid") && $0.urgency == .soon })
        #expect(plan.contains { $0.title.contains("no expiry") && $0.urgency == .check })
        #expect(plan.last?.urgency == SecretAction.Urgency.none)
    }

    @Test func privateKeysCountPerFileAndComeFirst() {
        let block = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
        let f = scan(["/a": block, "/b": block, "/c": "DB_PASSWORD=Zq8vTestOnly4kL2mN7pR"])
        let plan = SecretTriage.plan(f)
        #expect(plan.first?.rules == ["private-key-block"] && plan.first?.distinct == 2)
        let generic = try! #require(plan.first { $0.rules == ["secret-assignment"] })
        #expect(generic.names == ["DB_PASSWORD"] && generic.urgency == .check)
    }
}
