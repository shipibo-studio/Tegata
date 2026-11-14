import Testing
import Foundation
@testable import TegataCore

/// Files written the way Claude Code writes them: `JSON.stringify(value, null, 2)` plus, or minus, a final newline.
@Suite struct OrderedJSONTests {
    let stringified = """
    {
      "zeta": 1,
      "model": "opus",
      "env": {
        "B_VAR": "x",
        "A_VAR": "caf\\u00e9 \\"q\\" \\\\ /"
      },
      "numbers": [
        1.0,
        1e3,
        -0.5,
        12345678901234567890
      ],
      "empty": {},
      "none": [],
      "flag": true,
      "nothing": null,
      "hooks": {
        "Stop": [
          {
            "hooks": [
              {
                "type": "command",
                "command": "echo hi"
              }
            ]
          }
        ]
      }
    }
    """

    func edit(_ text: String, _ change: (inout [String: Any]) -> Void) throws -> String {
        var obj = try #require(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
        change(&obj)
        let edited = try ClaudeSettingsEditor.serialize(obj)          // sorted keys, as every editor produces
        return String(decoding: OrderedJSON.restyle(edited, like: Data(text.utf8)), as: UTF8.self)
    }

    @Test func anUnchangedDocumentComesBackByteForByte() throws {
        for text in [stringified, stringified + "\n"] {
            #expect(try edit(text) { _ in } == text)
        }
    }

    @Test func anEditChangesOnlyItsOwnLines() throws {
        let out = try edit(stringified + "\n") { $0["apiKeyHelper"] = "/Applications/Tegata.app/Contents/MacOS/tegata-token" }
        let before = (stringified + "\n").split(separator: "\n", omittingEmptySubsequences: false)
        let after = out.split(separator: "\n", omittingEmptySubsequences: false)
        // The new key goes last; the previous last line gains a comma; nothing else moves.
        #expect(after.count == before.count + 1)
        #expect(Array(after.prefix(before.count - 3)) == Array(before.prefix(before.count - 3)))
        #expect(after[after.count - 3] == "  \"apiKeyHelper\": \"/Applications/Tegata.app/Contents/MacOS/tegata-token\"")
        // Removing it again restores the original exactly.
        #expect(try edit(out) { $0.removeValue(forKey: "apiKeyHelper") } == stringified + "\n")
    }

    @Test func keyOrderSurvivesAnEditDeepInside() throws {
        let out = try edit(stringified) { o in
            var env = o["env"] as! [String: Any]; env["C_VAR"] = "new"; o["env"] = env
        }
        let keys = out.split(separator: "\n").filter { $0.hasPrefix("    \"") && $0.contains("_VAR") }.map { String($0.split(separator: "\"")[1]) }
        #expect(keys == ["B_VAR", "A_VAR", "C_VAR"])
        #expect(out.contains("\"zeta\": 1,\n  \"model\""))                  // top-level order kept too
    }

    @Test func otherIndentsAndCompactFilesKeepTheirStyle() throws {
        let four = "{\n    \"b\": 1,\n    \"a\": [\n        2\n    ]\n}"
        #expect(try edit(four) { _ in } == four)
        #expect(try edit(four) { $0["c"] = true } == "{\n    \"b\": 1,\n    \"a\": [\n        2\n    ],\n    \"c\": true\n}")
        let tabs = "{\n\t\"b\": 1\n}\n"
        #expect(try edit(tabs) { $0["a"] = "x" } == "{\n\t\"b\": 1,\n\t\"a\": \"x\"\n}\n")
        let compact = #"{"b":1,"a":{"x":[1,2]}}"#
        #expect(try edit(compact) { _ in } == compact)
    }

    @Test func longDecimalsKeepTheirSpelling() throws {
        // Regression from a real ~/.claude.json: 17-digit metrics changed spelling after a no-op edit.
        let text = "{\n  \"rate\": 0.12345678901234567,\n  \"other\": 2.7500000000000004,\n  \"n\": 9007199254740993\n}"
        #expect(try edit(text) { _ in } == text)
        #expect(try edit(text) { $0["rate"] = 0.5 }.contains("\"rate\": 0.5,"))   // a real change is still written
    }

    @Test func newValuesAreEscapedLikeJSONStringify() {
        #expect(OrderedJSON.quote("a\"b\\c/d\né\u{01}") == #""a\"b\\c/d\né\u0001""#)
    }

    @Test func unreadableOriginalsFallBackToTheEditedBytes() {
        let edited = Data("{\n  \"a\": 1\n}\n".utf8)
        #expect(OrderedJSON.restyle(edited, like: Data("{not json".utf8)) == edited)
        #expect(OrderedJSON.restyle(edited, like: nil) == edited)
        let deep = Data((String(repeating: "[", count: 5_000) + String(repeating: "]", count: 5_000)).utf8)
        #expect(OrderedJSON.restyle(edited, like: deep) == edited)    // too deep to trust: no crash, no restyle
    }

    @Test func tegatasOwnSetupAndRemovalLeaveTheFileAsItWas() throws {
        let sb = try ContentSandbox()
        let url = URL(fileURLWithPath: try sb.write(stringified + "\n", ".claude/settings.json"))
        try ClaudeSettingsFile.edit(url) { try ClaudeSettingsEditor.configure($0, helperPath: "/Applications/Tegata.app/Contents/MacOS/tegata-token", ttlMilliseconds: 300_000) }
        let configured = try String(contentsOf: url, encoding: .utf8)
        #expect(configured.hasPrefix("{\n  \"zeta\": 1,\n  \"model\": \"opus\",\n  \"env\": {\n    \"B_VAR\": \"x\","))
        try ClaudeSettingsFile.edit(url) { try ClaudeSettingsEditor.unconfigure($0) }
        #expect(try String(contentsOf: url, encoding: .utf8) == stringified + "\n")
    }
}
