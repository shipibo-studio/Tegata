import Testing
@testable import TegataCore

/// Uninstall gives back the user's own cleanupPeriodDays instead of deleting it (found 2026-11-12).
@Suite struct SettingLedgerTests {
    @Test func neverSetByTegataIsLeftAlone() {
        #expect(SettingLedger.undo(current: 36500, ledger: nil) == nil)
    }

    @Test func tegataValueGoesBackToTheUsersValueOrAway() {
        let overUser = SettingLedger.recording(90, over: 36500, existing: nil)
        #expect(SettingLedger.undo(current: 90, ledger: overUser) == .some(36500))
        let overNothing = SettingLedger.recording(90, over: nil, existing: nil)
        #expect(SettingLedger.undo(current: 90, ledger: overNothing) == .some(nil))      // remove the key
    }

    @Test func aValueTheUserChangedSinceIsKept() {
        let l = SettingLedger.recording(90, over: nil, existing: nil)
        #expect(SettingLedger.undo(current: 120, ledger: l) == nil)
    }

    @Test func laterWritesKeepWhatTheUserFirstHad() {
        let first = SettingLedger.recording(90, over: 36500, existing: nil)
        let second = SettingLedger.recording(60, over: 90, existing: first)
        #expect(second.previous == 36500 && second.wrote == 60)
        #expect(SettingLedger.undo(current: 60, ledger: second) == .some(36500))
        // "Use default" from Tegata removes the key; Uninstall then puts the user's value back.
        let removed = SettingLedger.recording(nil, over: 60, existing: second)
        #expect(SettingLedger.undo(current: nil, ledger: removed) == .some(36500))
    }
}
