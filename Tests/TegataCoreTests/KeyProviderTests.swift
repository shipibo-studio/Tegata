import Testing
import Foundation
import CryptoKit
@testable import TegataCore

@Suite struct InMemoryKeyProviderTests {
    let tag = "app.tegata.test"

    @Test func wrapUnwrapRoundTrip() async throws {
        let p = InMemoryKeyProvider()
        #expect(await p.state(tag: tag) == .absent)
        try await p.createKey(tag: tag)
        #expect(await p.state(tag: tag) == .present)
        let dek = SealedCoding.newDEK()
        let wrapped = try await p.wrap(dek, tag: tag)
        #expect(wrapped.count > 65 + 32)
        let back = try await p.unwrap(wrapped, tag: tag, authorization: nil)
        #expect(back == dek)
        // Wrapping is randomized.
        #expect(try await p.wrap(dek, tag: tag) != wrapped)
    }

    @Test func invalidationAndDestroy() async throws {
        let p = InMemoryKeyProvider()
        try await p.createKey(tag: tag)
        let wrapped = try await p.wrap(SealedCoding.newDEK(), tag: tag)
        await p.simulateBiometryChange(tag: tag)
        #expect(await p.state(tag: tag) == .invalidated)
        await #expect(throws: KeyProviderError.keyInvalidated) { try await p.unwrap(wrapped, tag: tag, authorization: nil) }
        try await p.destroyKey(tag: tag)
        #expect(await p.state(tag: tag) == .absent)
        await #expect(throws: KeyProviderError.keyNotFound) { try await p.unwrap(wrapped, tag: tag, authorization: nil) }
        await #expect(throws: KeyProviderError.keyNotFound) { _ = try await p.wrap(SealedCoding.newDEK(), tag: tag) }
    }

    @Test func duplicateCreateAndTamperedWrap() async throws {
        let p = InMemoryKeyProvider()
        try await p.createKey(tag: tag)
        await #expect(throws: KeyProviderError.keyAlreadyExists) { try await p.createKey(tag: tag) }
        var wrapped = try await p.wrap(SealedCoding.newDEK(), tag: tag)
        wrapped[wrapped.count - 1] ^= 1
        await #expect(throws: KeyProviderError.self) { try await p.unwrap(wrapped, tag: tag, authorization: nil) }
    }
}

@Suite struct SecretBytesTests {
    @Test func equalityAndZeroing() {
        let a = SecretBytes(utf8: "token"), b = SecretBytes(utf8: "token"), c = SecretBytes(utf8: "tokem")
        #expect(a.isEqual(to: b)); #expect(!a.isEqual(to: c)); #expect(!a.isEqual(to: SecretBytes(utf8: "tok")))
        #expect(String(describing: a) == "SecretBytes(5 bytes)")
        let buf = UnsafeMutableRawBufferPointer.allocate(byteCount: 8, alignment: 1)
        buf.copyBytes(from: [1, 2, 3, 4, 5, 6, 7, 8])
        SecretBytes.zero(buf)
        #expect(Array(buf) == [UInt8](repeating: 0, count: 8))
        buf.deallocate()
        #expect(SecretBytes([]).count == 0)
    }
}
