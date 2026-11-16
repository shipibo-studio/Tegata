# Verifying a download

Every release ships `tegata-cli-<version>-macos.zip` and `SHA256SUMS`. Check both before you run anything.

1. **The file is the one published:**

   ```sh
   shasum -a 256 -c SHA256SUMS
   ```

   Expected: `tegata-cli-<version>-macos.zip: OK`.

2. **This repository published those files, and the checksums are signed** (from 0.2.0; needs the [GitHub CLI](https://cli.github.com)):

   ```sh
   gh attestation verify tegata-cli-<version>-macos.zip --repo shipibo-studio/Tegata
   gh attestation verify SHA256SUMS --repo shipibo-studio/Tegata
   ```

   Expected: `Verification succeeded!` for both. A workflow in this repository ([attest.yml](../.github/workflows/attest.yml)) checks each release's files against `SHA256SUMS` and attests both with GitHub's Sigstore-backed artifact attestations, so a changed zip or a changed `SHA256SUMS` no longer verifies. It proves these exact files were published by `shipibo-studio/Tegata`; the build itself is made and notarized on the maintainer's Mac, because notarization needs the Apple Developer account, so it does not prove GitHub built them from source.

3. **Apple notarized it, and it is signed by the team that publishes Tegata:**

   ```sh
   ditto -x -k tegata-cli-<version>-macos.zip .
   spctl -a -vv -t exec "Tegata CLI.app"
   codesign -dv --verbose=2 "Tegata CLI.app" 2>&1 | grep -E "Authority|TeamIdentifier|Identifier"
   xcrun stapler validate "Tegata CLI.app"
   ```

   Expected: `accepted`, `source=Notarized Developer ID`; `Authority=Developer ID Application: …`, `TeamIdentifier=34BRMF8X9A`, `Identifier=app.tegata.cli`; `The validate action worked!`.

4. **The command reports the protection it has:**

   ```sh
   "Tegata CLI.app/Contents/MacOS/tegata" version
   ```

   Expected: `keychain: access group (signed build)`.

If any step differs, do not run it, and [report it privately](../SECURITY.md).
