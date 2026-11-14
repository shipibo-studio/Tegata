# Verifying a download

Every release ships `tegata-cli-<version>-macos.zip` and `SHA256SUMS`. Check both before you run anything.

1. **The file is the one published:**

   ```sh
   shasum -a 256 -c SHA256SUMS
   ```

   Expected: `tegata-cli-<version>-macos.zip: OK`.

2. **Apple notarized it, and it is signed by the team that publishes Tegata:**

   ```sh
   ditto -x -k tegata-cli-<version>-macos.zip .
   spctl -a -vv -t exec "Tegata CLI.app"
   codesign -dv --verbose=2 "Tegata CLI.app" 2>&1 | grep -E "Authority|TeamIdentifier|Identifier"
   xcrun stapler validate "Tegata CLI.app"
   ```

   Expected: `accepted`, `source=Notarized Developer ID`; `Authority=Developer ID Application: …`, `TeamIdentifier=34BRMF8X9A`, `Identifier=app.tegata.cli`; `The validate action worked!`.

3. **The command reports the protection it has:**

   ```sh
   "Tegata CLI.app/Contents/MacOS/tegata" version
   ```

   Expected: `keychain: access group (signed build)`.

If any step differs, do not run it, and [report it privately](../SECURITY.md).
