#!/bin/bash
# Builds `Tegata CLI.app`, the signed bundle around the `tegata` command (M10).
#
#   Packaging/macos/build.sh dev        Debug, development signing: test the access-group path on this Mac
#   Packaging/macos/build.sh release    archive, export with Developer ID, zip, notarize, staple, checksums
#
# release talks to Apple: -allowProvisioningUpdates may create the app id and a Developer ID profile on the team's
# account, and notarization uploads the build. Run it yourself. Notarization uses a keychain profile stored with
# `xcrun notarytool store-credentials` (default name tegata-notary); no password goes through this script.
set -euo pipefail
cd "$(dirname "$0")"
MODE="${1:-dev}"
xcodegen generate --quiet
case "$MODE" in
  dev)
    xcodebuild -project TegataCLI.xcodeproj -scheme TegataCLI -configuration Debug -derivedDataPath build \
      -allowProvisioningUpdates build 2>&1 | grep -E "error:|BUILD (SUCCEEDED|FAILED)" || true
    APP="build/Build/Products/Debug/Tegata CLI.app"
    ;;
  release)
    rm -rf build/archive dist && mkdir -p dist
    xcodebuild -project TegataCLI.xcodeproj -scheme TegataCLI -configuration Release -archivePath build/archive/TegataCLI.xcarchive \
      -allowProvisioningUpdates archive 2>&1 | grep -E "error:|ARCHIVE (SUCCEEDED|FAILED)" || true
    cat > build/ExportOptions.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>method</key><string>developer-id</string>
  <key>teamID</key><string>34BRMF8X9A</string>
  <key>signingStyle</key><string>automatic</string>
</dict></plist>
PLIST
    xcodebuild -exportArchive -archivePath build/archive/TegataCLI.xcarchive -exportPath dist -exportOptionsPlist build/ExportOptions.plist \
      -allowProvisioningUpdates 2>&1 | grep -E "error:|EXPORT (SUCCEEDED|FAILED)" || true
    APP="dist/Tegata CLI.app"
    ;;
  *) echo "usage: $0 dev|release"; exit 64 ;;
esac
[ -d "$APP" ] || { echo "no bundle built"; exit 1; }
codesign --verify --strict "$APP" || { echo "the bundle's signature does not verify"; exit 1; }
codesign -d --entitlements :- "$APP" 2>/dev/null | grep -q "keychain-access-groups" || { echo "no keychain access group in the signature"; exit 1; }
echo "built: $APP"
"$APP/Contents/MacOS/tegata" version

if [ "$MODE" = release ]; then
  VERSION=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "$APP/Contents/Info.plist")
  ZIP="dist/tegata-cli-$VERSION-macos.zip"
  ditto -c -k --keepParent "$APP" "$ZIP"
  xcrun notarytool submit "$ZIP" --keychain-profile "${TEGATA_NOTARY_PROFILE:-tegata-notary}" --wait
  xcrun stapler staple "$APP"
  xcrun stapler validate "$APP"
  spctl -a -vv -t exec "$APP"
  rm -f "$ZIP" && ditto -c -k --keepParent "$APP" "$ZIP"      # the stapled bundle is what ships
  (cd dist && shasum -a 256 "$(basename "$ZIP")" > SHA256SUMS)
  echo "ready: $ZIP and dist/SHA256SUMS (attach both to the GitHub release; update the cask's version and sha256)"
fi
