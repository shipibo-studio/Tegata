# Homebrew cask for the signed command line (template: version and sha256 come from Packaging/macos/build.sh release).
# The bundle goes to /Applications and `tegata` is linked into the PATH; launched through that link it keeps the
# bundle's keychain access group.
cask "tegata" do
  version "0.1.0"
  sha256 "REPLACE_WITH_SHA256_FROM_SHA256SUMS"

  url "https://github.com/shipibo-studio/Tegata/releases/download/v#{version}/tegata-cli-#{version}-macos.zip"
  name "Tegata"
  desc "See what your AI coding agents can run, and what secrets they may have copied"
  homepage "https://www.tegata.cc"

  depends_on macos: ">= :sequoia"

  app "Tegata CLI.app"
  binary "#{appdir}/Tegata CLI.app/Contents/MacOS/tegata"

  uninstall launchctl: "app.tegata.cli-watch",
            delete:    "~/Library/LaunchAgents/app.tegata.cli-watch.plist"

  zap trash: "~/Library/Application Support/Tegata CLI"

  caveats <<~EOS
    tegata scan            first look, read-only
    tegata watch install   background watcher (tegata watch establish takes its record with Touch ID)
    If Tegata.app is installed, it is the one watcher and the command line points to it.
  EOS
end
