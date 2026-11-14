# Contributing to Tegata

Thanks for your interest. Contributions of every size are welcome: a bug report with a synthetic reproduction, a new rule, a parser for another agent, a test.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Bugs:** open a [bug report](https://github.com/shipibo-studio/Tegata/issues/new?template=bug_report.yml). Never paste real keys, real chats or real configuration: reduce it to a synthetic example.
- **Features and rules:** open a [feature request](https://github.com/shipibo-studio/Tegata/issues/new?template=feature_request.yml) before writing code.
- **Security issues:** never in public. Follow [SECURITY.md](SECURITY.md).

## Development setup

- macOS 15 or later, Swift 6 (Xcode 16 or later).
- `swift build` and `swift test` from the repository root.
- The signed bundle is built with `Packaging/macos/build.sh dev` (needs xcodegen and a development certificate); maintainers run `build.sh release`.

## Pull requests

1. Open or find an issue first for anything beyond a small fix.
2. Fork and branch from `main`: `feat/opencode-parser`, `fix/redaction-escape`, `docs/verifying`.
3. Keep it focused: one change per pull request.
4. Add tests for new behavior and for every fix (start with a test that reproduces the bug). Include hostile input: control characters in names, huge files, invalid UTF-8, symlinks, files that change during a scan.
5. Add an entry under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
6. Fill in the pull request template. CI must be green and a maintainer review is required.

## Standards

- **English** in code, comments, docs and commit messages; [Conventional Commits](https://www.conventionalcommits.org/).
- **Never print, store or log a secret value**, and no new network access or telemetry.
- **Synthetic fixtures only.** Fake keys in tests carry `TestOnly` in the value.
- **Every write is compare-and-swap** against what was read, and reversible or explicitly confirmed.
- **No new dependencies** without discussing it first.
- Plain words in user-facing text: what it is, what it means, what to do.

## Releases

Maintainers move `[Unreleased]` entries under the new version in `CHANGELOG.md`, tag `vX.Y.Z` on `main`, build with `Packaging/macos/build.sh release` (signed, notarized, stapled) and publish the zip with `SHA256SUMS`.

## Licensing of contributions

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
