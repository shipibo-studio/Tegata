# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-11-15

### Added
- Release files are attested with GitHub artifact attestations: `gh attestation verify` on the zip and on `SHA256SUMS` (see docs/VERIFYING.md). 0.2.0 is attested too.

### Fixed
- A build from source on a Mac where the signed build took the record no longer reports the record as altered: it says another build of Tegata took it, and refuses to replace or forget it. The build that took the record still treats any change to it as an alarm. Records taken before 0.2.1 learn which build took them on the signed build's next check.

## [0.2.0] - 2026-11-15

### Added
- `tegata scan --json` and `tegata status --json`: one JSON document on stdout, with versioned schemas (`tegata.scan/1`, `tegata.status/1`) and an `untrusted` field naming what comes from files anyone can write.
- `tegata help agents` and [docs/AGENTS.md](docs/AGENTS.md): what an agent may run alone and what needs the person. A Claude Code skill in `skills/tegata`.

### Changed
- `tegata fix` without a record and `tegata clean` ask for Touch ID, also with `--yes`. Without Touch ID, only an answer typed at a terminal counts. Before, `fix --yes` on a Mac without a record let an agent remove hooks.

## [0.1.1] - 2026-11-14

### Fixed

- System Settings > Login Items listed the background watcher under the signing certificate's name with a blank icon; its LaunchAgent now names its app (`AssociatedBundleIdentifiers`), so it shows as Tegata CLI. Run `tegata watch install` once after updating.

## [0.1.0] - 2026-11-13

First public release.

### Added

- `tegata scan`: what your agents load (Claude Code, Codex, Cursor, Claude Desktop, Gemini, other Claude Code config roots) with risk in plain words and what to do; the secrets they copied, grouped by key, with where and how to rotate each; `--export` to Markdown or JSON.
- `tegata inventory`, `tegata fix` (remove or quarantine any entry, by id or by tool), `tegata clean` (remove copies of secrets from chats and shell history; chats are kept).
- `tegata watch`: a background watcher with an encrypted, authenticated record, Touch ID for every change to it, and notifications.
- `tegata status` and `tegata update`: version, an optional anonymous update check, and the record.
- Signed and notarized `Tegata CLI.app` bundle; SHA256SUMS; verification guide.
