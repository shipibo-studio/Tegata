# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
