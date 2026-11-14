# Tegata

```
  ┏━━━━┓  ▀█▀ █▀▀ █▀▀ ▄▀█ ▀█▀ ▄▀█
  ┃手形┃   █  ██▄ █▄█ █▀█  █  █▀█
  ┗━━━━┛  a checkpoint for your AI coding agents
```

Your AI coding agents run hooks, MCP servers and plugins nobody reviewed, and they copy your secrets into their chats. **Tegata shows what they can run, what they have seen, and tells you when it changes.**

A *tegata* (手形) was the pass a traveller showed at an Edo-period checkpoint. This one is for the agents that travel through your Mac.

- **See** every extension your agents load (Claude Code, Codex, Cursor, Claude Desktop, Gemini), who installed it, and what it can do, in plain words.
- **Fix** what you do not use: remove a hook or an MCP server, or move a skill aside, with a backup kept.
- **Find** the API keys, tokens and passwords that ended up in your agents' chats and your shell history, tell you which to rotate first and where, then **clean** the copies. Your chats stay; only the values change.
- **Watch** in the background: when something adds or changes a hook, an MCP server, a plugin or a skill, you get a notification and decide.

Read-only unless you ask. No account, no server, no telemetry.

## Install

Requires macOS 15 or later.

1. Download `tegata-cli-<version>-macos.zip` and `SHA256SUMS` from the [latest release](https://github.com/shipibo-studio/Tegata/releases/latest), and [check them](docs/VERIFYING.md).
2. Unzip, move **Tegata CLI.app** to `/Applications`, and link the command into your `PATH`:

   ```sh
   ln -s "/Applications/Tegata CLI.app/Contents/MacOS/tegata" /usr/local/bin/tegata   # or any folder in your PATH
   ```

The app bundle is signed with Developer ID and notarized by Apple. The command runs from inside it, so `tegata watch` can keep its keys in a keychain access group only this signed build can use. A Homebrew cask is coming.

**From source:** `swift build -c release` in this repository gives `.build/release/tegata`. It works the same, except that the watcher keeps its keys in the login keychain and a Secure Enclave key file (`tegata version` says which).

## Start

```sh
tegata scan
```

A first look, read like a check-up: the result first, then what your agents load and what each risk means, the secrets they copied with where and how to deal with each one, and the next commands. Nothing is changed.

| Command | What it does |
| --- | --- |
| `tegata scan [--details] [--export [file.md\|file.json]]` | The first look. `--export` saves the report (Markdown or JSON, readable only by you). |
| `tegata inventory [--why] [--ids] [--all] [--json]` | Every extension, worst first, with why each finding matters. |
| `tegata fix remove\|quarantine <id>… \| --owner <name>` | Take out what you do not use; a backup of each file is kept. |
| `tegata clean [--list] [--dry-run]` | After rotating keys, remove their copies from chats and shell history. |
| `tegata watch install` · `establish` | Watch in the background; take the record it compares against (Touch ID). |
| `tegata status` | Version, updates, your record and what changed. |
| `tegata watch accept\|remove\|revert <name>` | Keep or undo a change (Touch ID). |
| `tegata update` | Check for a newer version and offer to update. |

`--fail-on <severity>` exits with status 2 when a finding at that level or above exists, for CI. `--no-color` (or `NO_COLOR`) for plain output.

## What it reads, and what it never does

- **Reads** your agents' configuration (`~/.claude`, `~/.claude.json`, `~/.codex`, `~/.cursor`, `~/.gemini`, Claude Desktop's config, other Claude Code config roots such as `CLAUDE_CONFIG_DIR`), the scripts their hooks run, their chats, and your shell startup files and history. `.env` files only in folders you name.
- **Never prints a secret value**, nor a piece of one. Reports name files, lines and counts; paths under your home show as `~`, so a report is safe to paste into an issue.
- **Never writes** unless you run `fix`, `clean` or a `watch` action, and every write is checked against what the scan saw (compare-and-swap) so a file that changed since is left alone.
- **Never sends anything about you.** The only network request is `tegata status` and `tegata update` asking GitHub's public API whether a newer release exists; `--offline` or `TEGATA_NO_UPDATE_CHECK=1` skips it.
- **The watcher's record** is encrypted to a Secure Enclave key and authenticated with a key in the keychain; taking it, accepting a change and undoing one ask for Touch ID.

## Limits, honestly

- It sees what is on disk. An agent's provider may still keep a copy of what you pasted on its servers: rotating a key is what makes every copy worthless.
- Risk ratings come from fixed rules over text (no model, nothing run). A rule can miss a well-hidden script; a high rating means "can do a lot", not "is malicious".
- macOS only for now. Linux is next.

## Tegata, the app

A menu bar app with the same engine is coming, with a vault that keeps your agent's own login behind the Secure Enclave and Touch ID. The command line here stays free and open.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), never in a public issue.

## License

[Apache-2.0](LICENSE) © Shipibo Studio
