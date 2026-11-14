# Security policy

## Reporting a vulnerability

If you find a security vulnerability, **do not open a public issue** and do not describe it in a pull request.

Report it privately through GitHub: **[Report a vulnerability](https://github.com/shipibo-studio/Tegata/security/advisories/new)**.

Please include the affected version or commit, steps to reproduce (with synthetic data: never real keys or real chats), the potential impact, and suggested mitigations if any. We acknowledge reports within **48 business hours** and reply with a remediation timeline. We credit reporters in the advisory unless they prefer otherwise. Please do not access other people's data during your research, and do not disclose the finding until a fix is available.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |

## Threat model

Tegata reads files that agents, plugins and other tools can write. It treats **everything it reads as hostile**.

| Risk | How Tegata handles it |
| --- | --- |
| A secret leaking through Tegata's own output | Values are never printed, stored or logged; reports show file, line and rule. Unkeyed hashes of entries are kept out of shareable output (`--json`, `--export`), since they would confirm guesses of weak values |
| A user name leaking through a pasted report | Paths under the home folder, and its encoded form in transcript folder names, are shown as `~` |
| Terminal injection through file or folder names | Control characters in anything read from disk are replaced before printing |
| Writing over a file that changed since the scan | Every edit is compare-and-swap against what the scan saw; atomic writes keep permissions; backups for configuration edits |
| Cleaning a secret where it is in use | Only copies are cleaned (agent chats, shell history), never settings, startup files or `.env`; files a running process holds open are skipped |
| An attacker editing the watcher's record to hide a change | The record is encrypted to a Secure Enclave key and its index authenticated with a key in the keychain (an access group in the signed build); a deleted or altered record is reported, never treated as a first run; changes to it need Touch ID |
| An attacker posing as Tegata in an agent's settings | Tegata's own entries are recognised by exact path and by the installed app's code signature, never by name |
| Hostile scripts and huge files slowing a scan | Bounded reads and line lengths, no regular expression across a whole file, no code run |
| Supply chain | No third-party dependencies; arguments parsed by hand; releases signed with Developer ID, notarized and published with SHA256SUMS ([verifying](docs/VERIFYING.md)) |
| Data leaving the Mac | No telemetry. The only network request is the optional update check (`tegata status`, `tegata update`) to GitHub's public API, anonymous |

## Out of scope

- An attacker who already runs code as your user can change what agents load directly; Tegata reports the change, it does not prevent it.
- Copies held by your agents' providers on their servers.
