# Changelog

## 2.0.0 — 2026-11-09

- **BREAKING:** `kasa which` (alias `lookup`) no longer accepts values as arguments. Values are read only from a hidden prompt (no echo, TTY): `Value 1 (empty line to finish): `, `Value 2 ...`; an empty first line is `search value is empty`. Any argument that is not a flag, `--`, and unknown flags are rejected before the keychain is touched; the error and the audit note never contain what was typed. Flags stay as arguments (`-i`, `--prefix`, `--suffix`, `--contains`, `-e`/`--regex`, `--all`). Old command lines that passed the value (including after `--`) no longer work; run `kasa which` and type the value at the prompt.
- An invalid `--regex` pattern now reports the fixed message `invalid regex (pattern not shown)` instead of echoing the pattern and the regexp parser error.
- Removed the `kasa which` warning about `KASA_HISTORY_GUARD` (no longer needed). `kasa shell-init` stays as an optional extra layer; docs and agent install steps no longer call it required.
- README (EN/TR): the Claude Code example deny list now includes `Bash(kasa which:*)` and `Bash(kasa lookup:*)`.

## 1.2.0 — 2026-11-06

- `kasa which` (alias `lookup`) took the values as arguments (replaced in 2.0.0 by prompt-only input). Flags could come before or after the values; everything after `--` was a value. Without any value the hidden prompt was used.
- New `-e`/`--regex` (Go RE2, matched anywhere in the value; with `-i` literal text is folded and escapes like `\D` are kept) and `--all` (all values must match; default is any).
- Removed the 4-character minimum for partial modes; an empty value is still an error.
- Output is now only the matching key names, sorted, one per line (no header, count or profile info). No match: empty stdout, `no match` on stderr, exit 1. Unreadable keys: `unreadable: <name>` on stderr.
- Audit note is `mode=<..> values=<n> matches=<n> scanned=<n>`; it never contains a value or pattern.
- New `kasa shell-init <zsh|bash|fish|pwsh>` (shell guessed from `$SHELL` when omitted) prints shell code that keeps `kasa which` / `kasa lookup` lines out of shell history and sets `KASA_HISTORY_GUARD=1`; use `eval "$(kasa shell-init zsh)"` in your rc file (a required install step, see README). It chains with existing history hooks instead of replacing them. `pwsh` is for PowerShell on macOS and a possible Windows port.
- `kasa which` prints a one-line warning to stderr when values are given as arguments and `KASA_HISTORY_GUARD` is empty; the result is still printed. No warning on the hidden prompt path.
- Agent docs (`AGENTS.md`, skill, `llms.txt`, `docs/agents.md`) tell an installing agent to add the `shell-init` line to the rc file idempotently and verify it.
- Note: a value given as an argument is visible in shell history and briefly in `ps`; use `kasa shell-init` (see above) or the hidden prompt instead.

## 1.1.0 — 2026-11-06

- Standard Go layout: source moved to `cmd/kasa/` with English file names; module path is now `github.com/eirikaleid/kasa`. Build with `make install` or `go build ./cmd/kasa`.
- All CLI output, errors, help text and code comments are in English.
- English command and flag names are primary (`target add|rm`, `backup`, `backup-password status|set|rm`, `export --target --overwrite`, `mail --profile --subject --body`); the old Turkish names still work as hidden aliases.
- Audit log: `who` is now `human`, detail notes are English; action names (`hedef.ekle`, ...) and backup file names are unchanged.
- `kasa which` (alias `lookup`): reverse lookup from a value to key and profile names. The value is asked through a hidden prompt (never argv), compared inside the `kasa` process and never printed; human + TTY only. Modes: exact (constant-time), `-i` (Turkish-aware case folding), `--prefix`, `--suffix`, `--contains` (partial modes need at least 4 characters). Exits 1 when nothing matches.

## 1.0.0 — first public release

- Separate, lockable macOS keychain for secrets (`kasa init`, `unlock`, `lock`, `status`), auto-locking after 12 hours of inactivity; macOS password dialog unlock (`kasa unlock --gui`) and a daily reminder (`kasa morning`).
- `kasa add`, `ls`, `get`, `rm`; `get` and `rm` are human-only (agent marker and TTY guard, best effort).
- `kasa run <profile> -- <cmd>`: injects secrets as environment variables into an allow-listed command resolved to a full path.
- Environment allow-list for child processes: injection variables (`DYLD_*`, `LD_*`, `BASH_ENV`, ...) dropped, fixed `PATH`.
- Secrets and passwords never appear in the arguments of any subprocess (writes via Security.framework, reads over a pipe).
- Values are returned byte-for-byte, including non-ASCII text, newlines and tabs.
- Root-owned locked profiles (`/usr/local/etc/kasa/profiles.json`) for high-value secrets.
- Capability commands: `kasa mail send` (SMTP with STARTTLS).
- Profiles in `~/.config/kasa/profiles.json` (`kasa profile ls|edit|path`).
- Audit log of every access (key names, never values): `kasa audit`.
- Encrypted backups: `kasa export` / `kasa import` using age (scrypt, ASCII armor), written to multiple targets with verification and atomic writes; `kasa target add|rm|ls`, `kasa backup ls` with stale-backup detection.
- Stored backup password (`kasa backup-password status|set|rm`), minimum 12 characters and four character classes for new passwords; in agent environments `export` writes only to configured targets.
- Build-time `TRUSTED_DIRS` and `DEV_ROOT` settings, hardened-runtime signing.
- Documentation, agent integration files (`AGENTS.md`, Claude Code skill, `llms.txt`) and launchd templates.
