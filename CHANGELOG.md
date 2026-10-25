# Changelog

## Unreleased

- Standard Go layout: source moved to `cmd/kasa/` with English file names; module path is now `github.com/eirikaleid/kasa`. Build with `make install` or `go build ./cmd/kasa`.
- All CLI output, errors, help text and code comments are in English.
- English command and flag names are primary (`target add|rm`, `backup`, `backup-password status|set|rm`, `export --target --overwrite`, `mail --profile --subject --body`); the old Turkish names still work as hidden aliases.
- Audit log: `who` is now `human`, detail notes are English; action names (`hedef.ekle`, ...) and backup file names are unchanged.

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
