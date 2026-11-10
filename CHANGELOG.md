# Changelog

## 2.5.0 — 2026-11-10

Keychain items now trust only kasa itself, not `/usr/bin/security`.

- **Item ACL = kasa only.** New items are written with an access list holding just the running kasa. Its designated requirement is tied to your signing certificate (`identifier kasa and certificate leaf = H"<sha1>"`), not to one build, so a rebuild signed with the same certificate reads without a prompt. `/usr/bin/security`, ad-hoc copies and other same-user processes get `errSecAuthFailed` (keychain interaction is disabled, so no dialog).
- **Reads in-process.** Values are read through Security.framework, not through a `security find-generic-password` subprocess; byte-for-byte tests cover UTF-8, newlines, tabs, quotes and hex-looking values.
- **`make cert`** (`contrib/make-cert.sh`): creates a self-signed code-signing certificate, imports it with `-T /usr/bin/codesign`, writes an encrypted `.p12` backup, records `SIGN_IDENTITY` in `local.mk`; temporary key files are removed. `--keychain` targets another keychain (tests); `--force` makes a new certificate. **Keep the `.p12` safe and private.**
- **Makefile:** `make build`/`install` sign with `SIGN_IDENTITY` and fail with a hint to run `make cert` when it is missing; ad-hoc signing only with an explicit `ADHOC=1` (prints a warning).
- **`kasa acl migrate [--dry-run]`** (human only): moves items written before 2.5.0 to the new access list. It takes an encrypted backup first and restores it into a temporary keychain to verify it (otherwise nothing changes), then per item reads the old way, deletes it and rewrites it with the same label, kind, comment, service and account and kasa's own ACL, and compares a read-back byte for byte (on a mismatch it rewrites the in-memory value and stops). The backup-password item goes last. Idempotent: bound items are skipped. No in-place ACL editing and no private APIs are used.
- **Certificate loss:** restore the `.p12`, or create a new certificate and `kasa import` from an encrypted backup. The master password does not repair it. Covered end to end in temporary keychains.
- Tests: signed-rebuild, ad-hoc-refused, `.p12`-restore and new-certificate recovery in temporary keychains (no GUI windows, never the login keychain or the real vault).
- Docs: README (EN/TR) caution box and migration section, SECURITY.md threat model, AGENTS.md (`kasa acl` is human-only).

**Upgrade:** `make cert` → `make install` → `kasa unlock` → `kasa acl migrate --dry-run` → `kasa acl migrate`. Take a `kasa export` backup first.

## 2.4.0 — 2026-11-10

Behaviour changes, from an independent audit:

- **Locked profiles: no symlink match, resolved pins.** In a profile from `/usr/local/etc/kasa/profiles.json` the command must be exactly the allowed path; a symlink to it (`/tmp/x -> /usr/bin/tool`) is refused, since it could be swapped between the check and `exec`. A pinned path argument is passed to the command as the resolved path that was checked, not as given. `kasa profile test` follows the same rule. Unlocked profiles are unchanged (venv symlinks keep working).
- **Locked profiles: `PYTHONNOUSERSITE=1`.** Python's user site (`usercustomize.py`, `.pth`) no longer runs with the secrets of a locked profile. Unlocked profiles are unchanged.
- **Backup targets only from the locked file.** `export`, `target ls` and `backup ls` read targets only from `hedefler` in the root-owned `/usr/local/etc/kasa/profiles.json`. `hedefler` in `~/.config/kasa/profiles.json` (agent-writable) is ignored everywhere, also in a human terminal, with a stderr warning that prints the migration command; a human can still use `kasa export --target <dir>`. `kasa target add|rm` is human-only (`requireHuman`) and prints the exact `sudo /usr/bin/plutil ...` command when it cannot write the locked file; it never runs kasa as root. `target rm` also clears a leftover entry from the user file.
- **Migration:** run the command from the warning (`kasa target ls` shows it), check that the file is still `root:wheel -rw-r--r--`, then delete the `hedefler` key from `~/.config/kasa/profiles.json` by hand (`kasa target rm` would also remove it from the locked list).
- Tests: symlink and retargeted-symlink cases for locked commands and pins, unlocked behaviour unchanged, targets only from the locked file, `target add|rm` refused for an agent, sudo command when the locked file is not writable, `PYTHONNOUSERSITE` only when locked.
- Docs: SECURITY.md, README (EN/TR).

## 2.3.1 — 2026-11-09

- **Fix: `kasa run` with a non-terminal output runs the command via `exec` again.** 2.3.0 ran it as a child of kasa so the output could be masked. That broke two things: `perl -e 'alarm 2; exec @ARGV' kasa run p -- cmd | cat` (the timeout pattern trend-radar uses) delivered SIGALRM to kasa and the command ran on, and `kill -9 <kasa pid>` (what Python's `subprocess.run(timeout=)` does) left the command orphaned with the secrets in its environment.
- Now the command always takes over kasa's PID. Masking moved to a side process, `kasa __maske` (hidden, refuses to run unless its stdin is a pipe): every non-terminal stream becomes a pipe it reads; the values are sent to it over a separate pipe, length-prefixed (not argv or environment). It ignores SIGINT, SIGTERM, SIGHUP, SIGQUIT and SIGPIPE, reads to EOF, writes the `NOTE run <profile> masked N occurrence(s)` audit line (when N > 0) and exits.
- If the side process cannot be started, kasa exits with 70 and does **not** run the command unmasked.
- Removed the 2.3.0 signal forwarding and exit-status translation; the masker itself is unchanged.
- Known side effect: the side process can still be writing the last bytes when the command has exited. A reader on a pipe gets EOF only after that; output redirected straight to a file can be complete a moment after the shell returns.
- Tests (real processes): masked stdout and stderr, exit status 7, 1 MB output, target PID equals kasa's PID, `perl alarm 1; exec` ends in about 1 s, `kill -9` on kasa's PID leaves no process, SIGINT to the group loses no output, exit 70 without exec when the side process cannot start, direct `__maske` refused.

## 2.3.0 — 2026-11-09

- **Output masking for `kasa run`.** If stdout and stderr are both terminals, nothing changes: kasa still replaces itself with the command (`exec`). If one or both are not (agent, pipe, redirect), kasa runs the command as a child instead: stdin goes straight to it, a stream that is a terminal goes straight to it, and every other stream is read by kasa, masked and written to the real output.
- Masking: every secret value of the profile that is at least 6 bytes long (shorter ones would match ordinary text) becomes `***`; longest value first, so a value that is a prefix of another does not cut it. It works on bytes, with no wait for a newline; only the end of a chunk that could still be the start of a value is held back (always shorter than the longest value), so a value split across two reads is caught. Binary data passes unchanged.
- **This only catches accidental leaks** (a debug line or error message that echoes a value). It does not stop base64, hex, character-by-character or any other deliberate leak. SECURITY.md says so.
- SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2 and SIGWINCH are forwarded to the child (a signal that was ignored when kasa started stays ignored). The child shares kasa's process group, so when kasa is in a terminal's foreground group the terminal already delivers Ctrl-C, Ctrl-\ and resizes to it: those three are then not forwarded again. The exit status is the child's (128+signal if it was killed by one); kasa prints nothing of its own.
- Memory: in this mode the kasa process lives until the child exits and holds the values; the copies used for masking are wiped afterwards (Go strings cannot be). SECURITY.md lists it next to the `ps -E` item.
- **Audit:** the `OK run` line now ends with the mode: `command [matching allow entry] masked` or `... exec`. If something was masked, `NOTE run <profile> masked N occurrence(s)` follows when the child is done (never the value). Anything that parses the old `OK run` note must accept the new suffix.
- Tests: masker unit tests (every split point, prefix-related values, short values, binary data, empty stream) and end-to-end tests with a real `/bin/sh` child (stdout and stderr masked, exit status 7, killed-by-signal status, SIGTERM forwarded, stdin, terminal stream passed straight through and `exec` kept, under a pseudo-terminal from script(1)).
- Docs: README (EN/TR), SECURITY.md (run item, masking items, residual risk), AGENTS.md, skill, `llms.txt`.

## 2.2.0 — 2026-11-09

- **Warning for risky `allow` entries.** In an unlocked profile (`~/.config/kasa/profiles.json`), an entry is risky when its command (basename, case-insensitive, version suffix removed: `python3.13` -> `python`) is `python`, `node`, `deno`, `bun`, a shell (`sh bash zsh dash ksh fish`), `perl`, `ruby`, `php`, `lua`, `tclsh`, `Rscript`, `osascript`, `uv`, `uvx`, `pipx`, `npx`, `npm`, `pnpm`, `yarn`, `java`, `env`, `xargs`, `awk`, `gawk`, `find`, `curl` or `*`, and none of its pinned arguments is a path (`/...`, `~/...`) or a plain `-m`. Examples: `python3`, `npm run`, `uv run name` warn; `python3 ~/x/`, `python3 -m pkg`, `uv run --project ~/x name`, `gh` do not.
- `kasa profile ls` prints a `warning:` line for such a profile, and `kasa run` and `kasa profile test` print one line when the matching entry is risky. All of them go to stderr; stdout is not touched and the command is not blocked. Locked profiles are not checked. There is no environment variable to silence it.
- Audit: `kasa run` writes `NOTE run <profile> risky allow entry: <entry>` next to the unchanged `OK` line.
- **Fix:** `kasa profile test` is now audited like `run`: `OK profile-test <profile> <matching entry>` or `DENIED profile-test <profile> <reason>` (`command not allowed: <path>` or `not found: <name>`). Argument values are never logged. Before, an agent could probe the allow rules without a trace.
- Tests: the `test` subcommand is now exercised through `cmdProfile` (2.1.0 shipped it unwired and a direct unit test missed it), and `kasa run` is tested end to end in a child process.
- Docs: README (EN/TR), SECURITY.md (interpreters in `allow`), skill, `llms.txt`.

## 2.1.0 — 2026-11-09

- **Pinned arguments in `allow`.** An entry with spaces is split into tokens: the first is the command (same rules as before), the rest pin argv[1..n]. A token that is an absolute or `~/` path ending in `/` is a directory pin (the argument must be a regular file below it, after symlink resolution, not starting with `-`; `../` and symlinks pointing outside are refused; `<dir>x` is not below `<dir>/`). A path token without a trailing `/` must match exactly. Any other token is plain text and must be equal (`python3 -m trend_radar.bildir`). Arguments after the pinned prefix are free. Too few arguments never match. Entries without spaces behave exactly as before. This closes `python3 -c 'print(os.environ)'` for profiles that allow an interpreter; it is a speed bump if the pinned script is user-writable (SECURITY.md).
- Rejections name the entry and the reason (`entry "python3 ~/x/": argument 1 must be ...`); argument values are never echoed.
- Locked profiles: in a pinned entry the command and every path token must be absolute and clean; relative paths (`x/y.py`, `./y.py`) and `~/` are refused. Plain-text tokens are allowed, but only an absolute path pin to a root-owned script is a boundary (`-m module` and bare file names resolve against the agent-controlled cwd).
- New `kasa profile test <profile> -- <cmd> [arg...]`: dry run of the allow check. Prints the path that would be exec'd and `allowed: <entry>`, or exits 1 with the reason. Runs nothing, reads no secret, works while locked and in an agent session.
- Audit: the `OK run` note is now `command [matching allow entry]` (for example `python3 [python3 ~/Developer/x/]`); arguments are never logged.
- Build: the Makefile includes an optional, git-ignored `local.mk` (see `local.mk.example`) so `TRUSTED_DIRS` and `DEV_ROOT` survive a plain `make install`. Values on the command line still win.
- `-m` pins: when the matching entry has a plain `-m` token, `kasa run` adds `PYTHONSAFEPATH=1` to the child environment (after the `PYTHON*` drop, and only then), so `python3 -m pkg.mod` does not import from the agent-controlled working directory. The module must be installed in the interpreter's own site-packages; Python before 3.11 ignores the variable and is not protected.
- Docs: README (EN/TR) allow section and build note, SECURITY.md interpreter entry, AGENTS.md, skill, `llms.txt`.

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
