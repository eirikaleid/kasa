# Security policy

kasa exists to keep secrets out of AI agent sessions, so its security claims should be precise. This document says what kasa defends, what it does not, and where the sharp edges are.

## Threat model

**Assets.** API tokens, passwords and keys stored in the `kasa` keychain, plus the encrypted backups made from it.

**Actors.**

- **The human user**: trusted. Knows the master password, runs `kasa` from an interactive terminal.
- **An AI coding agent** running as the same macOS user, in the same session: *semi-trusted*. It is useful and normally well-behaved, but it can be confused, buggy, or steered by prompt injection from content it reads (web pages, issues, files, tool output).
- **Passive leakage channels**: chat transcripts, logs, shell history, files committed by accident. This is the primary threat kasa is built against.

**Out of scope.** A fully compromised machine or account (malware running as you with unrestricted access), a malicious root user, physical attacks on an unlocked, logged-in Mac, and side channels in macOS itself.

**Goal.** An agent can get work done with a secret without the secret entering its context, and an agent that is misbehaving has to get past several independent barriers to read it.

## What kasa does and does not protect against

### What kasa does

- **Separate, lockable keychain.** Secrets live in their own keychain (`kasa.keychain-db`), not in the login keychain. It auto-locks after 12 hours of inactivity. While locked, nothing can be read, and kasa exits with status 75 instead of prompting. The keychain is kept out of the keychain search list so other applications do not trigger password prompts for it.
- **No secrets in arguments.** Secrets and passwords are never placed in the argv of any child process. Creating, unlocking and writing go through Security.framework. Reads use `/usr/bin/security` (the only app on each item's access list, for compatibility), and the value comes back over a pipe — never on a command line.
- **Agents can add, not replace.** From an agent session `kasa add` may create a new key (so a tool can store a token it just generated) but cannot overwrite an existing one; keys used by root-owned locked profiles can only be written by a human at a TTY.
- **Injection without disclosure.** `kasa run <profile> -- <cmd>` resolves the command to an absolute path, checks it against the profile's allow list, and runs that exact path with the secrets in its environment. When stdout and stderr are both terminals it `exec`s it (the kasa process is gone); otherwise (agent, pipe) it runs the command as a child of kasa so the output can be masked (next item). There is no free-form execution.
- **Output masking (accidental leaks only).** In the child-process mode, every stream that is not a terminal is read by kasa and each exact occurrence of a secret value of the profile (at least 6 bytes, also when it is split across two reads) is replaced by `***` before it reaches the caller. A stream that is a terminal goes straight to the child. Signals are forwarded and the child's exit status is returned. The audit `OK` line says `masked` or `exec`, and `NOTE run <profile> masked N occurrence(s)` records that something was masked (never the value). This is a net for debug lines and error messages that echo a value by mistake, not a barrier: see below.
- **Strict environment.** The child gets a fixed `PATH`, an environment allow-list, and the secrets. Injection variables (`DYLD_*`, `LD_*`, `BASH_ENV`, `GIT_*`, `NODE_*`, `PYTHON*`, `NPM_CONFIG_*`, proxy and CA variables, ...) are dropped, and kasa itself is signed with the hardened runtime so `dyld` ignores `DYLD_*` for kasa.
- **Human-only raw access.** `kasa get`, `kasa rm`, `kasa unlock`, `kasa import` and setting or removing the backup password are refused when an agent marker is present or when there is no TTY.
- **Capability commands.** `kasa mail send` uses SMTP credentials inside the kasa process; they are never printed or passed on.
- **Locked profiles.** Profiles in the root-owned `/usr/local/etc/kasa/profiles.json` (file and every parent directory root-owned, no symlinks, not group/world-writable) override user profiles, can only be changed with `sudo`, and their keys cannot be used by any other profile.
- **Encrypted, verified backups.** Backups are age files (scrypt passphrase). New backup passwords need at least 12 characters and all four character classes. Each backup is verified by decrypting it before writing, written atomically to each target, and read back and compared byte for byte. In an agent environment `export` writes only to configured targets, and the backup password can only be set or removed by a human.
- **Audit log.** Every access is appended to `~/.local/state/kasa/audit.log` with the operation, the key name and the caller. Values are never logged.

### What kasa does not do

- **It does not stop a determined same-user agent by itself.** The guard that tells humans from agents (agent marker environment variables plus a TTY check) is **best effort**. A confused or prompt-injected agent running as the same user can bypass it, for example by clearing the marker variables or by allocating a pseudo-terminal.
- **Unlocked profiles are not a security boundary.** `~/.config/kasa/profiles.json` is writable by the user and therefore by an agent. Editing it can widen an allow list or, for example, change the `smtp` host so `kasa mail send` sends the password to another server. Treat unlocked profiles as a convenience.
- **It does not protect an unlocked keychain from the same user** using other tools (see residual risks).
- **Masking does not stop a child that leaks on purpose.** It is an exact byte match: base64, hex, URL-encoding, reversed text, one character per line, splitting a value over two streams, or sending it over the network or into a file all pass. Values shorter than 6 bytes are not masked (they would match ordinary text), a multi-line value printed line by line is not recognised, and a stream that is a terminal is never filtered. Do not treat `***` as proof that nothing leaked, and do not rely on it for an allowed command you do not trust.
- **It does not sandbox the allowed command.** Whatever you allow can do whatever that program can do with the secret it is given.

### The real boundaries

In order of strength, the barriers between an agent and your secrets are:

1. The **separate locked keychain**: when locked, nothing is readable.
2. **Your agent's own permission rules** (for example Claude Code `permissions.deny` for `kasa get`, `kasa unlock`, `kasa import`, `kasa rm` and `security find-generic-password`). See [docs/agents.md](docs/agents.md).
3. **Root-owned locked profiles** for high-value secrets.
4. The kasa guard, as a best-effort speed bump.

## Known residual risks

These are known, measured or understood, and not fixed.

- **`ps -E` exposes the child's initial environment.** The secrets are in the environment of the allowed child process. On macOS any process of the same user can read a child's initial environment block (the `KERN_PROCARGS2` data behind `ps -E`) for the life of the process, even if the child later unsets the variables.
- **The kasa process stays alive in child-process mode.** With `exec` the kasa process was replaced and only the child held the secrets. When the output is not a terminal, kasa waits for the child and holds the values in memory (the profile's secrets, plus the copies used for masking, which are wiped when the child is done; Go strings such as the environment block cannot be wiped) until the child exits. A same-user process that can read another process's memory could therefore read them from kasa as well as from the child. That is the same exposure the `ps -E` item above already accepts, with one more process.
- **`security find-generic-password` while kasa is unlocked.** The keychain is an ordinary macOS keychain; while it is unlocked, the same user can read items with the `security` tool. Deny that command in your agent's permission rules and keep the keychain locked when you are not using it. Every item's access list trusts `/usr/bin/security` rather than the kasa binary: an ad-hoc-signed kasa gets a new code signature on every build, so trusting it would re-prompt after each rebuild. Pinning items to kasa needs a stable Developer ID signature and is on the roadmap.
- **Interpreters in `allow`.** A profile that allows an interpreter or shell (`python3`, `bash`, `node`, `uv`, ...) effectively exposes its secrets: the agent can run code that prints the environment. The recommended form is a pinned entry such as `"python3 ~/Developer/x/"` or `"python3 -m module"` (see the README): `python3 -c`, `node -e` and `sh -c` no longer match. This is a speed bump, not a boundary. If the pinned script or directory is writable by the user, an agent can edit the script (or, with `-m`, plant a module in the working directory) and run it. The real boundary is a root-owned script plus a locked profile. A `-m` pin needs the module to be installed in the interpreter's own site-packages. For such entries kasa sets `PYTHONSAFEPATH=1` in the child so Python does not put the working directory on `sys.path`; Python before 3.11 ignores it and still adds the working directory, so a `-m` pin gives no protection there. Even in a locked profile the boundary holds only with an absolute path pin to a root-owned script (`/usr/bin/python3 /usr/local/libexec/x/run.py`): `-m module` and bare file names are resolved against the working directory, which the agent controls, so they are not a boundary even when locked. A bare interpreter entry stays equivalent to exposing the secrets. kasa now warns about such entries in unlocked profiles (on stderr from `kasa profile ls`, `kasa run` and `kasa profile test`, with a `NOTE run <profile> risky allow entry` audit line); the warning never blocks a command and cannot be silenced, because an agent could switch it off.
- **Tool configuration files are outside the environment filter.** Programs read configuration from files under `$HOME` (`.gitconfig`, `.npmrc`, `.netrc`, shell startup files, ...). An agent that can write those files can influence an allowed tool even though the environment is filtered.
- **Symlink race between check and exec.** The allow check resolves a path and then executes that path; a symlink inside a trusted directory could be retargeted between the check and the `exec`. Trusted directories that are user-writable are an accepted residual risk of which this race is a subset.
- **User-writable trusted directories and binary.** Directories such as `~/.local/bin` and the installed `kasa` binary are writable by the same user.
- **Backups are only as strong as their password.** Anyone holding a backup file can try to crack it offline; scrypt makes this expensive but cannot save a weak password. Keep backups private and use a long password.

## Reporting a vulnerability

Please report vulnerabilities privately using GitHub's **private vulnerability reporting**: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue or pull request for a suspected vulnerability.

Include the kasa version (`kasa version`), your macOS version, what you expected, what happened, and the smallest steps to reproduce. Please do not include real secrets in a report.

You can expect an acknowledgement within a few days. Reports about the documented residual risks above are welcome as hardening ideas, but they are known and are not treated as new vulnerabilities.

## Supported versions

Only the latest release receives security fixes.
