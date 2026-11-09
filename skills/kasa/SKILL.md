---
name: kasa
description: Use when a command needs an API key, token, password or other credential (for example gh, aws, a deploy script, sending mail via SMTP). Runs the command through kasa so the secret is injected without the agent ever seeing it. Also use when the user mentions kasa, secrets or credentials, or when you are tempted to ask the user to paste a token.
---

# kasa: use secrets without seeing them

`kasa` stores the user's secrets in a separate locked macOS keychain. Use it whenever a task needs a credential. Never ask the user to paste a secret into the conversation.

## Rules

1. Run credentialed commands as `kasa run <profile> -- <command> [args]`. The profile's secrets become environment variables of that one command.
2. **Never run `kasa get`**, `kasa unlock`, `kasa rm`, `kasa which`, `kasa import` or `kasa backup-password set|rm`. They are human-only. Never try `security find-generic-password` or any other way to read the keychain.
3. If `kasa` exits with **75**, the keychain is locked. Ask the user to run `kasa unlock` (or `kasa unlock --gui`) in their own terminal, then retry once. Do not loop.
4. Do not widen a profile's `allow` list or edit hosts in `~/.config/kasa/profiles.json` unless the user explicitly asks.
5. Never print or log the environment of a `kasa run` process.

## Installing kasa

Optional: after building and installing kasa, you may add the shell integration to the user's rc file, once (skip if `kasa shell-init` is already in it). It is an extra layer, not required (`kasa which` takes values only from a hidden prompt). zsh `~/.zshrc` and bash `~/.bashrc` get `eval "$(kasa shell-init zsh|bash)"`, fish `~/.config/fish/config.fish` gets `kasa shell-init fish | source`, pwsh `$PROFILE` gets `kasa shell-init pwsh | Out-String | Invoke-Expression`. If you add it, verify in a new shell that `echo $KASA_HISTORY_GUARD` prints `1`. `kasa shell-init` only prints code, so you may run it.

## Discover what exists

```bash
kasa status        # locked or unlocked
kasa ls            # key names only
kasa profile ls    # profiles, their env var names and allowed commands
kasa profile test <profile> -- <command> [args]   # dry run: allowed? (runs nothing, exit 1 if refused)
```

An allow entry may pin the first arguments (`python3 ~/Developer/x/` allows only scripts below that directory); other arguments are still refused. `kasa profile ls` prints a `warning:` line on stderr for a profile with a risky interpreter entry (`python3`, `npm run`, ... without a pinned path or `-m`), and `kasa run` / `kasa profile test` print one too; it does not block. Tell the user, do not edit the profile yourself.

## Examples

```bash
kasa run github -- gh pr list
kasa run github -- gh pr create --fill
kasa run aws -- aws s3 ls
kasa mail send --profile mail --to someone@example.com --subject "Report" --body "Done."
kasa mail send --profile mail --to someone@example.com --subject "Report" --body-file report.txt
```

## When it fails

- Exit 75 or a "locked" message: ask the human to unlock.
- "not in this profile's allow list": the command is not permitted for that profile. Tell the user; do not look for a workaround.
- "no such profile": check `kasa profile ls`.
