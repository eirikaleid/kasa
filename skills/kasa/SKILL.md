---
name: kasa
description: Use when a command needs an API key, token, password or other credential (for example gh, aws, a deploy script, sending mail via SMTP). Runs the command through kasa so the secret is injected without the agent ever seeing it. Also use when the user mentions kasa, secrets or credentials, or when you are tempted to ask the user to paste a token.
---

# kasa: use secrets without seeing them

`kasa` stores the user's secrets in a separate locked macOS keychain. Use it whenever a task needs a credential. Never ask the user to paste a secret into the conversation.

## Rules

1. Run credentialed commands as `kasa run <profile> -- <command> [args]`. The profile's secrets become environment variables of that one command.
2. **Never run `kasa get`**, `kasa unlock`, `kasa rm`, `kasa import` or `kasa backup-password set|rm`. They are human-only. Never try `security find-generic-password` or any other way to read the keychain.
3. If `kasa` exits with **75**, the keychain is locked. Ask the user to run `kasa unlock` (or `kasa unlock --gui`) in their own terminal, then retry once. Do not loop.
4. Do not widen a profile's `allow` list or edit hosts in `~/.config/kasa/profiles.json` unless the user explicitly asks.
5. Never print or log the environment of a `kasa run` process.

## Discover what exists

```bash
kasa status        # locked or unlocked
kasa ls            # key names only
kasa profile ls    # profiles, their env var names and allowed commands
```

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
- "profile not found": check `kasa profile ls`.

kasa's messages are currently printed in Turkish.
