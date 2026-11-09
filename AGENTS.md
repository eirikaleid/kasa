# Using kasa (rules for AI agents)

`kasa` holds this user's secrets (API keys, tokens, passwords) in a locked macOS keychain. You can use secrets through it without ever seeing them. Follow these rules.

## Rules

1. **Never ask the user to paste a secret** into the chat, a file, a command line or an environment variable. If a command needs a credential, use kasa.
2. **Run commands that need secrets with `kasa run <profile> -- <command> [args]`.** The secrets are injected into that process as environment variables.
3. **Never call `kasa get`.** It prints raw values and is for humans only. Do not try to work around it (no `security find-generic-password`, no reading the keychain, no reading `profiles.json` for values; it holds only references anyway).
4. **Never run `kasa unlock`, `kasa rm`, `kasa which`, `kasa import` or `kasa backup-password set|rm`.** These are human-only.
5. **Exit code 75 means the keychain is locked.** Stop and ask the human to run `kasa unlock` (or `kasa unlock --gui`) in their own terminal, then retry. Do not loop.
6. Do not edit `~/.config/kasa/profiles.json` to widen an allow list, add an interpreter such as `python3`, `bash` or `node`, or change a host, unless the human explicitly asked for that change.
7. Never print, log, echo or write the environment of a `kasa run` process (`env`, `printenv`, `set`, `ps -E`).

## Installing kasa (for agents doing the install)

Optional: after you build and install the binary (`make install`), you may add the shell integration to the user's shell rc file. It is an extra layer that keeps even rejected `kasa which` lines out of shell history; it is not required, because `kasa which` takes values only from a hidden prompt. Add the line only if it is not already there (idempotent), for the shell the user runs:

```bash
# zsh  (~/.zshrc)
grep -qF 'kasa shell-init' ~/.zshrc 2>/dev/null || echo 'eval "$(kasa shell-init zsh)"' >> ~/.zshrc
# bash (~/.bashrc)
grep -qF 'kasa shell-init' ~/.bashrc 2>/dev/null || echo 'eval "$(kasa shell-init bash)"' >> ~/.bashrc
# fish (~/.config/fish/config.fish)
grep -qF 'kasa shell-init' ~/.config/fish/config.fish 2>/dev/null || echo 'kasa shell-init fish | source' >> ~/.config/fish/config.fish
# pwsh ($PROFILE)
if (-not (Select-String -Path $PROFILE -SimpleMatch 'kasa shell-init' -Quiet -ErrorAction SilentlyContinue)) { Add-Content $PROFILE 'kasa shell-init pwsh | Out-String | Invoke-Expression' }
```

If you add it, verify in a new shell: `zsh -ic 'echo $KASA_HISTORY_GUARD'` (or the same with `bash`/`fish`) prints `1`. `kasa shell-init` only prints code and never reads secrets, so you may run it. Do not touch other lines of the rc file.

## Finding out what is available

```bash
kasa status          # locked or unlocked, who is calling
kasa ls              # key names (no values), e.g. github/token
kasa profile ls      # profiles: which env vars, which commands are allowed
```

A profile lists the commands it allows (`allow`). If the command you need is not allowed, tell the human and let them decide; do not look for another way.

## Examples

```bash
kasa run github -- gh pr list
kasa run github -- gh issue create --title "Bug" --body "Details"
kasa run aws -- aws s3 ls
kasa mail send --profile mail --to someone@example.com --subject "Report" --body-file report.txt
```

`kasa mail send` sends mail using the profile's SMTP settings; you never handle the password.

## If something fails

- `error: vault is locked` / exit 75: ask the human to unlock.
- "not in this profile's allow list": the command is not permitted for that profile; report it.
- "no such profile": run `kasa profile ls` and pick an existing profile or ask the human.
