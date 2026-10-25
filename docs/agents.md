# Using kasa with AI coding agents

kasa lets an agent run commands that need credentials without seeing the credentials. The agent-side guard in kasa (agent marker variables plus a TTY check) is a best-effort barrier. An agent running as your user can bypass it if it is confused or prompt-injected. The reliable boundaries are the locked keychain, **your agent's permission rules** and root-owned locked profiles, so configure the agent too. See [SECURITY.md](../SECURITY.md).

## The rules to give every agent

1. Never ask the user to paste a secret.
2. Run credentialed commands with `kasa run <profile> -- <command>`.
3. Never call `kasa get`, `kasa unlock`, `kasa rm`, `kasa import`, or read the keychain with `security`.
4. Exit code 75 means locked: ask the human to run `kasa unlock`.

The same text is in [AGENTS.md](../AGENTS.md).

## Claude Code

### Permissions

Add to `~/.claude/settings.json` (all projects) or `.claude/settings.json` (one project):

```json
{
  "permissions": {
    "allow": [
      "Bash(kasa run:*)",
      "Bash(kasa ls)",
      "Bash(kasa status)"
    ],
    "deny": [
      "Bash(kasa get:*)",
      "Bash(kasa rm:*)",
      "Bash(kasa unlock:*)",
      "Bash(kasa import:*)",
      "Bash(security find-generic-password:*)"
    ]
  }
}
```

You may also want to deny `Bash(kasa backup-password:*)`, `Bash(security dump-keychain:*)` and `Bash(security export:*)`. Deny rules win over allow rules.

### Skill

The skill teaches Claude when and how to use kasa. Copy it into your skills directory:

```bash
mkdir -p ~/.claude/skills/kasa
cp skills/kasa/SKILL.md ~/.claude/skills/kasa/SKILL.md
```

For a single project, use `.claude/skills/kasa/SKILL.md` inside that project instead. Start a new session to load it.

### Instructions file

If you prefer instructions over a skill, paste the contents of [AGENTS.md](../AGENTS.md) into your `CLAUDE.md`.

## Codex

Codex reads `AGENTS.md`. Copy this repository's [AGENTS.md](../AGENTS.md) into the project root, or append it to your existing file:

```bash
cat AGENTS.md >> /path/to/your/project/AGENTS.md
```

For user-wide rules, put the text in `~/.codex/AGENTS.md`. Use Codex's own approval and sandbox settings so that it must ask before running `kasa get`, `kasa unlock` or `security`; see the Codex documentation for the current options.

## Cursor

Create a rule file, for example `.cursor/rules/kasa.mdc`:

```markdown
---
description: Use kasa for any command that needs a credential
alwaysApply: true
---

- Never ask the user to paste a secret (API key, token, password).
- Run commands that need credentials as `kasa run <profile> -- <command>`.
- Never run `kasa get`, `kasa unlock`, `kasa rm` or `kasa import`, and never read the keychain with `security`.
- If kasa exits with code 75 the keychain is locked: ask the user to run `kasa unlock` themselves.
- Discover what exists with `kasa ls` and `kasa profile ls`.
```

In Cursor's settings, keep command auto-run restricted (allow-list mode) and do not allow-list `kasa get`, `kasa unlock` or `security`.

## Gemini CLI and other agents

Put the rules from [AGENTS.md](../AGENTS.md) into the agent's instruction file (for Gemini CLI, `GEMINI.md`) and use whatever command allow/deny mechanism the tool offers for the patterns in the Claude Code example above.

## For high-value secrets

Use a root-owned locked profile (`/usr/local/etc/kasa/profiles.json`, see the [README](../README.md#profiles)) and list absolute paths in `allow`. Do not allow interpreters (`python3`, `bash`, `node`) in profiles that hold valuable secrets.
