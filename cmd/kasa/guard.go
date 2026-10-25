package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Agent detection: BEST EFFORT, NOT a security boundary.
//
// Agent sessions are recognized from environment variables. An agent can strip
// these itself (`env -u CLAUDECODE kasa ...`, `env -i`); an unknown agent may
// leave no marker at all. So these gates stop careless/accidental access and
// the "agent granted itself permission" case; they do not stop a determined
// attacker. The real boundaries are: the vault lock (only a human knows the
// password), root-owned locked profiles, run's allow list and the TTY
// requirement.
//
// The list lives in ONE place: guard (agentName), run's child environment
// (env.go ajanIsaretiMi) and the tests all read from here.
//
// A name ending in "_" is a prefix (every variable starting with it).
// Variables that users commonly define in their own shell are deliberately
// EXCLUDED: CODEX_HOME (Codex config dir), GEMINI_API_KEY (API key) and the
// like; they would mistake a human for an "agent" and lock them out.
var agentMarkers = []string{
	"CLAUDECODE",                   // Claude Code
	"CLAUDE_CODE_ENTRYPOINT",       // Claude Code
	"CLAUDE_CODE_MESSAGING_SOCKET", // Claude Code
	"AI_AGENT",                     // generic convention: value is the agent name
	"CODEX_SANDBOX",                // OpenAI Codex CLI (seatbelt/landlock)
	"CODEX_SANDBOX_NETWORK_DISABLED",
	"CODEX_THREAD_ID", // Codex session
	"CODEX_CI",
	"GEMINI_CLI",      // Google Gemini CLI
	"CURSOR_AGENT",    // Cursor agent
	"CURSOR_TRACE_ID", // Cursor (including the integrated terminal)
	"COPILOT_AGENT",   // GitHub Copilot CLI/agent
	"AIDER_",          // aider (AIDER_MODEL etc.)
	"CLINE_",          // Cline
	"GOOSE_",          // Block goose
	"OPENCODE",        // opencode
	"OPENCODE_",
}

// ajanIsaretiAdi: whether the variable name is an agent marker; if so, the matching list entry.
func ajanIsaretiAdi(ad string) (string, bool) {
	for _, m := range agentMarkers {
		if strings.HasSuffix(m, "_") {
			if strings.HasPrefix(ad, m) && len(ad) > len(m) {
				return m, true
			}
		} else if ad == m {
			return m, true
		}
	}
	return "", false
}

// agentName: short name of the first matching marker (in list order); "" if none.
func agentName() string {
	ortam := os.Environ()
	for _, m := range agentMarkers {
		for _, e := range ortam {
			ad, v, _ := strings.Cut(e, "=")
			if v == "" {
				continue
			}
			if g, ok := ajanIsaretiAdi(ad); !ok || g != m {
				continue
			}
			if m == "AI_AGENT" {
				return v
			}
			k := strings.TrimSuffix(strings.TrimSuffix(m, "_"), "_ENTRYPOINT")
			if i := strings.Index(k, "_"); i > 0 && !strings.HasPrefix(k, "CLAUDE") {
				k = k[:i] // CODEX_SANDBOX -> codex, CURSOR_AGENT -> cursor
			}
			return strings.ToLower(k)
		}
	}
	return ""
}

func isAgent() bool { return agentName() != "" }

// testEvDizini: set ONLY by tests, so audit, profile and state files are not
// written to the real home directory. There is deliberately no env-var override.
var testEvDizini string

// kasaEvi: home directory for kasa's own files (audit, profiles.json, state).
// Taken from the account record (homeDir, getpwuid), not from $HOME, so an
// agent cannot change HOME to make kasa read a fake profile file or write the
// audit log elsewhere.
func kasaEvi() string {
	if testEvDizini != "" {
		return testEvDizini
	}
	return homeDir()
}

// isTTY: whether stdin is a real terminal. ModeCharDevice is not enough:
// /dev/null is also a character device and is the default stdin of
// LaunchAgents; scheduled jobs used to show up as "TTY: yes" (2026-10-04). A
// termios query succeeds only on a real terminal.
func isTTY() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TIOCGETA)
	return err == nil
}

// requireHuman: for commands that expose a raw secret. Refuses to run in an
// agent or TTY-less context.
func requireHuman(op, target string) error {
	if a := agentName(); a != "" {
		audit("DENIED", op, target, "agent environment: "+a)
		return fmt.Errorf("denied: a raw secret cannot be read from an agent session (%s)\n"+
			"  run this command yourself in a separate Terminal window", a)
	}
	if !isTTY() {
		audit("DENIED", op, target, "no TTY")
		return fmt.Errorf("denied: a raw secret can only be read in an interactive terminal (no TTY)")
	}
	return nil
}

func auditPath() string {
	h := kasaEvi()
	if h == "" {
		return ""
	}
	dir := filepath.Join(h, ".local", "state", "kasa")
	os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, "audit.log")
}

// auditAlan: escapes separators inside a field. If a key name, error text or
// agent name (AI_AGENT value) contains \t or \n, it cannot forge a fake
// line/column.
var auditKacis = strings.NewReplacer("\\", "\\\\", "\t", "\\t", "\n", "\\n", "\r", "\\r")

func auditAlan(s string) string { return auditKacis.Replace(s) }

// audit: records every access. The value is never written, only the key name.
func audit(result, op, target, note string) {
	yol := auditPath()
	if yol == "" {
		return
	}
	f, err := os.OpenFile(yol, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	who := agentName()
	if who == "" {
		who = "human"
	}
	fmt.Fprintf(f, "%s\t%s\t%s\t%s\t%s\t%s\n",
		time.Now().Format(time.RFC3339), auditAlan(result), auditAlan(op),
		auditAlan(target), auditAlan(who), auditAlan(note))
}
