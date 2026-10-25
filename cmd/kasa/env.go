package main

import (
	"fmt"
	"sort"
	"strings"
)

// The environment run hands to the child.
//
// Passing the caller's ENTIRE environment is dangerous: an agent could run
// `DYLD_INSERT_LIBRARIES=/tmp/x.dylib kasa run <p> -- <allowed binary>` to
// load its own code into the allowed binary and read the secret. So it is
// ALWAYS an allowlist:
//
//   - If the profile has an "ortam" (environment) field, that list is used;
//     otherwise varsayilanOrtam. An entry is an exact name or "PREFIX*".
//   - PATH is NOT taken from the caller: it is always guvenliPath (so the
//     allowed tool's subprocesses cannot be hijacked via a fake PATH). PATH
//     cannot appear in a profile list.
//   - Injection variables (enjeksiyonMu) are blocked even if listed; the
//     profile is rejected.
//   - Agent markers (agentMarkers) always pass through, so the agent gates
//     in the child are not blinded.
//   - A caller variable with the same name as a secret is dropped (the first
//     one would win: it would shadow the secret).
//
// Known residual risk (README "run environment"): the secret lives in the
// child's ENVIRONMENT; on macOS a same-user process can read the initial
// environment block via KERN_PROCARGS2 (`ps -E`) even if the child calls
// os.Unsetenv (test: TestPsEIlkOrtamiGosterir).

// varsayilanOrtam: names passed to the child for profiles without an "ortam" field.
var varsayilanOrtam = []string{
	"HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TERM", "COLORTERM", "NO_COLOR", "TZ",
	"LANG", "LC_*", "__CF_USER_TEXT_ENCODING", "SSH_AUTH_SOCK",
}

// guvenliPath: the fixed PATH given to the child (consistent with the trusted directories in allow.go).
func guvenliPath(home string) string {
	d := []string{}
	if home != "" {
		d = append(d, ekGuvenilenDizinler(home)...)
		d = append(d, home+"/.local/bin")
	}
	d = append(d, "/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin")
	return strings.Join(d, ":")
}

// enjeksiyonOnekleri / enjeksiyonAdlari: variables that change the behavior
// of the loader, shell, interpreters and tools so that they run code. None pass.
var enjeksiyonOnekleri = []string{
	"DYLD_", "LD_", "BASH_FUNC_", "PYTHON", "NODE_", "PERL5", "PERLLIB", "RUBY", "GIT_", "SSH_ASKPASS",
	"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "NPM_CONFIG_", "UV_", "PIP_",
}

var enjeksiyonAdlari = map[string]bool{
	"PATH": true, "BASH_ENV": true, "ENV": true, "SHELLOPTS": true, "BASHOPTS": true, "PS4": true,
	"PROMPT_COMMAND": true, "IFS": true, "CDPATH": true, "ZDOTDIR": true, "EDITOR": true, "VISUAL": true,
	"PAGER": true, "BROWSER": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "CURL_CA_BUNDLE": true,
	"REQUESTS_CA_BUNDLE": true, "HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true,
	"http_proxy": true, "https_proxy": true, "all_proxy": true,
}

func enjeksiyonMu(ad string) bool {
	if enjeksiyonAdlari[ad] {
		return true
	}
	for _, o := range enjeksiyonOnekleri {
		if strings.HasPrefix(ad, o) {
			return true
		}
	}
	return false
}

// beyazListedeMi: an entry is an exact name or "PREFIX*".
func beyazListedeMi(ad string, liste []string) bool {
	for _, g := range liste {
		if g == ad || (strings.HasSuffix(g, "*") && len(g) > 1 && strings.HasPrefix(ad, strings.TrimSuffix(g, "*"))) {
			return true
		}
	}
	return false
}

// ortamGecerli: are the entries in the profile allowlist valid (no PATH, no
// injection name/prefix, and no empty or wildcard-only entry).
func ortamGecerli(liste []string) error {
	for _, g := range liste {
		ad := strings.TrimSuffix(g, "*")
		if ad == "" || strings.ContainsAny(ad, "=* ") {
			return fmt.Errorf("invalid environment entry: %q", g)
		}
		if enjeksiyonMu(ad) {
			return fmt.Errorf("environment entry is an injection variable: %q (never passed)", g)
		}
		if strings.HasSuffix(g, "*") {
			for _, o := range enjeksiyonOnekleri {
				if strings.HasPrefix(o, ad) {
					return fmt.Errorf("environment entry covers an injection prefix: %q", g)
				}
			}
			for k := range enjeksiyonAdlari {
				if strings.HasPrefix(k, ad) {
					return fmt.Errorf("environment entry covers an injection name: %q", g)
				}
			}
		}
	}
	return nil
}

func ajanIsaretiMi(ad string) bool {
	_, ok := ajanIsaretiAdi(ad)
	return ok
}

// cocukOrtami: caller's environment (os.Environ format) + profile -> the
// environment that goes to the child. Dropped names (not values) come back as
// the second return value and are written to the audit log (ordinary names
// outside the allowlist are silently not passed and do not bloat the audit).
func cocukOrtami(cagiran []string, p Profile, sirlar map[string]string, home string) (env []string, atilan []string) {
	liste := varsayilanOrtam
	if p.Ortam != nil {
		liste = *p.Ortam
	}
	env = append(env, "PATH="+guvenliPath(home))
	for _, e := range cagiran {
		ad, _, ok := strings.Cut(e, "=")
		if !ok || ad == "" || ad == "PATH" {
			continue
		}
		_, sirAdi := sirlar[ad]
		switch {
		case sirAdi, enjeksiyonMu(ad):
			atilan = append(atilan, ad)
		case ajanIsaretiMi(ad), beyazListedeMi(ad, liste):
			env = append(env, e)
		}
	}
	adlar := make([]string, 0, len(sirlar))
	for k := range sirlar {
		adlar = append(adlar, k)
	}
	sort.Strings(adlar)
	for _, k := range adlar {
		env = append(env, k+"="+sirlar[k])
	}
	return env, atilan
}
