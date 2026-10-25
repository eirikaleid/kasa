package main

import (
	"path/filepath"
	"strings"
)

// Trust settings fixed at build time. Deliberately NOT in the config file:
// ~/.config/kasa/profiles.json is writable by the user (and by the agent); if
// the trusted-directory list were read from there, an agent could add its own
// directory and bypass the allow check. To change them, rebuild:
//
//	make install TRUSTED_DIRS="~/bin:~/dotfiles/bin" DEV_ROOT="~/Developer"
var (
	// trustedDirsFlag: extra trusted directories separated by ":" ("~/" is supported).
	// Bare allow entries can also be resolved in these directories; they also
	// go into run's PATH.
	trustedDirsFlag = ""
	// devRootFlag: project root (e.g. "~/Developer"). Disabled when empty. When
	// set, <root>/**/.venv/bin and <root>/**/venv/bin directories count as
	// trusted, and symlinks in a trusted directory may point to a target under
	// the root.
	devRootFlag = ""
)

// ekGuvenilenDizinler: trustedDirsFlag expanded against the home directory, as absolute paths.
func ekGuvenilenDizinler(home string) []string {
	var out []string
	for _, d := range strings.Split(trustedDirsFlag, ":") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "~") && home == "" {
			continue
		}
		d = tildeAc(d, home)
		if filepath.IsAbs(d) {
			out = append(out, filepath.Clean(d))
		}
	}
	return out
}

// gelistirmeKoku: devRootFlag as an absolute path; "" if disabled.
func gelistirmeKoku(home string) string {
	d := strings.TrimSpace(devRootFlag)
	if d == "" || (strings.HasPrefix(d, "~") && home == "") {
		return ""
	}
	d = tildeAc(d, home)
	if !filepath.IsAbs(d) {
		return ""
	}
	return filepath.Clean(d)
}
