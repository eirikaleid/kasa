package main

import (
	"fmt"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

// The allow check for run.
//
// Checking only the command's basename is not enough: any file named
// `./deploy`, or a fake `deploy` put first with `PATH=/tmp/x:$PATH`, would
// pass the check and could read the profile's secrets from the environment.
//
// Now the command is first resolved to a full path, that path is what gets
// exec'd (PATH is not searched again between check and execution), and
// matching follows these rules:
//   - allow entry is an absolute path ("/..." or "~/..."): the command's
//     path, or its symlink-resolved form, must be exactly this path.
//   - allow entry is a bare name ("python3", "jq"): the basename must match
//     AND the command must live in a trusted directory (guvenilenDizin).
//
// Remaining race: the checked path is exec'd, but the symlink's target can be
// swapped between the check and the exec. Exec'ing the resolved target would
// close that, but Python virtual environments (the .venv/bin/python3 symlink)
// only recognize the venv when run through the symlink path. Trusted
// directories being user-writable is already an accepted residual risk; this
// race is a subset of it.

// guvenilenOnekler: where a bare allow entry resolves to must be under one of these.
func guvenilenOnekler(home string) []string {
	o := []string{
		"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/local/bin/",
		"/opt/homebrew/",
		"/Library/Developer/CommandLineTools/",
		"/Applications/Xcode.app/Contents/Developer/",
	}
	if home != "" {
		o = append(o,
			filepath.Join(home, ".local", "bin")+"/",
			filepath.Join(home, "Library", "Application Support", "pipx", "venvs")+"/",
		)
	}
	for _, d := range ekGuvenilenDizinler(home) {
		o = append(o, d+"/")
	}
	return o
}

// Under the development root (devRootFlag), only the bin directories of
// project virtual environments are trusted: `kasa run <p> -- .venv/bin/python3`.
// If the root is disabled, none are.
func venvBinMi(dir, home string) bool {
	kok := gelistirmeKoku(home)
	if kok == "" || !strings.HasPrefix(dir+"/", kok+"/") {
		return false
	}
	base := filepath.Base(dir)
	parent := filepath.Base(filepath.Dir(dir))
	return base == "bin" && (parent == ".venv" || parent == "venv")
}

func guvenilenDizin(path, home string) bool {
	dir := filepath.Dir(path)
	for _, o := range guvenilenOnekler(home) {
		if strings.HasPrefix(dir+"/", o) {
			return true
		}
	}
	return venvBinMi(dir, home)
}

func tildeAc(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

// komutCoz: turns arg0 into the absolute path to execute (via PATH or a relative path).
func komutCoz(arg0 string) (string, error) {
	bin, err := exec.LookPath(arg0)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func gercekYol(p string) (string, error) {
	return filepath.EvalSymlinks(p)
}

// The symlink's destination must be trusted too: a symlink in a trusted
// directory must not be able to point at a script in /tmp. The development
// root is kept broad here so setups like
// ~/.local/bin/tool -> <root>/project/tool keep working.
func hedefGuvenilir(gercek, home string) bool {
	if guvenilenDizin(gercek, home) {
		return true
	}
	kok := gelistirmeKoku(home)
	return kok != "" && strings.HasPrefix(gercek, kok+"/")
}

// izinVer: may bin (the absolute path from komutCoz) run under this allow list?
func izinVer(allow []string, bin, home string) (bool, string) {
	base := filepath.Base(bin)
	gercek, err := gercekYol(bin)
	if err != nil {
		return false, fmt.Sprintf("could not resolve %s: %v", bin, err)
	}
	adEslesti := false
	for _, a := range allow {
		if a == "*" {
			return true, ""
		}
		a = tildeAc(a, home)
		if filepath.IsAbs(a) {
			a = filepath.Clean(a)
			if bin == a || gercek == a {
				return true, ""
			}
			if ag, err := gercekYol(a); err == nil && gercek == ag {
				return true, ""
			}
			continue
		}
		if a == base {
			adEslesti = true
			if guvenilenDizin(bin, home) && hedefGuvenilir(gercek, home) {
				return true, ""
			}
		}
	}
	if adEslesti {
		return false, fmt.Sprintf("'%s' is in the allow list but %s (-> %s) is not in a trusted directory "+
			"(system, homebrew, ~/.local/bin, pipx, and TRUSTED_DIRS / DEV_ROOT given at build time); "+
			"if you need this path, put its absolute path in allow", base, bin, gercek)
	}
	return false, fmt.Sprintf("'%s' is not in this profile's allow list (%v)\n  to add it: kasa profile edit", base, allow)
}

// homeDir: for the trust boundary, the home directory comes from the account
// record (getpwuid, via cgo), NOT from $HOME, so an agent cannot set
// HOME=/tmp/x and make /tmp/x/.local/bin "trusted". Returns empty if not
// found; with an empty home, home-directory prefixes never match.
// Note: with CGO_ENABLED=0, os/user falls back to $HOME — kasa must be built with cgo.
func homeDir() string {
	u, err := user.Current()
	if err != nil || u.HomeDir == "" || !filepath.IsAbs(u.HomeDir) {
		return ""
	}
	if r, err := filepath.EvalSymlinks(u.HomeDir); err == nil {
		return r
	}
	return filepath.Clean(u.HomeDir)
}
