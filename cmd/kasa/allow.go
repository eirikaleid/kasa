package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
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
// Pinned arguments: an entry that contains whitespace is split with
// strings.Fields. The first token is the command (matched by the two rules
// above); the others pin argv[1..n] (argumanSabitle). A bare "python3" entry
// lets the agent run `python3 -c 'print(os.environ)'`; "python3 ~/dir/" lets it
// run only scripts below that directory. Arguments after the pinned prefix are
// free. Entries without whitespace behave exactly as before.
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

// komutEslesir: does one allow token (a bare name or an absolute path)
// match bin? adEslesti: the bare name matched but the binary is not in a trusted
// directory (for the error message).
func komutEslesir(a, bin, gercek, base, home string) (eslesti, adEslesti bool) {
	a = tildeAc(a, home)
	if filepath.IsAbs(a) {
		a = filepath.Clean(a)
		if bin == a || gercek == a {
			return true, false
		}
		if ag, err := gercekYol(a); err == nil && gercek == ag {
			return true, false
		}
		return false, false
	}
	if a == base {
		return guvenilenDizin(bin, home) && hedefGuvenilir(gercek, home), true
	}
	return false, false
}

// yolTokeni: a pinned token that names a path ("/..." or "~/...") rather than plain text.
func yolTokeni(t string) bool {
	return strings.HasPrefix(t, "/") || strings.HasPrefix(t, "~/")
}

// argvGercek: the symlink-resolved path of an argv element, relative to cwd.
// filepath.Abs is not used: it cleans ".." lexically, but the kernel resolves
// ".." after following symlinks, and EvalSymlinks follows the kernel.
func argvGercek(a string) (string, error) {
	if !filepath.IsAbs(a) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		a = cwd + "/" + a
	}
	return filepath.EvalSymlinks(a)
}

// argumanSabitle: do the pinned tokens (an allow entry without its command)
// match the start of args (argv without arg0)? Returns "" on a match, else the
// reason. The reason never includes the argument value.
//   - path token ending in "/": args[i] must be a regular file below that directory
//   - other path token: args[i] must resolve to exactly that path
//   - any other token: plain text, args[i] must be equal
//
// A path argument may not start with "-" (an interpreter would read it as an option).
func argumanSabitle(tokenlar, args []string, home string) string {
	_, r := argumanSabitleCoz(tokenlar, args, home)
	return r
}

// argumanSabitleCoz is argumanSabitle that also returns the resolved form of
// every pinned path argument (index i -> the symlink-free path checked). A
// locked profile passes these to the child instead of what the caller gave, so
// a symlink cannot be retargeted between the check and exec.
func argumanSabitleCoz(tokenlar, args []string, home string) (map[int]string, string) {
	cozulmus := map[int]string{}
	for i, t := range tokenlar {
		n := i + 1
		if i >= len(args) {
			return nil, fmt.Sprintf("argument %d is missing (expected %q)", n, t)
		}
		a := args[i]
		if !yolTokeni(t) {
			if a != t {
				return nil, fmt.Sprintf("argument %d must be exactly %q", n, t)
			}
			continue
		}
		if a == "" || strings.HasPrefix(a, "-") {
			return nil, fmt.Sprintf("argument %d must be a path for %q, not empty or starting with '-'", n, t)
		}
		if strings.HasPrefix(t, "~/") && home == "" {
			return nil, fmt.Sprintf("%q cannot be expanded (no home directory)", t)
		}
		pin, err := gercekYol(tildeAc(t, home))
		if err != nil {
			return nil, fmt.Sprintf("%q cannot be resolved: %v", t, err)
		}
		gercek, err := argvGercek(a)
		if err != nil {
			return nil, fmt.Sprintf("argument %d does not resolve to an existing file: %v", n, err)
		}
		if !strings.HasSuffix(t, "/") {
			if gercek != pin {
				return nil, fmt.Sprintf("argument %d must resolve to %q", n, t)
			}
			cozulmus[i] = gercek
			continue
		}
		if fi, err := os.Stat(gercek); err != nil || !fi.Mode().IsRegular() {
			return nil, fmt.Sprintf("argument %d must be a regular file below %q", n, t)
		}
		if !strings.HasPrefix(gercek, strings.TrimSuffix(pin, "/")+"/") {
			return nil, fmt.Sprintf("argument %d resolves outside %q", n, t)
		}
		cozulmus[i] = gercek
	}
	return cozulmus, ""
}

// izinVer: may bin (the absolute path from komutCoz) run with args (argv
// without arg0) under this allow list? On success it also returns the matching
// entry (whitespace-normalized, for the audit log); on failure, the reason.
func izinVer(allow []string, bin string, args []string, home string) (bool, string, string) {
	ok, eslesen, neden, _ := izinVerKilit(allow, bin, args, home, false)
	return ok, eslesen, neden
}

// izinVerKilit is izinVer with the profile's lock state. In a locked profile
// (kilitli) an entry matches only when bin is exactly its path: a symlink that
// resolves to the allowed binary is refused, because it could be retargeted
// between this check and exec. A pinned path argument is replaced by its
// resolved path in the returned args for the same reason. Unlocked profiles
// keep the old matching (venv symlinks) and get args back unchanged.
func izinVerKilit(allow []string, bin string, args []string, home string, kilitli bool) (bool, string, string, []string) {
	ok, eslesen, neden, cozulmus := izinVerIc(allow, bin, args, home, kilitli)
	if !ok || !kilitli || len(cozulmus) == 0 {
		return ok, eslesen, neden, args
	}
	yeni := append([]string(nil), args...)
	for i, y := range cozulmus {
		yeni[i] = y
	}
	return ok, eslesen, neden, yeni
}

func izinVerIc(allow []string, bin string, args []string, home string, kilitli bool) (bool, string, string, map[int]string) {
	base := filepath.Base(bin)
	gercek, err := gercekYol(bin)
	if err != nil {
		return false, "", fmt.Sprintf("could not resolve %s: %v", bin, err), nil
	}
	esles := func(t string) (bool, bool) {
		if kilitli {
			// Locked entries are absolute and clean (kilitliAllowDenetle).
			return bin == filepath.Clean(t), false
		}
		return komutEslesir(t, bin, gercek, base, home)
	}
	adEslesti := false
	var argRet []string
	for _, a := range allow {
		if a == "*" {
			return true, a, "", nil
		}
		// An entry with one token (or none) is matched exactly as before, as the raw string.
		tokenlar := strings.Fields(a)
		if len(tokenlar) < 2 {
			eslesti, ad := esles(a)
			if eslesti {
				return true, a, "", nil
			}
			adEslesti = adEslesti || ad
			continue
		}
		eslesti, ad := esles(tokenlar[0])
		adEslesti = adEslesti || ad
		if !eslesti {
			continue
		}
		girdi := strings.Join(tokenlar, " ")
		cozulmus, r := argumanSabitleCoz(tokenlar[1:], args, home)
		if r != "" {
			argRet = append(argRet, fmt.Sprintf("entry %q: %s", girdi, r))
			continue
		}
		return true, girdi, "", cozulmus
	}
	if len(argRet) > 0 {
		return false, "", fmt.Sprintf("'%s' is allowed only with pinned arguments, and none of them matched:\n  %s\n  to change it: kasa profile edit",
			base, strings.Join(argRet, "\n  ")), nil
	}
	if adEslesti {
		return false, "", fmt.Sprintf("'%s' is in the allow list but %s (-> %s) is not in a trusted directory "+
			"(system, homebrew, ~/.local/bin, pipx, and TRUSTED_DIRS / DEV_ROOT given at build time); "+
			"if you need this path, put its absolute path in allow", base, bin, gercek), nil
	}
	if kilitli {
		return false, "", fmt.Sprintf("'%s' is not in this locked profile's allow list (%v)\n  a locked profile matches only the exact path in allow, not a symlink to it", bin, allow), nil
	}
	return false, "", fmt.Sprintf("'%s' is not in this profile's allow list (%v)\n  to add it: kasa profile edit", base, allow), nil
}

// riskliKomutlar: programs that can run code of the agent's choosing (or, for
// curl, read the environment), so an unpinned entry exposes the secrets.
var riskliKomutlar = map[string]bool{
	"python": true, "node": true, "deno": true, "bun": true,
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true,
	"perl": true, "ruby": true, "php": true, "lua": true, "tclsh": true, "rscript": true, "osascript": true,
	"uv": true, "uvx": true, "pipx": true, "npx": true, "npm": true, "pnpm": true, "yarn": true, "java": true,
	"env": true, "xargs": true, "awk": true, "gawk": true, "find": true,
	"curl": true, // 8.3+ reads the environment with `--variable %ENV`
}

// surumEki: version suffix of a program name (python3.13, perl5.38.0, python3.13t).
var surumEki = regexp.MustCompile(`[-_]?[0-9]+(\.[0-9]+)*t?$`)

// riskliGirdi: does this allow entry hand its profile's secrets to a program
// that can run arbitrary code? True when the command (basename, lowercased,
// version suffix removed) is on riskliKomutlar, or the entry is "*", and no
// pinned argument is a path ("/..." or "~/...") or a plain "-m".
func riskliGirdi(girdi string) bool {
	tokenlar := strings.Fields(girdi)
	if len(tokenlar) == 0 {
		return false
	}
	ad := strings.ToLower(filepath.Base(tokenlar[0]))
	if tokenlar[0] != "*" && !riskliKomutlar[surumEki.ReplaceAllString(ad, "")] {
		return false
	}
	for _, t := range tokenlar[1:] {
		if yolTokeni(t) {
			return false
		}
	}
	return !moduSabitli(girdi)
}

// kilitliProfil: is this profile from the root-owned locked file?
func (c *Config) kilitliProfil(ad string) bool {
	_, kilitli := c.kullaniciAsli[ad]
	return kilitli
}

// riskliSatiri: the warning line `kasa profile ls` prints under an unlocked
// profile with risky allow entries, or "" if there is nothing to warn about.
func riskliSatiri(c *Config, ad string, p Profile) string {
	if c.kilitliProfil(ad) {
		return ""
	}
	var q []string
	for _, a := range p.Allow {
		if riskliGirdi(a) {
			q = append(q, fmt.Sprintf("%q", strings.Join(strings.Fields(a), " ")))
		}
	}
	if len(q) == 0 {
		return ""
	}
	return fmt.Sprintf("             warning: %s: interpreter entries, the profile's secrets can be exposed (pin them: \"python3 ~/dir/\")",
		strings.Join(q, ", "))
}

// riskliUyar: for run and profile test. If the matching entry is risky and the
// profile is not locked (a locked profile only accepts absolute paths), prints
// one line to stderr, never stdout, and reports true. It never blocks. There
// is deliberately no environment variable to silence it: an agent could set it.
func riskliUyar(c *Config, profil, eslesen string) bool {
	if c.kilitliProfil(profil) || !riskliGirdi(eslesen) {
		return false
	}
	fmt.Fprintf(os.Stderr, "kasa: warning: allow entry %q in profile %s is an interpreter: "+
		"the profile's secrets can be exposed (pin it: \"python3 ~/dir/\")\n", eslesen, profil)
	return true
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
