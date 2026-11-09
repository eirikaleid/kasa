package main

import (
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func calistirilabilir(t *testing.T, p string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// On macOS TempDir lives under /var, and /var is a symlink to /private/var;
// use the canonical path, like a real home directory.
func kanonikTemp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestIzinVer(t *testing.T) {
	home := kanonikTemp(t)
	eskiT, eskiD := trustedDirsFlag, devRootFlag
	trustedDirsFlag, devRootFlag = "~/dotfiles/bin", "~/Developer"
	t.Cleanup(func() { trustedDirsFlag, devRootFlag = eskiT, eskiD })
	dotbin := calistirilabilir(t, filepath.Join(home, "dotfiles", "bin", "deploy"))
	venv := calistirilabilir(t, filepath.Join(home, "Developer", "proje", ".venv", "bin", "python3"))
	pipx := calistirilabilir(t, filepath.Join(home, "Library", "Application Support", "pipx", "venvs", "mytool", "bin", "mytool"))
	localbin := filepath.Join(home, ".local", "bin", "mytool")
	os.MkdirAll(filepath.Dir(localbin), 0o755)
	if err := os.Symlink(pipx, localbin); err != nil {
		t.Fatal(err)
	}
	sahte := calistirilabilir(t, filepath.Join(home, "Desktop", "deploy"))
	tmpSahte := calistirilabilir(t, filepath.Join(t.TempDir(), "deploy"))
	devSahte := calistirilabilir(t, filepath.Join(home, "Developer", "x", "deploy"))
	sahteVenv := calistirilabilir(t, filepath.Join(home, "Developer", "x", "bin", "python3"))
	tmpHedef := calistirilabilir(t, filepath.Join(t.TempDir(), "hedef"))
	kacisLink := filepath.Join(home, ".local", "bin", "deploy")
	if err := os.Symlink(tmpHedef, kacisLink); err != nil {
		t.Fatal(err)
	}
	devHedef := calistirilabilir(t, filepath.Join(home, "Developer", "araclar", "arac"))
	tgLink := filepath.Join(home, ".local", "bin", "arac")
	if err := os.Symlink(devHedef, tgLink); err != nil {
		t.Fatal(err)
	}
	venvDizinTmp := t.TempDir()
	calistirilabilir(t, filepath.Join(venvDizinTmp, "python3"))
	os.MkdirAll(filepath.Join(home, "Developer", "y", ".venv"), 0o755)
	if err := os.Symlink(venvDizinTmp, filepath.Join(home, "Developer", "y", ".venv", "bin")); err != nil {
		t.Fatal(err)
	}
	venvKacis := filepath.Join(home, "Developer", "y", ".venv", "bin", "python3")

	durumlar := []struct {
		ad    string
		allow []string
		bin   string
		izin  bool
	}{
		{"dotfiles/bin bare name", []string{"deploy"}, dotbin, true},
		{"system python3", []string{"python3"}, "/usr/bin/python3", true},
		{"homebrew", []string{"node"}, "/opt/homebrew/bin/node", true},
		{"project venv", []string{"python3"}, venv, true},
		{"~/.local/bin symlink", []string{"mytool"}, localbin, true},
		{"pipx resolved path", []string{"mytool"}, pipx, true},
		{"absolute entry via symlink", []string{"~/.local/bin/mytool"}, localbin, true},
		{"absolute entry via resolved path", []string{"~/.local/bin/mytool"}, pipx, true},
		{"wildcard", []string{"*"}, sahte, true},
		{"~/.local/bin -> ~/Developer (tool)", []string{"arac"}, tgLink, true},

		{"same name on Desktop", []string{"deploy"}, sahte, false},
		{"same name in tmp (PATH hijack)", []string{"deploy"}, tmpSahte, false},
		{"non-venv under Developer", []string{"deploy"}, devSahte, false},
		{"fake bin/python3 under Developer", []string{"python3"}, sahteVenv, false},
		{"not in list", []string{"python3"}, dotbin, false},
		{"absolute entry, different file", []string{"~/dotfiles/bin/deploy"}, sahte, false},
		{"symlink in trusted dir pointing to /tmp", []string{"deploy"}, kacisLink, false},
		{".venv/bin directory symlinked to /tmp", []string{"python3"}, venvKacis, false},
		{"nonexistent file", []string{"deploy"}, filepath.Join(home, "dotfiles", "bin", "yok"), false},
	}
	for _, d := range durumlar {
		ok, _, neden := izinVer(d.allow, d.bin, nil, home)
		if ok != d.izin {
			t.Errorf("%s: allowed=%v, expected %v (%s)", d.ad, ok, d.izin, neden)
		}
	}
}

func TestKomutCozGoreliYol(t *testing.T) {
	d := t.TempDir()
	calistirilabilir(t, filepath.Join(d, "deploy"))
	eski, _ := os.Getwd()
	defer os.Chdir(eski)
	os.Chdir(d)
	bin, err := komutCoz("./deploy")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(bin) {
		t.Fatalf("expected an absolute path: %s", bin)
	}
	if ok, _, _ := izinVer([]string{"deploy"}, bin, nil, t.TempDir()); ok {
		t.Fatal("a same-named file in cwd must not be allowed")
	}
	if ok, _, _ := izinVer([]string{"deploy"}, bin, nil, ""); ok {
		t.Fatal("a same-named file in cwd must not be allowed")
	}
}

// Common tools must not break (machine-dependent; skipped if the path is missing).
func TestGercekKullanimlar(t *testing.T) {
	home := homeDir()
	durumlar := []struct{ allow, arg0 string }{
		{"python3", "/usr/bin/python3"},
		{"python3", "python3"},
		{"node", "node"},
		{"bash", "bash"},
		{"openssl", "openssl"},
		{"uv", "uv"},
		{"gh", "gh"},
	}
	for _, d := range durumlar {
		bin, err := komutCoz(d.arg0)
		if err != nil {
			t.Logf("skipped (not on this machine): %s", d.arg0)
			continue
		}
		if ok, _, neden := izinVer([]string{d.allow}, bin, nil, home); !ok {
			t.Errorf("%s -> %s was rejected: %s", d.arg0, bin, neden)
		}
	}
}

func TestHomeDirHOMEdenBagimsiz(t *testing.T) {
	gercek := homeDir()
	t.Setenv("HOME", t.TempDir())
	if homeDir() != gercek || gercek == "" {
		t.Fatalf("homeDir followed HOME: %q -> %q", gercek, homeDir())
	}
}

func cwdDegistir(t *testing.T, d string) {
	t.Helper()
	eski, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(d); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(eski) })
}

func dosyaYaz(t *testing.T, p string) string {
	t.Helper()
	return calistirilabilir(t, p)
}

func linkYap(t *testing.T, hedef, yol string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(yol), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hedef, yol); err != nil {
		t.Fatal(err)
	}
	return yol
}

// Pinned arguments: "command arg..." entries (allow.go).
func TestIzinVerSabitleme(t *testing.T) {
	home := kanonikTemp(t)
	py := calistirilabilir(t, filepath.Join(home, ".local", "bin", "python3"))
	node := calistirilabilir(t, filepath.Join(home, ".local", "bin", "node"))
	sh := calistirilabilir(t, filepath.Join(home, ".local", "bin", "sh"))
	proj := filepath.Join(home, "proj")
	betik := dosyaYaz(t, filepath.Join(proj, "betik.py"))
	ic := dosyaYaz(t, filepath.Join(proj, "alt", "ic.py"))
	dis := dosyaYaz(t, filepath.Join(home, "dis", "disbetik.py"))
	kardes := dosyaYaz(t, filepath.Join(home, "projx", "kardes", "betik.py"))
	disLink := linkYap(t, dis, filepath.Join(proj, "dislink.py"))
	dizinLink := linkYap(t, filepath.Join(home, "dis"), filepath.Join(proj, "dizinlink"))
	icLink := linkYap(t, betik, filepath.Join(proj, "iclink.py"))
	dizinKendisi := filepath.Join(proj, "alt")
	cwdDegistir(t, proj)

	dizin := "python3 ~/proj/"
	dosya := "python3 ~/proj/betik.py"
	modul := "python3 -m modul"
	durumlar := []struct {
		ad    string
		allow []string
		args  []string
		izin  bool
	}{
		{"dir pin: script in dir", []string{dizin}, []string{betik}, true},
		{"dir pin: script's own arguments are free", []string{dizin}, []string{betik, "-c", "x", "--flag"}, true},
		{"dir pin: script in subdirectory", []string{dizin}, []string{ic}, true},
		{"dir pin: relative path in cwd", []string{dizin}, []string{"betik.py"}, true},
		{"dir pin: symlink inside dir to a file inside dir", []string{dizin}, []string{icLink}, true},

		{"dir pin: -c", []string{dizin}, []string{"-c", "import os;print(os.environ)"}, false},
		{"dir pin: -m x", []string{dizin}, []string{"-m", "x"}, false},
		{"dir pin: relative arg starting with -", []string{dizin}, []string{"-betik.py"}, false},
		{"dir pin: script outside the dir", []string{dizin}, []string{dis}, false},
		{"dir pin: ../ escape (relative)", []string{dizin}, []string{"../dis/disbetik.py"}, false},
		{"dir pin: ../ escape (absolute)", []string{dizin}, []string{proj + "/../dis/disbetik.py"}, false},
		{"dir pin: symlink to a file outside", []string{dizin}, []string{disLink}, false},
		{"dir pin: symlinked directory pointing outside", []string{dizin}, []string{filepath.Join(dizinLink, "disbetik.py")}, false},
		{"dir pin: .. after a symlink is physical, not lexical", []string{dizin}, []string{dizinLink + "/../betik.py"}, false},
		{"dir pin: sibling <dir>x/kardes", []string{dizin}, []string{kardes}, false},
		{"dir pin: a directory, not a file", []string{dizin}, []string{dizinKendisi}, false},
		{"dir pin: nonexistent file", []string{dizin}, []string{filepath.Join(proj, "yok.py")}, false},
		{"dir pin: empty argument", []string{dizin}, []string{""}, false},
		{"dir pin: no argument", []string{dizin}, nil, false},

		{"file pin: the file", []string{dosya}, []string{betik, "x"}, true},
		{"file pin: symlink resolving to the file", []string{dosya}, []string{icLink}, true},
		{"file pin: another file in the same dir", []string{dosya}, []string{ic}, false},
		{"file pin: -c", []string{dosya}, []string{"-c", "x"}, false},

		{"plain token: exact", []string{modul}, []string{"-m", "modul", "arg"}, true},
		{"plain token: other module", []string{modul}, []string{"-m", "baska"}, false},
		{"plain token: -c instead", []string{modul}, []string{"-c", "x"}, false},
		{"plain token: argv too short", []string{modul}, []string{"-m"}, false},
		{"plain token: argv missing", []string{modul}, nil, false},

		{"legacy bare entry: any args", []string{"python3"}, []string{"-c", "x"}, true},
		{"legacy absolute entry: any args", []string{py}, []string{"-c", "x"}, true},
		{"wildcard is only the whole entry", []string{"* x"}, []string{"x"}, false},
		{"other command in pinned entry", []string{"node ~/proj/"}, []string{betik}, false},
		{"pinned entry, absolute command", []string{py + " ~/proj/"}, []string{betik}, true},
		{"second entry matches when the first fails", []string{dizin, modul}, []string{"-m", "modul"}, true},
	}
	for _, d := range durumlar {
		ok, eslesen, neden := izinVer(d.allow, py, d.args, home)
		if ok != d.izin {
			t.Errorf("%s: allowed=%v, expected %v (%s)", d.ad, ok, d.izin, neden)
		}
		if ok && eslesen == "" {
			t.Errorf("%s: no matching entry returned", d.ad)
		}
	}

	for _, d := range []struct {
		ad, girdi, bin string
		args           []string
	}{
		{"node -e", "node ~/proj/", node, []string{"-e", "console.log(process.env)"}},
		{"sh -c", "sh ~/proj/", sh, []string{"-c", "env"}},
	} {
		if ok, _, neden := izinVer([]string{d.girdi}, d.bin, d.args, home); ok {
			t.Errorf("%s must be refused by a pinned entry (%s)", d.ad, neden)
		}
		if ok, _, neden := izinVer([]string{d.girdi}, d.bin, []string{betik}, home); !ok {
			t.Errorf("%s: a script below the pinned dir must pass: %s", d.ad, neden)
		}
	}
	t.Run("~ token with no home", func(t *testing.T) {
		ok, _, neden := izinVer([]string{py + " ~/proj/"}, py, []string{betik}, "")
		if ok || !strings.Contains(neden, "no home directory") {
			t.Fatalf("allowed=%v reason=%q", ok, neden)
		}
	})
	t.Run("matching entry is whitespace-normalized", func(t *testing.T) {
		ok, eslesen, _ := izinVer([]string{"python3 \t ~/proj/\n"}, py, []string{betik}, home)
		if !ok || eslesen != dizin {
			t.Fatalf("allowed=%v entry=%q", ok, eslesen)
		}
	})
	t.Run("rejection names the entry and not the argument value", func(t *testing.T) {
		ok, _, neden := izinVer([]string{dizin}, py, []string{"-c", "gizli-kod"}, home)
		if ok || !strings.Contains(neden, dizin) || strings.Contains(neden, "gizli-kod") {
			t.Fatalf("allowed=%v reason=%q", ok, neden)
		}
	})
	t.Run("pinned entry, command in an untrusted directory", func(t *testing.T) {
		sahte := calistirilabilir(t, filepath.Join(home, "Desktop", "python3"))
		ok, _, neden := izinVer([]string{dizin}, sahte, []string{betik}, home)
		if ok || !strings.Contains(neden, "trusted directory") {
			t.Fatalf("allowed=%v reason=%q", ok, neden)
		}
	})
}

func TestKilitliAllowSabitli(t *testing.T) {
	iyi := []string{
		"/usr/bin/python3 /opt/x/",
		"/usr/bin/python3 /opt/x/bildir.py --flag",
		"/usr/bin/python3 -m modul",
		"/usr/bin/python3 -m trend_radar.bildir",
	}
	for _, a := range iyi {
		if err := kilitliAllowDenetle([]string{a}); err != nil {
			t.Errorf("%q should be accepted: %v", a, err)
		}
	}
	kotu := []string{
		"python3 /opt/x/",
		"~/bin/python3 /opt/x/",
		"/usr/bin/../bin/python3 /opt/x/",
		"/usr/bin/python3 scripts/x.py",
		"/usr/bin/python3 ./x.py",
		"/usr/bin/python3 ../x.py",
		"/usr/bin/python3 ~/x/",
		"/usr/bin/python3 /opt/../x/",
		"/usr/bin/python3 /opt//x/",
		"* /opt/x/",
	}
	for _, a := range kotu {
		if kilitliAllowDenetle([]string{a}) == nil {
			t.Errorf("%q should be rejected", a)
		}
	}
}

func TestProfilTest(t *testing.T) {
	home := kanonikTemp(t)
	py := calistirilabilir(t, filepath.Join(home, ".local", "bin", "python3"))
	betik := dosyaYaz(t, filepath.Join(home, "proj", "betik.py"))
	girdi := py + " " + filepath.Join(home, "proj") + "/"
	c := &Config{Profiles: map[string]Profile{"p": {Allow: []string{girdi}}}}

	calistir := func(args ...string) (string, error) {
		eski := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		err := cmdProfileTest(c, args)
		w.Close()
		os.Stdout = eski
		b, _ := io.ReadAll(r)
		return string(b), err
	}

	out, err := calistir("p", "--", py, betik)
	if err != nil || !strings.Contains(out, "allowed: "+girdi) || !strings.Contains(out, py) {
		t.Fatalf("expected allowed, got err=%v out=%q", err, out)
	}
	if _, err := calistir("p", "--", py, "-c", "x"); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected a denial with a reason, got %v", err)
	}
	if _, err := calistir("yok", "--", py, betik); err == nil {
		t.Fatal("expected an error for an unknown profile")
	}
	if _, err := calistir("p", py, betik); err == nil {
		t.Fatal("expected a usage error without --")
	}
}

func TestRiskliGirdi(t *testing.T) {
	riskli := []string{
		"python3", "python", "python3.13", "/usr/bin/python3", "Python3", "node", "deno", "bun",
		"sh", "bash", "zsh", "dash", "ksh", "fish", "perl", "perl5.38.0", "ruby", "php", "lua5.4", "tclsh8.6", "Rscript", "osascript",
		"uv", "uvx", "pipx", "npx", "npm", "pnpm", "yarn", "java",
		"env", "xargs", "awk", "gawk", "find", "curl", "*",
		"npm run", "pnpm --filter api eval", "uv run sistembir", "python3 -c", "  python3  ",
		"python3 script.py", "/bin/sh -c",
	}
	for _, g := range riskli {
		if !riskliGirdi(g) {
			t.Errorf("%q should be risky", g)
		}
	}
	risksiz := []string{
		"", "gh", "git", "jq", "aws", "kubectl", "python3-config", "pythonista", "nodemon", "shellcheck",
		"python3 ~/x/", "python3 -m pkg", "python3 -m", "sh ~/x/a.sh", "uv run --project ~/x sistembir",
		"/usr/bin/python3 /opt/x/run.py", "python3.13 /opt/x/", "node /opt/x/app.js", "pnpm --dir /opt/x run",
		"bash -m x", "* /opt/x/",
	}
	for _, g := range risksiz {
		if riskliGirdi(g) {
			t.Errorf("%q should not be risky", g)
		}
	}
}

// yakala runs fn with os.Stdout and os.Stderr redirected, and returns both.
func yakala(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	eskiO, eskiE := os.Stdout, os.Stderr
	ro, wo, _ := os.Pipe()
	re, we, _ := os.Pipe()
	os.Stdout, os.Stderr = wo, we
	defer func() { os.Stdout, os.Stderr = eskiO, eskiE }()
	fn()
	wo.Close()
	we.Close()
	bo, _ := io.ReadAll(ro)
	be, _ := io.ReadAll(re)
	return string(bo), string(be)
}

// profilEvi: a temporary home with the given user profiles, no locked file, an empty audit log.
func profilEvi(t *testing.T, profiller map[string]Profile) string {
	t.Helper()
	d := kanonikTemp(t)
	eskiEv, eskiK := testEvDizini, KilitliProfilYolu
	testEvDizini, KilitliProfilYolu = d, filepath.Join(d, "yok.json")
	t.Cleanup(func() { testEvDizini, KilitliProfilYolu = eskiEv, eskiK })
	if err := saveConfig(&Config{Profiles: profiller}); err != nil {
		t.Fatal(err)
	}
	return d
}

func auditOku(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(auditPath())
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

func TestProfilLsRiskliUyari(t *testing.T) {
	profilEvi(t, map[string]Profile{
		"acik":  {Allow: []string{"gh", "python3", "npm run", "python3 ~/x/"}},
		"temiz": {Allow: []string{"gh", "python3 ~/x/", "sh ~/x/a.sh"}},
	})
	out, _ := yakala(t, func() {
		if err := cmdProfile([]string{"ls"}); err != nil {
			t.Error(err)
		}
	})
	const satir = `             warning: "python3", "npm run": interpreter entries, the profile's secrets can be exposed (pin them: "python3 ~/dir/")`
	if strings.Count(out, "warning:") != 1 || !strings.Contains(out, satir+"\n") {
		t.Fatalf("expected one warning line for the risky profile only:\n%s", out)
	}
	// The warning sits directly under the risky profile's own allow line.
	if !strings.Contains(out, "allow : gh python3 npm run python3 ~/x/\n"+satir) {
		t.Fatalf("warning is not under the risky profile's allow line:\n%s", out)
	}
}

// A locked profile gets no warning (it only accepts absolute paths). A real
// locked file needs root, so the locked state is set the way kilitliUygula does.
func TestRiskliKilitliProfildeUyariYok(t *testing.T) {
	p := Profile{Allow: []string{"/usr/bin/python3"}}
	c := &Config{Profiles: map[string]Profile{"k": p, "u": p}, kullaniciAsli: map[string]*Profile{"k": nil}}
	if riskliSatiri(c, "k", p) != "" {
		t.Error("locked profile: ls warning expected to be empty")
	}
	if riskliSatiri(c, "u", p) == "" {
		t.Error("unlocked profile: ls warning expected")
	}
	if _, e := yakala(t, func() {
		if riskliUyar(c, "k", "/usr/bin/python3") {
			t.Error("locked profile: riskliUyar reported a warning")
		}
	}); e != "" {
		t.Errorf("locked profile wrote to stderr: %q", e)
	}
	if _, e := yakala(t, func() {
		if !riskliUyar(c, "u", "/usr/bin/python3") {
			t.Error("unlocked profile: riskliUyar reported no warning")
		}
	}); !strings.Contains(e, "warning") || !strings.HasSuffix(e, "\n") || strings.Count(e, "\n") != 1 {
		t.Errorf("expected exactly one stderr line, got %q", e)
	}
}

// The test goes through cmdProfile, the real dispatch: 2.1.0 shipped
// cmdProfileTest without wiring the "test" subcommand, and a unit test that
// called cmdProfileTest directly did not notice.
func TestProfilTestDispatchUyariVeAudit(t *testing.T) {
	d := kanonikTemp(t)
	py := calistirilabilir(t, filepath.Join(d, "bin", "python3"))
	dizin := filepath.Join(d, "proj")
	betik := dosyaYaz(t, filepath.Join(dizin, "betik.py"))
	pin := py + " " + dizin + "/"
	profilEvi(t, map[string]Profile{
		"riskli": {Allow: []string{py}},
		"pinli":  {Allow: []string{pin}},
	})
	test := func(args ...string) (string, string, error) {
		var err error
		o, e := yakala(t, func() { err = cmdProfile(append([]string{"test"}, args...)) })
		return o, e, err
	}

	// Allowed by a risky entry: warning on stderr, stdout stays the two lines.
	o, e, err := test("riskli", "--", py)
	if err != nil {
		t.Fatal(err)
	}
	if o != "path   : "+py+"\nallowed: "+py+"\n" {
		t.Errorf("stdout is not clean: %q", o)
	}
	if strings.Count(e, "\n") != 1 || !strings.Contains(e, "warning") || !strings.Contains(e, py) {
		t.Errorf("expected a single warning line on stderr, got %q", e)
	}

	// Allowed by a pinned entry: no warning.
	if o, e, err = test("pinli", "--", py, betik); err != nil || e != "" || !strings.Contains(o, "allowed: "+pin) {
		t.Errorf("pinned entry: err=%v stderr=%q stdout=%q", err, e, o)
	}

	// Denied: nothing on stderr from the warning, and an error comes back.
	const gizli = "ARGUMAN-DEGERI-GIZLI"
	if _, e, err = test("pinli", "--", py, "-c", gizli); err == nil || !strings.Contains(err.Error(), "denied") || e != "" {
		t.Errorf("expected a denial, got err=%v stderr=%q", err, e)
	}
	if _, _, err = test("pinli", "--", filepath.Join(d, "yok-komut")); err == nil {
		t.Error("expected an error for a command that does not exist")
	}

	// Audit: OK with the entry, DENIED with a reason, never an argument value.
	log := auditOku(t)
	satirlar := strings.Split(strings.TrimRight(log, "\n"), "\n")
	if len(satirlar) != 4 {
		t.Fatalf("expected 4 audit lines, got %d:\n%s", len(satirlar), log)
	}
	beklenen := []struct{ sonuc, hedef, ayrinti string }{
		{"OK", "riskli", py},
		{"OK", "pinli", pin},
		{"DENIED", "pinli", "command not allowed: " + py},
		{"DENIED", "pinli", "not found: yok-komut"},
	}
	for i, b := range beklenen {
		alanlar := strings.Split(satirlar[i], "\t")
		if len(alanlar) != 6 || alanlar[1] != b.sonuc || alanlar[2] != "profile-test" || alanlar[3] != b.hedef || alanlar[5] != b.ayrinti {
			t.Errorf("audit line %d: want %v, got %q", i, b, satirlar[i])
		}
	}
	for _, yasak := range []string{gizli, "-c", betik} {
		if strings.Contains(log, yasak) {
			t.Errorf("audit log contains an argument value %q:\n%s", yasak, log)
		}
	}
}

// TestRunYardimci is not a test: it is the child process of TestRunUyari. It
// calls cmdRun, which replaces the process with the allowed command.
func TestRunYardimci(t *testing.T) {
	ev := os.Getenv("KASA_TEST_RUN_EV")
	if ev == "" {
		t.Skip("child process of TestRunUyari")
	}
	testEvDizini, KilitliProfilYolu = ev, filepath.Join(ev, "yok.json")
	testKeychainYolu = filepath.Join(ev, "kasa.keychain-db")
	if err := cmdRun(flag.Args()); err != nil {
		os.Stderr.WriteString("run error: " + err.Error() + "\n")
		os.Exit(1)
	}
}

func TestRunUyari(t *testing.T) {
	d := kanonikTemp(t)
	py := calistirilabilir(t, filepath.Join(d, "bin", "python3"))
	dizin := filepath.Join(d, "proj")
	betik := dosyaYaz(t, filepath.Join(dizin, "betik.py"))
	pin := py + " " + dizin + "/"
	ev := profilEvi(t, map[string]Profile{
		"riskli": {Allow: []string{py}},
		"pinli":  {Allow: []string{pin}},
	})
	if err := os.WriteFile(filepath.Join(ev, "kasa.keychain-db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	calistir := func(args ...string) (stdout, stderr string) {
		cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestRunYardimci$", "--"}, args...)...)
		cmd.Env = append(os.Environ(), "KASA_TEST_RUN_EV="+ev)
		var o, e strings.Builder
		cmd.Stdout, cmd.Stderr = &o, &e
		if err := cmd.Run(); err != nil {
			t.Fatalf("kasa run %v: %v\nstdout: %s\nstderr: %s", args, err, o.String(), e.String())
		}
		return o.String(), e.String()
	}

	o, e := calistir("riskli", "--", py)
	if o != "" || strings.Count(e, "\n") != 1 || !strings.Contains(e, "warning") {
		t.Errorf("risky entry: want empty stdout and one stderr line, got stdout=%q stderr=%q", o, e)
	}
	if o, e = calistir("pinli", "--", py, betik); o != "" || e != "" {
		t.Errorf("pinned entry: want no output, got stdout=%q stderr=%q", o, e)
	}

	// The warning does not touch the OK line; a separate NOTE names the entry.
	log := auditOku(t)
	if !strings.Contains(log, "\tNOTE\trun\triskli\t") || !strings.Contains(log, "\trisky allow entry: "+py+"\n") {
		t.Errorf("missing NOTE line:\n%s", log)
	}
	if !strings.Contains(log, "\tOK\trun\triskli\t") || !strings.Contains(log, "\tpython3 ["+py+"]\n") {
		t.Errorf("OK line changed:\n%s", log)
	}
	if strings.Count(log, "risky allow entry") != 1 {
		t.Errorf("NOTE written for the pinned profile too:\n%s", log)
	}
}
