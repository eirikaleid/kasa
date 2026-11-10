package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// gercekTemp: t.TempDir() without symlinks (/var -> /private/var on macOS).
func gercekTemp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func yurutulebilirYaz(t *testing.T, yol string) {
	t.Helper()
	if err := os.WriteFile(yol, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// Finding 1: a symlink to the allowed binary matches an unlocked profile (venv
// setups) but not a locked one, where it could be swapped before exec.
func TestKilitliSymlinkKomutReddedilir(t *testing.T) {
	d := gercekTemp(t)
	gercek := filepath.Join(d, "tool")
	yurutulebilirYaz(t, gercek)
	link := filepath.Join(d, "x")
	if err := os.Symlink(gercek, link); err != nil {
		t.Fatal(err)
	}
	allow := []string{gercek}
	if ok, _, neden, _ := izinVerKilit(allow, link, nil, "", true); ok {
		t.Error("locked profile accepted a symlink to the allowed binary")
	} else if !strings.Contains(neden, "symlink") {
		t.Errorf("reason does not mention symlinks: %s", neden)
	}
	if ok, _, _, _ := izinVerKilit(allow, gercek, nil, "", true); !ok {
		t.Error("locked profile refused the exact allowed path")
	}
	if ok, _, _, _ := izinVerKilit(allow, link, nil, "", false); !ok {
		t.Error("unlocked profile no longer accepts a symlink (venv behaviour changed)")
	}
	// Allow entry is itself a symlink (unlocked: venv); only the exact path matches when locked.
	if ok, _, _, _ := izinVerKilit([]string{link}, gercek, nil, "", true); ok {
		t.Error("locked profile matched through the allow entry's symlink")
	}
	if ok, _, _, _ := izinVerKilit([]string{link}, gercek, nil, "", false); !ok {
		t.Error("unlocked profile: allow symlink no longer matches its target")
	}
}

// Finding 1, pinned arguments: the locked profile hands the child the resolved
// path that was checked, so retargeting the caller's symlink afterwards has no
// effect. Unlocked profiles get the arguments back unchanged.
func TestKilitliSabitArgumanCozulmusYol(t *testing.T) {
	d := gercekTemp(t)
	bin := filepath.Join(d, "py")
	yurutulebilirYaz(t, bin)
	pin := filepath.Join(d, "pin")
	if err := os.Mkdir(pin, 0o755); err != nil {
		t.Fatal(err)
	}
	icerde := filepath.Join(pin, "run.py")
	disarda := filepath.Join(d, "evil.py")
	yurutulebilirYaz(t, icerde)
	yurutulebilirYaz(t, disarda)
	tekPin := filepath.Join(d, "one.py")
	yurutulebilirYaz(t, tekPin)

	link := filepath.Join(d, "link.py")
	if err := os.Symlink(icerde, link); err != nil {
		t.Fatal(err)
	}
	allow := []string{bin + " " + pin + "/"}
	ok, _, neden, args := izinVerKilit(allow, bin, []string{link, "--flag"}, "", true)
	if !ok {
		t.Fatalf("locked dir pin refused: %s", neden)
	}
	// Swap the symlink to a file outside the pin after the check (the race).
	tmp := filepath.Join(d, "link.tmp")
	if err := os.Symlink(disarda, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, link); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(args, []string{icerde, "--flag"}) {
		t.Errorf("locked: child args = %v, want the resolved path %q", args, icerde)
	}

	link2 := filepath.Join(d, "link2.py")
	if err := os.Symlink(tekPin, link2); err != nil {
		t.Fatal(err)
	}
	ok, _, neden, args = izinVerKilit([]string{bin + " " + tekPin}, bin, []string{link2}, "", true)
	if !ok || !slices.Equal(args, []string{tekPin}) {
		t.Errorf("locked exact pin: ok=%v args=%v (%s), want %q", ok, args, neden, tekPin)
	}

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(icerde, link); err != nil {
		t.Fatal(err)
	}
	_, _, _, args = izinVerKilit(allow, bin, []string{link}, "", false)
	if !slices.Equal(args, []string{link}) {
		t.Errorf("unlocked: args were rewritten: %v", args)
	}
}

// Finding 2: targets come only from the locked file; a target in the
// agent-writable user file is ignored, also for a human-started export.
func TestHedeflerYalnizKilitliDosyadan(t *testing.T) {
	kullanici, kilitli := t.TempDir(), t.TempDir()
	c := &Config{Hedefler: []string{kullanici}, kilitliHedefler: []string{kilitli}}
	if hs := hedefler(c); !slices.Equal(hs, []string{kilitli}) {
		t.Errorf("targets = %v, want only the locked one", hs)
	}
	yollar, err := exportYollari(nil, map[string]string{}, &Config{Hedefler: []string{kullanici}}, false)
	if err == nil {
		t.Errorf("export used a user-file target: %v", yollar)
	}

}

// Finding 2: an agent cannot add or remove a target; the locked file is never
// written by a non-root user and the exact sudo command is printed instead.
func TestHedefEkleSilAjanaKapali(t *testing.T) {
	d := t.TempDir()
	for _, alt := range []string{"add", "rm"} {
		err := cmdHedef([]string{alt, d})
		if err == nil || !strings.Contains(err.Error(), "agent") {
			t.Errorf("target %s in an agent environment: %v", alt, err)
		}
	}

	kilit := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(kilit, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(kilit, 0o700) })
	eski := KilitliProfilYolu
	KilitliProfilYolu = filepath.Join(kilit, "profiles.json")
	t.Cleanup(func() { KilitliProfilYolu = eski })
	err := hedefKaydet("hedef.ekle", "/x/y", []string{"/x/y"})
	if err == nil {
		t.Fatal("wrote into a read-only directory")
	}
	if !strings.Contains(err.Error(), "sudo /bin/mkdir -p") || !strings.Contains(err.Error(), `"hedefler":["/x/y"]`) {
		t.Errorf("no full sudo command: %v", err)
	}

	// Existing file: plutil form with the whole list, single quotes escaped.
	f := filepath.Join(t.TempDir(), "profiles.json")
	os.WriteFile(f, []byte(`{"profiles":{}}`), 0o644)
	k := hedefSudoKomutu(f, []string{"/a", "/b'c"})
	want := `sudo /usr/bin/plutil -replace hedefler -json '["/a","/b'\''c"]' '` + f + `'`
	if k != want {
		t.Errorf("sudo command\n got %s\nwant %s", k, want)
	}
	if k := hedefSudoKomutu(f, nil); !strings.Contains(k, "plutil -remove hedefler") {
		t.Errorf("empty list: %s", k)
	}

	// hedefYaz keeps the other fields and leaves the file world-readable.
	if err := os.WriteFile(f, []byte(`{"profiles":{"p":{"allow":["/bin/ls"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := hedefYaz(f, []string{"/a"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f)
	fi, _ := os.Stat(f)
	if !strings.Contains(string(b), `"/bin/ls"`) || !strings.Contains(string(b), `"hedefler"`) || !strings.Contains(string(b), `"/a"`) || fi.Mode().Perm() != 0o644 {
		t.Errorf("hedefYaz: mode %v, content %s", fi.Mode().Perm(), b)
	}
}

// Finding 3: user site is off only for locked profiles.
func TestKilitliPythonNoUserSite(t *testing.T) {
	if !slices.Contains(sabitliOrtam(nil, "/usr/bin/python3 /opt/x/run.py", true), "PYTHONNOUSERSITE=1") {
		t.Error("locked profile: PYTHONNOUSERSITE=1 missing")
	}
	for _, e := range sabitliOrtam(nil, "python3 -m pkg", false) {
		if strings.HasPrefix(e, "PYTHONNOUSERSITE") {
			t.Error("unlocked profile got PYTHONNOUSERSITE")
		}
	}
	if env := sabitliOrtam(nil, "/usr/bin/python3 -m pkg", true); !slices.Equal(env, []string{"PYTHONSAFEPATH=1", "PYTHONNOUSERSITE=1"}) {
		t.Errorf("locked -m: %v", env)
	}
}
