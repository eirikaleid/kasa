package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Production shape of the signing story (TestImzaliSertifikaYolu uses `go test
// -c` binaries and vaults in TMPDIR, and passed while the real vault broke):
// real kasa binaries from `make build`, two different source versions, the
// same certificate, written and read through the CLI. Temporary keychains
// only, interaction disabled.

// e2eKaynak: a copy of the source tree WITHOUT local.mk (the checkout's
// local.mk would sign test builds with the user's real certificate). surum !=
// "" changes the version constant: a second source version, i.e. a real
// upgrade, not just other link flags.
func e2eKaynak(t *testing.T, surum string) string {
	t.Helper()
	kok, d := repoKok(t), t.TempDir()
	for _, p := range []string{"Makefile", "go.mod", "go.sum", "cmd", "contrib"} {
		if out, err := komutKos(t, "", nil, "/bin/cp", "-R", filepath.Join(kok, p), filepath.Join(d, p)); err != nil {
			t.Fatalf("copying %s: %v\n%s", p, err, out)
		}
	}
	if surum != "" {
		f := filepath.Join(d, "cmd", "kasa", "main.go")
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		yeni := strings.Replace(string(b), `const version = "`+version+`"`, `const version = "`+surum+`"`, 1)
		if yeni == string(b) {
			t.Fatal("version constant not found")
		}
		if err := os.WriteFile(f, []byte(yeni), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// e2eMakeBuild: `make build` in src, signed with the certificate, with the
// vault path and kasa's home pointed at the test directories.
func e2eMakeBuild(t *testing.T, src, out, sha1, kc, vault, ev string, ekLd ...string) {
	t.Helper()
	ld := "LDFLAGS=-s -w -X 'main.testKeychainYolu=" + vault + "' -X 'main.testEvDizini=" + ev + "'" + strings.Join(ekLd, "")
	if o, err := komutKos(t, src, nil, "make", "build", "OUT="+out, "SIGN_IDENTITY="+sha1, "SIGN_KEYCHAIN="+kc, ld); err != nil {
		t.Fatalf("make build: %v\n%s", err, o)
	}
}

// e2eUretimOrtami: a vault at vault (created by this process, the way `kasa
// init` creates it: SecKeychainCreate) and a profile that maps one key.
func e2eUretimOrtami(t *testing.T, vault, ev string, anahtarlar ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(vault), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := kcOlusturYol(vault, []byte("temporary-e2e-password")); err != nil {
		t.Fatalf("vault: %v", err)
	}
	t.Cleanup(func() { kcKeychainSilYol(vault) })
	sec := map[string]string{}
	for i, a := range anahtarlar {
		sec["K"+string(rune('A'+i))] = a
	}
	c := Config{Profiles: map[string]Profile{"p": {Secrets: sec, Allow: []string{"/usr/bin/true"}}}}
	b, _ := json.Marshal(c)
	d := filepath.Join(ev, ".config", "kasa")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "profiles.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func e2eKasa(t *testing.T, bin, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := []string{"-c", `printf '%s' "$KASA_E2E_GIRDI" | "$0" "$@"`, bin}
	return komutKos(t, "", []string{"KASA_E2E_GIRDI=" + stdin}, "/bin/sh", append(cmd, args...)...)
}

// TestUretimYenidenDerleme: 2.5.0 is installed, its items are in the vault,
// a changed source (2.5.1) is built with the same certificate. Where the vault
// lives is the variable: macOS gives a keychain under */Library/Keychains/ the
// newer blob format whose items carry a partition list; for a Team-ID-less
// self-signed binary that list names the writer's cdhash ("cdhash:..."), so
// the certificate-bound ACL alone does not let the rebuild in. A keychain
// elsewhere (the old tests: TMPDIR) has no partition list and the rebuild reads.
func TestUretimYenidenDerleme(t *testing.T) {
	kc1, kcp1 := e2eAnahtarlik(t, "cert1")
	sha1, _, _ := e2eSertifika(t, kc1, kcp1)
	srcA, srcB := e2eKaynak(t, ""), e2eKaynak(t, "9.9.9-rebuild")

	for _, yer := range []struct{ ad, alt string }{
		{"tmp", "kasa.keychain-db"},
		{"library-keychains", "Library/Keychains/kasa.keychain-db"},
		{"appsupport", "Library/Application Support/kasa/kasa.keychain-db"},
	} {
		t.Run(yer.ad, func(t *testing.T) {
			ev := kanonikTemp(t)
			vault := filepath.Join(ev, yer.alt)
			e2eUretimOrtami(t, vault, ev, "e2e/key")
			d := t.TempDir()
			eski, yeni := filepath.Join(d, "kasa-old"), filepath.Join(d, "kasa-new")
			e2eMakeBuild(t, srcA, eski, sha1, kc1, vault, ev)
			e2eMakeBuild(t, srcB, yeni, sha1, kc1, vault, ev)

			if out, err := e2eKasa(t, eski, "sekret-değer", "add", "e2e/key", "--stdin"); err != nil {
				t.Fatalf("old kasa add: %v\n%s", err, out)
			}
			if out, err := e2eKasa(t, eski, "", "run", "p", "--", "/usr/bin/true"); err != nil {
				t.Fatalf("old kasa reads its own item: %v\n%s", err, out)
			}
			_, err := e2eKasa(t, yeni, "", "run", "p", "--", "/usr/bin/true")
			if yer.ad != "library-keychains" {
				if err != nil {
					t.Fatalf("outside */Library/Keychains a rebuild reads: %v", err)
				}
				if yer.ad == "appsupport" {
					e2eNegatif(t, eski, vault, ev)
				}
				return
			}
			if err == nil {
				t.Fatal("under */Library/Keychains a bare rebuild read the old build's item: the partition list is gone, revisit acl devral")
			}
		})
	}
}

// e2eInsan: runs a command the way a human does: on a terminal (pty through
// script(1)), with no agent markers in the environment, girdi typed in.
func e2eInsan(t *testing.T, dir, girdi string, args ...string) (string, error) {
	t.Helper()
	var env []string
	for _, e := range os.Environ() {
		ad, _, _ := strings.Cut(e, "=")
		if _, ok := ajanIsaretiAdi(ad); !ok {
			env = append(env, e)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/script", append([]string{"-q", "/dev/null"}, args...)...)
	cmd.Dir, cmd.Env, cmd.Stdin = dir, env, &yavasGirdi{satirlar: strings.SplitAfter(girdi, "\n")}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestUretimYukseltmeDevri: the upgrade path for a vault under
// */Library/Keychains: the old kasa (installed with make install) writes the
// items and the backup password; a plain `make install` of changed source
// refuses and leaves the old kasa in place; the old kasa exports; `make
// install DEVIR_YEDEK=` hands every item over; the new kasa reads all of
// them, the backup password last; a rerun changes nothing.
func TestUretimYukseltmeDevri(t *testing.T) {
	kc1, kcp1 := e2eAnahtarlik(t, "cert1")
	sha1, _, _ := e2eSertifika(t, kc1, kcp1)
	srcA, srcB := e2eKaynak(t, ""), e2eKaynak(t, "9.9.9-rebuild")
	ev := kanonikTemp(t)
	vault := filepath.Join(ev, "Library", "Keychains", "kasa.keychain-db")
	e2eUretimOrtami(t, vault, ev, "e2e/a", "e2e/b")
	bindir := filepath.Join(t.TempDir(), "bin")
	kur := func(src string, ekstra ...string) (string, error) {
		return e2eKur(t, src, bindir, sha1, kc1, vault, ev, ekstra...)
	}
	if out, err := kur(srcA, "DEVIR_ATLA=", ""); err != nil {
		t.Fatalf("installing the old kasa: %v\n%s", err, out)
	}
	kasa := filepath.Join(bindir, "kasa")
	for _, k := range []string{"e2e/a", "e2e/b"} {
		if out, err := e2eKasa(t, kasa, "değer-"+k, "add", k, "--stdin"); err != nil {
			t.Fatalf("old kasa add: %v\n%s", err, out)
		}
	}
	const yp = "Backup.Pass-2026"
	if out, err := e2eInsan(t, "", yp+"\n"+yp+"\n", kasa, "backup-password", "set"); err != nil {
		t.Fatalf("backup-password set: %v\n%s", err, out)
	}
	eskiBayt, _ := os.ReadFile(kasa)

	out, err := kur(srcB, "DEVIR_ATLA=", "")
	if err == nil || !strings.Contains(out, "DEVIR_YEDEK") {
		t.Fatalf("make install over another build must refuse without a handover: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(kasa); string(b) != string(eskiBayt) {
		t.Fatal("the refused install replaced the old kasa")
	}
	if _, err := os.Stat(kasa + ".new"); err == nil {
		t.Fatal("the refused install left kasa.new behind")
	}
	yedek := filepath.Join(t.TempDir(), "devir.age")
	if out, err := e2eInsan(t, "", "", kasa, "export", yedek); err != nil {
		t.Fatalf("old kasa export: %v\n%s", err, out)
	}
	if out, err := kur(srcB, "DEVIR_YEDEK="+yedek, yp+"\n"); err != nil || !strings.Contains(out, "3 moved") {
		t.Fatalf("make install DEVIR_YEDEK: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(kasa); string(b) == string(eskiBayt) {
		t.Fatal("the new kasa was not installed")
	}
	if out, err := e2eKasa(t, kasa, "", "version"); err != nil || !strings.Contains(out, "9.9.9-rebuild") {
		t.Fatalf("installed version: %v\n%s", err, out)
	}
	if out, err := e2eKasa(t, kasa, "", "run", "p", "--", "/usr/bin/true"); err != nil {
		t.Fatalf("the new kasa cannot read the handed-over items: %v\n%s", err, out)
	}
	// export reads every item AND the stored backup password (no terminal here).
	if out, err := e2eInsan(t, "", "", kasa, "export", filepath.Join(t.TempDir(), "yeni.age")); err != nil {
		t.Fatalf("the new kasa cannot export (backup password not handed over?): %v\n%s", err, out)
	}
	if out, err := e2eInsan(t, "", yp+"\n", kasa, "acl", "devral", yedek); err != nil || !strings.Contains(out, "0 moved, 3 already") {
		t.Fatalf("a rerun must change nothing: %v\n%s", err, out)
	}
	// Same source again: the same cdhash owns the items, no handover asked.
	if out, err := kur(srcB, "DEVIR_ATLA=", ""); err != nil {
		t.Fatalf("reinstalling the same source must not ask for a handover: %v\n%s", err, out)
	}
}

// e2eKur: `make install` of src into bindir, as a human on a terminal.
// ekstra[0] is one more make argument, the rest is typed in.
func e2eKur(t *testing.T, src, bindir, sha1, kc1, vault, ev string, ekstra ...string) (string, error) {
	t.Helper()
	return e2eKurLd(t, "", src, bindir, sha1, kc1, vault, ev, ekstra...)
}

// e2eKurLd: e2eKur with more link flags (test hooks), e.g. " -X 'main.testTasiDur=2'".
func e2eKurLd(t *testing.T, ekLd, src, bindir, sha1, kc1, vault, ev string, ekstra ...string) (string, error) {
	t.Helper()
	args := []string{"make", "install", "BINDIR=" + bindir, "SIGN_IDENTITY=" + sha1, "SIGN_KEYCHAIN=" + kc1,
		"LDFLAGS=-s -w -X 'main.testKeychainYolu=" + vault + "' -X 'main.testEvDizini=" + ev + "'" + ekLd}
	return e2eInsan(t, src, strings.Join(ekstra[1:], ""), append(args, ekstra[0])...)
}

// yavasGirdi: types one line at a time after a pause. Typed ahead, a line is
// flushed when the prompt switches the terminal to no-echo.
type yavasGirdi struct{ satirlar []string }

func (y *yavasGirdi) Read(p []byte) (int, error) {
	for len(y.satirlar) > 0 && y.satirlar[0] == "" {
		y.satirlar = y.satirlar[1:]
	}
	if len(y.satirlar) == 0 {
		time.Sleep(time.Second)
		return 0, io.EOF
	}
	time.Sleep(700 * time.Millisecond)
	n := copy(p, y.satirlar[0])
	y.satirlar[0] = y.satirlar[0][n:]
	return n, nil
}

// e2eNegatif: nobody but kasa gets the value, and no window opens (interaction
// is disabled in-process; the security CLI is only asked to DESCRIBE the ACL).
func e2eNegatif(t *testing.T, kasa, vault, ev string) {
	t.Helper()
	if v, err := kcOkuYol(vault, service, "e2e/key"); err == nil {
		t.Fatalf("the unsigned test process read the item: %q", v)
	}
	if out, _ := e2eKasa(t, e2eAdhoc(t, kasa), "", "run", "p", "--", "/usr/bin/true"); !strings.Contains(out, "-25293") {
		t.Fatalf("an ad-hoc copy must get -25293: %s", out)
	}
	dump, err := komutKos(t, "", nil, "/usr/bin/security", "dump-keychain", "-a", vault)
	if err != nil {
		t.Fatalf("dump-keychain -a: %v\n%s", err, dump)
	}
	if strings.Contains(dump, "/usr/bin/security") {
		t.Fatalf("/usr/bin/security is in the item's ACL:\n%s", dump)
	}
}

// TestUretimKasaTasima (experiment b): the item is written under
// */Library/Keychains, then the FILE is moved to the new place. A build of
// changed source still cannot read it: the partition list is inside the item,
// not bound to the location. That is why `acl tasi` writes the items again
// instead of moving the file.
func TestUretimKasaTasima(t *testing.T) {
	kc1, kcp1 := e2eAnahtarlik(t, "cert1")
	sha1, _, _ := e2eSertifika(t, kc1, kcp1)
	srcA, srcB := e2eKaynak(t, ""), e2eKaynak(t, "9.9.9-rebuild")
	ev := kanonikTemp(t)
	eskiYol := filepath.Join(ev, "Library", "Keychains", "kasa.keychain-db")
	yeniYol := filepath.Join(ev, "Library", "Application Support", "kasa", "kasa.keychain-db")
	e2eUretimOrtami(t, eskiYol, ev, "e2e/key")
	d := t.TempDir()
	a, b := filepath.Join(d, "a"), filepath.Join(d, "b")
	e2eMakeBuild(t, srcA, a, sha1, kc1, eskiYol, ev)
	e2eMakeBuild(t, srcB, b, sha1, kc1, yeniYol, ev)
	if out, err := e2eKasa(t, a, "sekret-değer", "add", "e2e/key", "--stdin"); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if err := os.MkdirAll(filepath.Dir(yeniYol), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(eskiYol, yeniYol); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kcKeychainSilYol(yeniYol) })
	// A moved file is a new keychain to securityd: locked until unlocked.
	if err := kcParolaylaAcYol(yeniYol, []byte("temporary-e2e-password")); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if out, err := e2eKasa(t, b, "", "run", "p", "--", "/usr/bin/true"); err == nil {
		t.Fatalf("a moved keychain file is readable by a rebuild: the partition list follows the location after all, `acl tasi` can be a mv.\n%s", out)
	}
}

// TestUretimYerDegisimi: the 2.5.x -> 2.6.0 step. The old kasa keeps the vault
// under */Library/Keychains; the new default is Application Support, where a
// rebuild reads without a handover. The old vault is moved with `make install
// DEVIR_YEDEK=` (-> acl tasi); afterwards a third source version installs and
// reads the items with no handover at all.
func TestUretimYerDegisimi(t *testing.T) {
	kc1, kcp1 := e2eAnahtarlik(t, "cert1")
	sha1, _, _ := e2eSertifika(t, kc1, kcp1)
	srcA, srcB, srcC := e2eKaynak(t, ""), e2eKaynak(t, "9.9.9-rebuild"), e2eKaynak(t, "9.9.10-rebuild")
	ev := kanonikTemp(t)
	eskiYol := filepath.Join(ev, "Library", "Keychains", "kasa.keychain-db")
	yeniYol := filepath.Join(ev, "Library", "Application Support", "kasa", "kasa.keychain-db")
	e2eUretimOrtami(t, eskiYol, ev, "e2e/a", "e2e/b")
	t.Cleanup(func() { kcKeychainSilYol(yeniYol) })
	bindir := filepath.Join(t.TempDir(), "bin")
	if out, err := e2eKur(t, srcA, bindir, sha1, kc1, eskiYol, ev, "DEVIR_ATLA=1"); err != nil {
		t.Fatalf("installing the old kasa: %v\n%s", err, out)
	}
	kasa := filepath.Join(bindir, "kasa")
	for _, k := range []string{"e2e/a", "e2e/b"} {
		if out, err := e2eKasa(t, kasa, "değer-"+k, "add", k, "--stdin"); err != nil {
			t.Fatalf("old kasa add: %v\n%s", err, out)
		}
	}
	const yp, master = "Backup.Pass-2026", "Master.Pass-2026"
	if out, err := e2eInsan(t, "", yp+"\n"+yp+"\n", kasa, "backup-password", "set"); err != nil {
		t.Fatalf("backup-password set: %v\n%s", err, out)
	}
	eskiBayt, _ := os.ReadFile(kasa)

	// The new kasa says where the vault is instead of pretending there is none.
	yeni := filepath.Join(t.TempDir(), "kasa-new")
	e2eMakeBuild(t, srcB, yeni, sha1, kc1, yeniYol, ev)
	if out, err := e2eKasa(t, yeni, "", "run", "p", "--", "/usr/bin/true"); err == nil || !strings.Contains(out, "acl tasi") {
		t.Fatalf("no hint about the old vault: %v\n%s", err, out)
	}
	out, err := e2eKur(t, srcB, bindir, sha1, kc1, yeniYol, ev, "DEVIR_ATLA=", "")
	if err == nil || !strings.Contains(out, "DEVIR_YEDEK") {
		t.Fatalf("make install must ask for the backup while the vault is at the old place: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(kasa); string(b) != string(eskiBayt) {
		t.Fatal("the refused install replaced the old kasa")
	}
	if _, err := os.Stat(kasa + ".new"); err == nil {
		t.Fatal("the refused install left kasa.new behind")
	}
	yedek := filepath.Join(t.TempDir(), "devir.age")
	if out, err := e2eInsan(t, "", "", kasa, "export", yedek); err != nil {
		t.Fatalf("old kasa export: %v\n%s", err, out)
	}
	if out, err := e2eKur(t, srcB, bindir, sha1, kc1, yeniYol, ev, "DEVIR_YEDEK="+yedek, yp+"\n"+master+"\n"+master+"\n"); err != nil || !strings.Contains(out, "moved: 3 written") {
		t.Fatalf("make install DEVIR_YEDEK: %v\n%s", err, out)
	}
	if _, err := os.Stat(eskiYol); err == nil {
		t.Fatal("the old vault file is still in place")
	}
	if _, err := os.Stat(eskiYol + ".eski"); err != nil {
		t.Fatalf("the old vault was not kept as .eski: %v", err)
	}
	if out, err := e2eKasa(t, kasa, "", "run", "p", "--", "/usr/bin/true"); err != nil {
		t.Fatalf("the new kasa cannot read the moved items: %v\n%s", err, out)
	}
	if out, err := e2eInsan(t, "", "", kasa, "export", filepath.Join(t.TempDir(), "yeni.age")); err != nil {
		t.Fatalf("the new kasa cannot export (backup password not moved?): %v\n%s", err, out)
	}
	// The point: another source version, same certificate, NO handover.
	if out, err := e2eKur(t, srcC, bindir, sha1, kc1, yeniYol, ev, "DEVIR_ATLA=", ""); err != nil || strings.Contains(out, "DEVIR_YEDEK") {
		t.Fatalf("a rebuild at the new place must install without a handover: %v\n%s", err, out)
	}
	if out, err := e2eKasa(t, kasa, "", "version"); err != nil || !strings.Contains(out, "9.9.10-rebuild") {
		t.Fatalf("installed version: %v\n%s", err, out)
	}
	if out, err := e2eKasa(t, kasa, "", "run", "p", "--", "/usr/bin/true"); err != nil {
		t.Fatalf("the rebuilt kasa cannot read the items: %v\n%s", err, out)
	}
	if out, err := e2eInsan(t, "", "", kasa, "export", filepath.Join(t.TempDir(), "uc.age")); err != nil {
		t.Fatalf("the rebuilt kasa cannot export: %v\n%s", err, out)
	}
}

// TestUretimTasiYarim: the move from the old place is cut off in the middle
// (the test hook stops `acl tasi` after 2 of 4 writes; a kill leaves the same
// state). The old file is still there, so every command of the new kasa says
// the move is UNFINISHED, `acl yokla` answers 2, the refused install leaves no
// kasa.new and the old kasa in place; `make install DEVIR_YEDEK=` again reuses
// the new vault, writes the rest and only then keeps the old file as .eski.
func TestUretimTasiYarim(t *testing.T) {
	kc1, kcp1 := e2eAnahtarlik(t, "cert1")
	sha1, _, _ := e2eSertifika(t, kc1, kcp1)
	srcA, srcB := e2eKaynak(t, ""), e2eKaynak(t, "9.9.9-rebuild")
	ev := kanonikTemp(t)
	eskiYol := filepath.Join(ev, "Library", "Keychains", "kasa.keychain-db")
	yeniYol := filepath.Join(ev, "Library", "Application Support", "kasa", "kasa.keychain-db")
	e2eUretimOrtami(t, eskiYol, ev, "e2e/a", "e2e/b", "e2e/c")
	t.Cleanup(func() { kcKeychainSilYol(yeniYol) })
	bindir := filepath.Join(t.TempDir(), "bin")
	if out, err := e2eKur(t, srcA, bindir, sha1, kc1, eskiYol, ev, "DEVIR_ATLA=1"); err != nil {
		t.Fatalf("installing the old kasa: %v\n%s", err, out)
	}
	kasa := filepath.Join(bindir, "kasa")
	for _, k := range []string{"e2e/a", "e2e/b", "e2e/c"} {
		if out, err := e2eKasa(t, kasa, "değer-"+k, "add", k, "--stdin"); err != nil {
			t.Fatalf("old kasa add: %v\n%s", err, out)
		}
	}
	const yp, master = "Backup.Pass-2026", "Master.Pass-2026"
	if out, err := e2eInsan(t, "", yp+"\n"+yp+"\n", kasa, "backup-password", "set"); err != nil {
		t.Fatalf("backup-password set: %v\n%s", err, out)
	}
	eskiBayt, _ := os.ReadFile(kasa)
	yedek := filepath.Join(t.TempDir(), "devir.age")
	if out, err := e2eInsan(t, "", "", kasa, "export", yedek); err != nil {
		t.Fatalf("old kasa export: %v\n%s", err, out)
	}

	const kes = " -X 'main.testTasiDur=2'"
	out, err := e2eKurLd(t, kes, srcB, bindir, sha1, kc1, yeniYol, ev, "DEVIR_YEDEK="+yedek, yp+"\n"+master+"\n"+master+"\n")
	if err == nil || !strings.Contains(out, "stopped by the test hook") {
		t.Fatalf("the first move should have been cut off: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(kasa); string(b) != string(eskiBayt) {
		t.Fatal("the failed install replaced the old kasa")
	}
	if _, err := os.Stat(kasa + ".new"); err == nil {
		t.Fatal("the failed install left kasa.new behind")
	}
	if _, err := os.Stat(eskiYol); err != nil {
		t.Fatalf("the old vault must stay while the move is unfinished: %v", err)
	}
	if _, err := os.Stat(eskiYol + ".eski"); err == nil {
		t.Fatal(".eski exists although the move is unfinished")
	}

	yeni := filepath.Join(t.TempDir(), "kasa-new")
	e2eMakeBuild(t, srcB, yeni, sha1, kc1, yeniYol, ev)
	if out, err := e2eKasa(t, yeni, "", "run", "p", "--", "/usr/bin/true"); err == nil || !strings.Contains(out, "UNFINISHED") {
		t.Fatalf("run must say the move is unfinished: %v\n%s", err, out)
	}
	if out, _ := e2eKasa(t, yeni, "", "status"); !strings.Contains(out, "UNFINISHED") {
		t.Fatalf("status must say the move is unfinished:\n%s", out)
	}
	if out, err := e2eKasa(t, yeni, "", "acl", "yokla"); err == nil || !strings.Contains(out, "move-unfinished") {
		t.Fatalf("acl yokla must answer 2 (move-unfinished): %v\n%s", err, out)
	}

	// The rerun: same command as the first time, no hook; the new vault exists.
	out, err = e2eKur(t, srcB, bindir, sha1, kc1, yeniYol, ev, "DEVIR_YEDEK="+yedek, yp+"\n")
	if err != nil || !strings.Contains(out, "2 written, 2 already there") {
		t.Fatalf("the rerun must write the remaining items: %v\n%s", err, out)
	}
	if _, err := os.Stat(eskiYol); err == nil {
		t.Fatal("the old vault file is still in place after a complete move")
	}
	if _, err := os.Stat(eskiYol + ".eski"); err != nil {
		t.Fatalf("the old vault was not kept as .eski: %v", err)
	}
	if _, err := os.Stat(kasa + ".new"); err == nil {
		t.Fatal("kasa.new left behind after a successful install")
	}
	if out, err := e2eKasa(t, kasa, "", "run", "p", "--", "/usr/bin/true"); err != nil {
		t.Fatalf("the new kasa cannot read the moved items: %v\n%s", err, out)
	}
	if out, err := e2eInsan(t, "", "", kasa, "export", filepath.Join(t.TempDir(), "yeni.age")); err != nil {
		t.Fatalf("the new kasa cannot export: %v\n%s", err, out)
	}
	if out, err := e2eKasa(t, kasa, "", "acl", "yokla"); err != nil {
		t.Fatalf("acl yokla after a complete move: %v\n%s", err, out)
	}
}
