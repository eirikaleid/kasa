package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestMain: no test touches the real vault, the login keychain, or the real
// home directory.
//   - keychain path: a temporary, nonexistent file (a test that needs a real
//     keychain sets up its own under t.TempDir() with geciciKasa)
//   - audit / profiles.json / state: a temporary home directory
//   - KASA_SOR is unset and an agent marker is set: no test opens a password dialog.
func TestMain(m *testing.M) {
	// The test binary is also the masker that calistir starts (`<binary> __maske`).
	if len(os.Args) > 1 && os.Args[1] == "__maske" {
		testEvDizini = os.Getenv("KASA_TEST_RUN_EV")
		if testEvDizini == "" {
			os.Exit(97) // never write to the real audit log
		}
		if err := cmdMaske(os.Args[2:]); err != nil {
			os.Stderr.WriteString("masker: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	ev, err := os.MkdirTemp("", "kasa-test-ev-")
	if err != nil {
		panic(err)
	}
	testEvDizini = ev
	testKeychainYolu = filepath.Join(ev, "yok", "kasa.keychain-db")
	os.Unsetenv("KASA_SOR")
	if agentName() == "" {
		os.Setenv("AI_AGENT", "go-test")
	}
	kod := m.Run()
	os.RemoveAll(ev)
	os.Exit(kod)
}

func kasaYoluTest(t *testing.T, yol string) {
	t.Helper()
	eski := testKeychainYolu
	testKeychainYolu = yol
	t.Cleanup(func() { testKeychainYolu = eski })
}

func aramaListesi(t *testing.T) string {
	t.Helper()
	out, err := sec("list-keychains", "-d", "user")
	if err != nil {
		t.Fatalf("could not read the search list: %v", err)
	}
	return out
}

// geciciKasa: sets up a temporary vault under t.TempDir() with kcCreate (the
// production path). The user's keychain search list must be the SAME before
// and after setup, and after deletion. The keychain is deleted when the test ends.
func geciciKasa(t *testing.T) (yol, parola string) {
	t.Helper()
	once := aramaListesi(t)
	d := kanonikTemp(t)
	yol = filepath.Join(d, "kasa.keychain-db")
	kasaYoluTest(t, yol)
	parola = "temporary-test-password-1"
	if err := kcCreate(parola); err != nil {
		t.Fatalf("could not set up the temporary vault: %v", err)
	}
	t.Cleanup(func() {
		if err := kcKeychainSilYol(yol); err != nil {
			t.Errorf("could not delete the temporary vault: %v", err)
		}
		if son := aramaListesi(t); son != once {
			t.Errorf("search list differs at the end of the test:\nbefore: %s\nafter: %s", once, son)
		}
	})
	if _, err := os.Stat(yol); err != nil {
		t.Fatalf("keychain file is not at the expected path: %v", err)
	}
	if sonra := aramaListesi(t); sonra != once || strings.Contains(sonra, d) {
		t.Fatalf("kcCreate changed the search list:\nbefore: %s\nafter: %s", once, sonra)
	}
	return yol, parola
}

// cliYaz: via the security CLI, the way kasa before 2.5.0 (and a user by hand)
// wrote items: the ACL trusts /usr/bin/security only. The values are fake test
// data; being in argv is not a problem here.
func cliYaz(t *testing.T, svc, acct, deger string) {
	t.Helper()
	cliYazTam(t, svc, acct, deger, svc, "kasa secret", "managed by kasa")
}

func cliYazTam(t *testing.T, svc, acct, deger, etiket, tur, aciklama string) {
	t.Helper()
	out, err := exec.Command("/usr/bin/security", "add-generic-password",
		"-s", svc, "-a", acct, "-w", deger, "-l", etiket, "-D", tur, "-j", aciklama,
		"-U", testKeychainYolu).CombinedOutput()
	if err != nil {
		t.Fatalf("security add-generic-password: %v %s", err, out)
	}
}

// yabanciOku: tries to read an item from ANOTHER process: a copy of this test
// binary re-signed ad-hoc with a different identifier (so a different code
// identity), with interaction disabled. It never opens a dialog; the result is
// the error text the copy printed ("<nil>" if it could read).
func yabanciOku(t *testing.T, svc, acct string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	kopya := filepath.Join(t.TempDir(), "other-process")
	if err := os.WriteFile(kopya, b, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/codesign", "-f", "-s", "-", "-i", "other.process", kopya).CombinedOutput(); err != nil {
		t.Fatalf("codesign: %v %s", err, out)
	}
	cmd := exec.Command(kopya, "-test.run=^TestYabanciYardimci$", "-test.count=1")
	cmd.Env = append(os.Environ(), "KASA_YABANCI_OKU="+testKeychainYolu+"\n"+svc+"\n"+acct)
	out, _ := cmd.CombinedOutput()
	s := string(out)
	if i := strings.Index(s, "YABANCI: "); i >= 0 {
		return strings.SplitN(s[i+len("YABANCI: "):], "\n", 2)[0]
	}
	t.Fatalf("helper process gave no result: %s", s)
	return ""
}

// TestYabanciYardimci: runs only inside yabanciOku's child process.
func TestYabanciYardimci(t *testing.T) {
	a := os.Getenv("KASA_YABANCI_OKU")
	if a == "" {
		t.Skip("helper for yabanciOku")
	}
	p := strings.SplitN(a, "\n", 3)
	_, err := kcOkuYol(p[0], p[1], p[2])
	fmt.Printf("YABANCI: %v\n", err)
}

// aclDokumu: the vault's ACLs (`dump-keychain -a`: attributes and access
// lists, never values, no dialog).
func aclDokumu(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("/usr/bin/security", "dump-keychain", "-a", testKeychainYolu).CombinedOutput()
	if err != nil {
		t.Fatalf("dump-keychain -a: %v %s", err, out)
	}
	return string(out)
}

// Upgrade path: items written with `security add-generic-password` (pre-2.5.0
// ACL) are not readable by kasa until `kasa acl migrate` (aclGocur) deletes and
// rewrites them with kasa's own ACL; afterwards /usr/bin/security is gone from
// the ACL and another process gets errSecAuthFailed without a dialog.
func TestGeriyeUyumCLIveFramework(t *testing.T) {
	_, parola := geciciKasa(t)

	// Values that exercise the read path: UTF-8, newline, tab, quotes, a value
	// that looks like hex.
	degerler := map[string]string{
		"old/cli":    "old-value 1",
		"old/utf8":   "çğüşiö 日本語 ✓",
		"old/nl":     "line1\nline2\n",
		"old/tab":    "a\tb\tc",
		"old/quote":  `say "hi" 'there' $x \ ` + "`" + `cmd`,
		"old/hex":    "deadbeef00ff",
		"old/hex0x":  "0x41424344",
		"old/empty":  "",
		"old/spaces": "  lead and trail  ",
	}
	for k, v := range degerler {
		cliYaz(t, service, k, v)
	}
	cliYazTam(t, service, "old/attrs", "attr-value", "custom label", "custom kind", "custom comment")
	degerler["old/attrs"] = "attr-value"
	const eskiParola = "Qx.904417-ab"
	cliYaz(t, yedekParolaService, yedekParolaAccount, eskiParola)
	toplam := len(degerler) + 1

	oncekiOgeler, err := kcOgeler()
	if err != nil || len(oncekiOgeler) != toplam {
		t.Fatalf("items before: %v %v", oncekiOgeler, err)
	}
	oncekiDokum := aclDokumu(t)

	// old -> new: not readable before migration.
	if v, err := kcGet("old/cli"); err == nil {
		t.Fatalf("kasa read an item bound to /usr/bin/security without migration: %q", v)
	}

	// Dry run: nothing changes, no backup is written.
	yedekDizin := t.TempDir()
	yedek1 := filepath.Join(yedekDizin, "before.age")
	var rapor strings.Builder
	if s, err := aclGocur(&rapor, true, "", nil); err != nil || s.tasinacak != toplam || s.tasindi != 0 || s.hata != 0 {
		t.Fatalf("dry run: %+v %v\n%s", s, err, rapor.String())
	}
	if aclDokumu(t) != oncekiDokum {
		t.Fatal("the dry run changed the vault")
	}
	if _, err := kcGet("old/cli"); err == nil {
		t.Fatal("the dry run changed the ACL")
	}

	// A backup that cannot be written stops the migration before any change.
	engel := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(engel, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	rapor.Reset()
	if _, err := aclGocur(&rapor, false, "Backup.Pass-2026", []string{filepath.Join(engel, "x.age")}); err == nil {
		t.Fatal("migration went ahead although the backup could not be written")
	}
	if aclDokumu(t) != oncekiDokum {
		t.Fatal("a failed backup still changed the vault")
	}

	// The real run.
	rapor.Reset()
	s, err := aclGocur(&rapor, false, "Backup.Pass-2026", []string{yedek1})
	if err != nil || s.tasindi != toplam || s.bagli != 0 || s.hata != 0 {
		t.Fatalf("migration: %+v %v\n%s", s, err, rapor.String())
	}
	satirlar := strings.Split(strings.TrimSpace(rapor.String()), "\n")
	if son := satirlar[len(satirlar)-2]; !strings.Contains(son, yedekParolaService) {
		t.Fatalf("the backup-password item was not moved last:\n%s", rapor.String())
	}
	// Encrypted backup exists, opens, holds every `kasa` item.
	enc, err := os.ReadFile(yedek1)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := openBundle(enc, "Backup.Pass-2026")
	if err != nil {
		t.Fatal(err)
	}
	var yb bundle
	if err := json.Unmarshal(plain, &yb); err != nil {
		t.Fatal(err)
	}
	if len(yb.Secrets) != len(degerler) {
		t.Fatalf("backup holds %d secrets, expected %d", len(yb.Secrets), len(degerler))
	}
	for k, v := range degerler {
		if yb.Secrets[k] != v {
			t.Errorf("backup value of %s differs", k)
		}
		got, err := kcGet(k)
		if err != nil || got != v {
			t.Errorf("%s after migration: %q %v, expected %q", k, got, err, v)
		}
		// An empty value has no encrypted data for the ACL to guard.
		if e := yabanciOku(t, service, k); v != "" && !strings.Contains(e, "-25293") {
			t.Errorf("another process read the migrated %s or failed differently: %s", k, e)
		}
	}
	if p, err := yedekParolaOku(); err != nil || p != eskiParola {
		t.Fatalf("backup password after migration: %q %v", p, err)
	}
	// Attributes survived (label, kind, comment, service, account).
	sonrakiOgeler, err := kcOgeler()
	if err != nil || len(sonrakiOgeler) != toplam {
		t.Fatalf("items after: %v %v", sonrakiOgeler, err)
	}
	var once, sonra []string
	for _, o := range oncekiOgeler {
		once = append(once, fmt.Sprintf("%+v", o))
	}
	for _, o := range sonrakiOgeler {
		sonra = append(sonra, fmt.Sprintf("%+v", o))
	}
	sort.Strings(once)
	sort.Strings(sonra)
	if strings.Join(once, "\n") != strings.Join(sonra, "\n") {
		t.Fatalf("attributes changed:\nbefore:\n%s\nafter:\n%s", strings.Join(once, "\n"), strings.Join(sonra, "\n"))
	}
	if d := aclDokumu(t); strings.Contains(d, "/usr/bin/security") {
		t.Fatalf("/usr/bin/security is still in the ACL after migration:\n%s", d)
	}

	// Idempotent: the second run changes nothing and writes no backup.
	rapor.Reset()
	if s, err := aclGocur(&rapor, false, "Backup.Pass-2026", []string{filepath.Join(yedekDizin, "second.age")}); err != nil || s.bagli != toplam || s.tasindi != 0 {
		t.Fatalf("second migration was not a no-op: %+v %v\n%s", s, err, rapor.String())
	}
	if _, err := os.Stat(filepath.Join(yedekDizin, "second.age")); err == nil {
		t.Fatal("the no-op run wrote a backup")
	}
	if keys, err := kcList(); err != nil || len(keys) != len(degerler) {
		t.Fatalf("ls: %v %v", keys, err)
	}
	for k := range degerler {
		if k != "old/cli" {
			if err := kcDelete(k); err != nil {
				t.Fatalf("delete %s: %v", k, err)
			}
		}
	}
	if err := kcSet("old/cli", "updated-value"); err != nil {
		t.Fatalf("migrated item could not be updated: %v", err)
	}
	if v, _ := kcGet("old/cli"); v != "updated-value" {
		t.Fatalf("updated value: %q", v)
	}

	// New items: bound to kasa from the start; no other process reads them.
	if err := kcSet("new/item", "new value !$`\"'"); err != nil {
		t.Fatal(err)
	}
	if e := yabanciOku(t, service, "new/item"); !strings.Contains(e, "-25293") {
		t.Fatalf("another process read a new item or failed differently: %s", e)
	}
	if d := aclDokumu(t); strings.Contains(d, "/usr/bin/security") {
		t.Fatalf("a new item trusts /usr/bin/security:\n%s", d)
	}
	if v, err := kcGet("new/item"); err != nil || v != "new value !$`\"'" {
		t.Fatalf("item written via the framework could not be read from kasa: %q %v", v, err)
	}

	// Lookup is case-sensitive: a different spelling is a different key.
	if _, err := kcGet("New/Item"); !errors.Is(err, errAnahtarYok) {
		t.Fatalf("the upper-case spelling matched or the error is wrong: %v", err)
	}

	// Deletion (including an item written via the CLI).
	if err := kcDelete("old/cli"); err != nil {
		t.Fatal(err)
	}
	if _, err := kcGet("old/cli"); !errors.Is(err, errAnahtarYok) {
		t.Fatalf("deleted item: %v", err)
	}

	// Backup password: stored under the 9-character rule, migrated above; the
	// path export uses accepts it.
	if p, kaynak, err := yedekParolasiCoz(); err != nil || p != eskiParola || kaynak != "keychain" {
		t.Fatalf("old backup password was not accepted: %q %q %v", p, kaynak, err)
	}
	if yedekParolaKusuru(eskiParola) != "" {
		t.Fatal("the test password should meet the new rule")
	}
	if err := yedekParolaYaz("New.Password-2026"); err != nil {
		t.Fatal(err)
	}
	if v, err := yedekParolaOku(); err != nil || v != "New.Password-2026" {
		t.Fatalf("new backup password could not be read: %q %v", v, err)
	}
	if keys, _ := kcList(); len(keys) != 1 || keys[0] != "new/item" {
		t.Fatalf("backup password showed up in kasa ls or the list is broken: %v", keys)
	}
	if err := yedekParolaSil(); err != nil {
		t.Fatal(err)
	}
	if yedekParolaVarMi() {
		t.Fatal("backup password was not deleted")
	}

	// Lock: while locked, an agent neither reads nor writes (the EX_TEMPFAIL path); it opens with the password.
	if err := kcLock(); err != nil {
		t.Fatal(err)
	}
	if !isLocked() {
		t.Fatal("did not lock")
	}
	if _, err := kcGet("new/item"); !errors.Is(err, errKilitli) {
		t.Fatalf("read while locked: %v", err)
	}
	if err := kcSet("new/item", "x"); !errors.Is(err, errKilitli) {
		t.Fatalf("write while locked: %v", err)
	}
	if err := kcUnlock("wrong-password"); err == nil {
		t.Fatal("wrong password was accepted")
	}
	if err := kcUnlock(parola); err != nil {
		t.Fatalf("correct password: %v", err)
	}
	if v, err := kcGet("new/item"); err != nil || v != "new value !$`\"'" {
		t.Fatalf("after unlocking: %q %v", v, err)
	}
}

// A read-back that differs from the value written: the value held in memory is
// written again at once, the migration reports an error and stops.
func TestGocGeriOkumaUyusmazligi(t *testing.T) {
	geciciKasa(t)
	cliYaz(t, service, "mm/item", "right value")
	o := ogeKaydi{svc: service, acct: "mm/item", etiket: service, tur: "kasa secret", aciklama: "managed by kasa"}
	cagri := 0
	eski := gocGeriOku
	gocGeriOku = func(yol, svc, acct string) (string, error) {
		cagri++
		if cagri == 1 {
			return "corrupted", nil
		}
		return eski(yol, svc, acct)
	}
	t.Cleanup(func() { gocGeriOku = eski })
	err := ogeTasi(o, "right value")
	if err == nil || !strings.Contains(err.Error(), "written again") {
		t.Fatalf("a mismatch was not reported: %v", err)
	}
	if v, err := kcGet("mm/item"); err != nil || v != "right value" {
		t.Fatalf("the value was not restored after the mismatch: %q %v", v, err)
	}
}

// Secrets and passwords must not enter a child process's argv: these commands
// must never be invoked through the security CLI (source scan; regression gate).
func TestArgvdeSirYok(t *testing.T) {
	dosyalar, _ := filepath.Glob("*.go")
	for _, f := range dosyalar {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, yasak := range []string{`"add-generic-password"`, `"create-keychain"`, `"unlock-keychain"`, `"stty"`} {
			if strings.Contains(string(b), yasak) {
				t.Errorf("%s: %s subprocess is used (secret/password would enter argv)", f, yasak)
			}
		}
	}
}

func ajanIsaretleriniTemizle(t *testing.T) {
	t.Helper()
	for _, e := range os.Environ() {
		ad, _, _ := strings.Cut(e, "=")
		if ajanIsaretiMi(ad) {
			t.Setenv(ad, "")
		}
	}
}

func TestAjanIsaretleri(t *testing.T) {
	durumlar := []struct{ ad, deger, beklenen string }{
		{"CODEX_HOME", "/x", ""},
		{"GEMINI_API_KEY", "x", ""},
		{"AIDER", "x", ""},
		{"CODEX_SANDBOX", "seatbelt", "codex"},
		{"CODEX_THREAD_ID", "1", "codex"},
		{"GEMINI_CLI", "1", "gemini"},
		{"CURSOR_AGENT", "1", "cursor"},
		{"CURSOR_TRACE_ID", "abc", "cursor"},
		{"AIDER_MODEL", "x", "aider"},
		{"CLINE_ACTIVE", "1", "cline"},
		{"GOOSE_PROVIDER", "x", "goose"},
		{"OPENCODE", "1", "opencode"},
		{"CLAUDECODE", "1", "claudecode"},
		{"AI_AGENT", "custom-agent", "custom-agent"},
	}
	for _, d := range durumlar {
		t.Run(d.ad, func(t *testing.T) {
			ajanIsaretleriniTemizle(t)
			if a := agentName(); a != "" {
				t.Fatalf("agent after cleanup: %q", a)
			}
			t.Setenv(d.ad, d.deger)
			if g := agentName(); g != d.beklenen {
				t.Fatalf("%s=%s: %q, expected %q", d.ad, d.deger, g, d.beklenen)
			}
		})
	}
}

// In an agent environment: unlocking with a dialog, deleting the backup password, and a custom export path are rejected.
func TestAjanKapilari(t *testing.T) {
	d := t.TempDir()
	kc := filepath.Join(d, "kasa.keychain-db")
	if err := os.WriteFile(kc, []byte("sahte"), 0o600); err != nil {
		t.Fatal(err)
	}
	kasaYoluTest(t, kc)
	t.Setenv("CLAUDECODE", "1")

	for _, arg := range []string{"--pencere", "--gui"} {
		if err := cmdUnlock([]string{arg}); err == nil || !strings.Contains(err.Error(), "denied") {
			t.Errorf("unlock %s in an agent environment: %v", arg, err)
		}
	}
	if err := cmdYedekParola([]string{"rm"}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("backup-password rm in an agent environment: %v", err)
	}
	if err := cmdYedekParola([]string{"set"}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("backup-password set in an agent environment: %v", err)
	}
	if pencereAcilabilir(true, isAgent(), "1") {
		t.Error("KASA_SOR=1 opened a dialog in an agent environment")
	}

	c := &Config{kilitliHedefler: []string{t.TempDir()}}
	for _, f := range []map[string]string{{"hedef": d}, {"target": d}, {"out": d}, {"cikti": d}} {
		if _, err := exportYollari(nil, f, c, false); err == nil {
			t.Errorf("agent was able to give a custom path: %v", f)
		}
	}
	if _, err := exportYollari([]string{filepath.Join(d, "x.age")}, map[string]string{}, c, false); err == nil {
		t.Error("agent was able to give a positional custom path")
	}
	if y, err := exportYollari(nil, map[string]string{}, c, false); err != nil || len(y) != 1 {
		t.Errorf("configured target did not work for the agent: %v %v", y, err)
	}

	ajanIsaretleriniTemizle(t)
	if y, err := exportYollari(nil, map[string]string{"hedef": d}, c, false); err != nil || len(y) != 1 {
		t.Errorf("human could not give a custom path: %v %v", y, err)
	}
}

func TestYedegiYazSymlinkVeAtomik(t *testing.T) {
	dir := t.TempDir()
	baska := filepath.Join(t.TempDir(), "other.txt")
	if err := os.WriteFile(baska, []byte("must-stay-untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	yol := filepath.Join(dir, "kasa-yedek-x.age")
	if err := os.Symlink(baska, yol); err != nil {
		t.Fatal(err)
	}
	for _, ustune := range []bool{false, true} {
		if err := yedegiYaz(yol, []byte("yeni"), ustune); err == nil {
			t.Fatalf("wrote to a symlink target (overwrite=%v)", ustune)
		}
	}
	if b, _ := os.ReadFile(baska); string(b) != "must-stay-untouched" {
		t.Fatalf("the symlink target changed: %q", b)
	}
	normal := filepath.Join(dir, "kasa-yedek-y.age")
	if err := yedegiYaz(normal, []byte("content"), false); err != nil {
		t.Fatal(err)
	}
	girdiler, _ := os.ReadDir(dir)
	for _, g := range girdiler {
		if strings.HasSuffix(g.Name(), ".tmp") {
			t.Errorf("temporary file left behind: %s", g.Name())
		}
	}
}

func TestAuditAlanKacisi(t *testing.T) {
	audit("OK", "get", "sahte\tanahtar\nOK\tget\tbaska", "not\r\nx")
	b, err := os.ReadFile(auditPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(auditPath(), testEvDizini) {
		t.Fatalf("audit is writing to the real home directory: %s", auditPath())
	}
	satirlar := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	son := satirlar[len(satirlar)-1]
	if n := len(strings.Split(son, "\t")); n != 6 {
		t.Fatalf("audit line has %d fields, must be 6: %q", n, son)
	}
	if !strings.Contains(son, `sahte\tanahtar\nOK`) {
		t.Fatalf("no escaping: %q", son)
	}
}

func TestValidKeyASCII(t *testing.T) {
	for _, k := range []string{"mail/pass", "acme/signing/server/key-pass", "gemini/api_key", "a.b/c-d_e"} {
		if err := validKey(k); err != nil {
			t.Errorf("%s was rejected: %v", k, err)
		}
	}
	for _, k := range []string{"Mail/pass", "mail", "/mail/pass", "mail/pass/", "mail//pass", "maıl/pass", "mail/pa ss", "mail/päss"} {
		if validKey(k) == nil {
			t.Errorf("%q was accepted", k)
		}
	}
}

func TestKilitliProfilCiplakAdYok(t *testing.T) {
	if err := kilitliAllowDenetle([]string{"/usr/local/libexec/signer/sign"}); err != nil {
		t.Fatal(err)
	}
	for _, kotu := range []string{"python3", "~/bin/x", "*", "./x", "/usr/bin/../tmp/x", ""} {
		if kilitliAllowDenetle([]string{kotu}) == nil {
			t.Errorf("%q was accepted in a locked profile", kotu)
		}
	}
}

func TestKilitliAnahtarBuyukKucukHarf(t *testing.T) {
	c := &Config{
		Profiles: map[string]Profile{
			"signing": {Secrets: map[string]string{"P": "gizli/ref"}},
			"sahte1":  {Secrets: map[string]string{"X": "Gizli/Ref"}},
			"sahte2":  {Secrets: map[string]string{"X": " GIZLI/REF "}},
		},
		kullaniciAsli: map[string]*Profile{"signing": nil},
		kilitliRef:    map[string]bool{anahtarNormal("gizli/ref"): true},
	}
	for _, ad := range []string{"sahte1", "sahte2"} {
		if _, err := c.get(ad); err == nil {
			t.Errorf("%s reached a locked key via a spelling difference", ad)
		}
	}
}

// Old .age files (taken before the 12-character rule, with a 9-character
// password) keep opening: import applies no password rule.
func TestEskiYedekAcilir(t *testing.T) {
	plain, _ := json.Marshal(bundle{Version: 1, Secrets: map[string]string{"a/b": "c"}})
	enc, err := sealBundle(plain, "Qx.904417")
	if err != nil {
		t.Fatal(err)
	}
	got, err := openBundle(enc, "Qx.904417")
	if err != nil || string(got) != string(plain) {
		t.Fatalf("backup with the old password did not open: %v", err)
	}
}

// The home directory comes from the account record, not from $HOME: even if
// HOME changes, the keychain and profile paths do not.
func TestYollarHOMEdenBagimsiz(t *testing.T) {
	eskiK, eskiE := testKeychainYolu, testEvDizini
	testKeychainYolu, testEvDizini = "", ""
	t.Cleanup(func() { testKeychainYolu, testEvDizini = eskiK, eskiE })
	kOnce, cOnce := keychainPath(), filepath.Dir(filepath.Dir(configPathYol()))
	t.Setenv("HOME", t.TempDir())
	if keychainPath() != kOnce || filepath.Dir(filepath.Dir(configPathYol())) != cOnce {
		t.Fatalf("path followed HOME: %s %s", keychainPath(), configPathYol())
	}
	if !strings.HasPrefix(kOnce, homeDir()+"/") {
		t.Fatalf("keychain path is not under the home directory: %s", kOnce)
	}
}

// Values with Turkish letters, newlines, tabs, quotes, or ones that look
// entirely like hex must be read back byte for byte (previously -w printed a
// value containing unprintable characters as hex).
func TestDegerBaytBaytAyni(t *testing.T) {
	geciciKasa(t)
	degerler := map[string]string{
		"t/turkce":  "şifre-ğüıİöç",
		"t/satir":   "first line\nsecond\tline\n",
		"t/tirnak":  `a"b"c "`,
		"t/hexgibi": "deadbeef0123",
		"t/duz":     "plain-value_123",
		"t/bosluk":  " leading and trailing ",
	}
	for k, v := range degerler {
		if err := kcSet(k, v); err != nil {
			t.Fatalf("could not write %s: %v", k, err)
		}
		got, err := kcGet(k)
		if err != nil {
			t.Fatalf("could not read %s: %v", k, err)
		}
		if got != v {
			t.Errorf("%s: wrote %q, read %q", k, v, got)
		}
	}
}

// An agent cannot change an existing secret with `kasa add`; it can add a new key.
func TestAjanVarOlaniDegistiremez(t *testing.T) {
	geciciKasa(t)
	if err := kcSet("t/existing", "first"); err != nil {
		t.Fatal(err)
	}
	if err := eklemeKapisi("t/existing"); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("agent was able to change an existing secret: %v", err)
	}
	if err := eklemeKapisi("t/new"); err != nil {
		t.Fatalf("agent could not add a new key: %v", err)
	}
	if v, _ := kcGet("t/existing"); v != "first" {
		t.Fatalf("value changed: %q", v)
	}
}
