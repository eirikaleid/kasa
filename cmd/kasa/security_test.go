package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

// cliYaz / cliOku: via the security CLI, the way the old kasa (and a user by
// hand) did it. The values are fake test data; being in argv is not a problem here.
func cliYaz(t *testing.T, svc, acct, deger string) {
	t.Helper()
	out, err := exec.Command("/usr/bin/security", "add-generic-password",
		"-s", svc, "-a", acct, "-w", deger, "-U", testKeychainYolu).CombinedOutput()
	if err != nil {
		t.Fatalf("security add-generic-password: %v %s", err, out)
	}
}

func cliOku(t *testing.T, svc, acct string) (string, error) {
	t.Helper()
	out, err := exec.Command("/usr/bin/security", "find-generic-password",
		"-s", svc, "-a", acct, "-w", testKeychainYolu).Output()
	return strings.TrimRight(string(out), "\n"), err
}

// Backward compatibility: items written with `security add-generic-password`
// are read/updated/deleted by the new code; items written by the new code are
// read with the security CLI. The same holds for the backup-password service.
func TestGeriyeUyumCLIveFramework(t *testing.T) {
	_, parola := geciciKasa(t)

	// old -> new
	cliYaz(t, service, "old/cli", "old-value 1")
	if v, err := kcGet("old/cli"); err != nil || v != "old-value 1" {
		t.Fatalf("item written via the CLI could not be read: %q %v", v, err)
	}
	if keys, err := kcList(); err != nil || len(keys) != 1 || keys[0] != "old/cli" {
		t.Fatalf("ls: %v %v", keys, err)
	}
	if err := kcSet("old/cli", "updated-value"); err != nil {
		t.Fatalf("CLI item could not be updated: %v", err)
	}
	if v, err := cliOku(t, service, "old/cli"); err != nil || v != "updated-value" {
		t.Fatalf("updated value could not be read via the CLI: %q %v", v, err)
	}
	if v, _ := kcGet("old/cli"); v != "updated-value" {
		t.Fatalf("updated value: %q", v)
	}

	// new -> old
	if err := kcSet("new/item", "new value !$`\"'"); err != nil {
		t.Fatal(err)
	}
	if v, err := cliOku(t, service, "new/item"); err != nil || v != "new value !$`\"'" {
		t.Fatalf("item written via the framework could not be read via the CLI: %q %v", v, err)
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
	if _, err := cliOku(t, service, "old/cli"); err == nil {
		t.Fatal("the deleted item can still be read via the CLI")
	}
	if _, err := kcGet("old/cli"); !errors.Is(err, errAnahtarYok) {
		t.Fatalf("deleted item: %v", err)
	}

	// Backup password: an old password (9 characters, from before the 12-character
	// rule) stored via the CLI -> the path export uses accepts it.
	const eskiParola = "Qx.904417"
	cliYaz(t, yedekParolaService, yedekParolaAccount, eskiParola)
	if p, kaynak, err := yedekParolasiCoz(); err != nil || p != eskiParola || kaynak != "keychain" {
		t.Fatalf("old backup password was not accepted: %q %q %v", p, kaynak, err)
	}
	if yedekParolaKusuru(eskiParola) == "" {
		t.Fatal("a 9-character password passed the NEW rule")
	}
	if err := yedekParolaYaz("New.Password-2026"); err != nil {
		t.Fatal(err)
	}
	if v, err := cliOku(t, yedekParolaService, yedekParolaAccount); err != nil || v != "New.Password-2026" {
		t.Fatalf("new backup password could not be read via the CLI: %q %v", v, err)
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

	c := &Config{Hedefler: []string{t.TempDir()}}
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

func TestParolaSatiriCoz(t *testing.T) {
	durumlar := []struct{ girdi, beklenen string }{
		{"password: \"abc\"\n", "abc"},
		{"password: 0x7369666E  \"sifn\"\n", "sifn"},
		{"password: \n", ""},
		{"keychain: \"x\"\npassword: \"a\"b\"\n", `a"b`},
	}
	for _, d := range durumlar {
		v, err := parolaSatiriCoz([]byte(d.girdi))
		if err != nil || v != d.beklenen {
			t.Errorf("%q -> %q, %v (expected %q)", d.girdi, v, err, d.beklenen)
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
