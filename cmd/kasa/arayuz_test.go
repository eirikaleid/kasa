package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// calis: kasaMain with stdout/stderr captured.
func calis(t *testing.T, args ...string) (kod int, out, errOut string) {
	t.Helper()
	out, errOut = yakala(t, func() { kod = kasaMain(args) })
	return
}

func jsonAlanlari(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &m); err != nil {
		t.Fatalf("not JSON: %q: %v", s, err)
	}
	return m
}

func alanAdlari(m map[string]any) []string {
	var k []string
	for a := range m {
		k = append(k, a)
	}
	sort.Strings(k)
	return k
}

// TestStatusSozlesmesi: EXTERNAL SCRIPTS depend on these exit codes and JSON
// fields (a backup job once went silent for four days when the text it grepped
// changed language in 2.4). If this test must change, the interface changed:
// that is a breaking release, not a cleanup.
func TestStatusSozlesmesi(t *testing.T) {
	profilEvi(t, map[string]Profile{"a": {}, "b": {}})
	if statusAcik != 0 || statusKilitli != 3 || statusYok != 4 {
		t.Fatal("status exit codes changed (0 unlocked, 3 locked, 4 missing)")
	}

	// 4: no vault.
	kasaYoluTest(t, filepath.Join(t.TempDir(), "yok", "kasa.keychain-db"))
	for _, a := range [][]string{{"status"}, {"status", "-q"}, {"status", "--json"}} {
		if kod, _, _ := calis(t, a...); kod != 4 {
			t.Errorf("%v with no vault: exit %d, want 4", a, kod)
		}
	}
	_, out, _ := calis(t, "status", "--json")
	m := jsonAlanlari(t, out)
	if m["state"] != "missing" {
		t.Errorf("state = %v, want missing", m["state"])
	}

	// 0: unlocked.
	geciciKasa(t)
	yazTest(t, service, "x/one", "v1")
	yazTest(t, service, "x/two", "v2")
	kod, out, _ := calis(t, "status")
	if kod != 0 || !strings.Contains(out, "state     : unlocked") || !strings.Contains(out, "keys      : 2") {
		t.Errorf("human output or code changed: %d %q", kod, out)
	}
	kod, out, errOut := calis(t, "status", "-q")
	if kod != 0 || out != "" || errOut != "" {
		t.Errorf("status -q must print nothing: %d %q %q", kod, out, errOut)
	}
	kod, out, _ = calis(t, "status", "--json")
	m = jsonAlanlari(t, out)
	if kod != 0 || !reflect.DeepEqual(alanAdlari(m), []string{"keys", "profiles", "state", "version"}) {
		t.Fatalf("--json fields changed: %d %v", kod, alanAdlari(m))
	}
	if m["state"] != "unlocked" || m["keys"] != float64(2) || m["profiles"] != float64(2) || m["version"] != version {
		t.Errorf("--json values: %v", m)
	}
	if kod, _, _ := calis(t, "status", "--json", "-q"); kod != 2 {
		t.Errorf("-q with --json is a usage error, got %d", kod)
	}

	// 3: locked.
	if err := kcLock(); err != nil {
		t.Fatal(err)
	}
	if kod, out, _ := calis(t, "status"); kod != 3 || !strings.Contains(out, "state     : LOCKED") {
		t.Errorf("locked human output/code: %d %q", kod, out)
	}
	if kod, out, _ := calis(t, "status", "-q"); kod != 3 || out != "" {
		t.Errorf("locked -q: %d %q", kod, out)
	}
	kod, out, _ = calis(t, "status", "--json")
	m = jsonAlanlari(t, out)
	if kod != 3 || m["state"] != "locked" || !reflect.DeepEqual(alanAdlari(m), []string{"keys", "profiles", "state", "version"}) {
		t.Errorf("locked --json: %d %v", kod, m)
	}
}

// A vault still at its old place (or a move left half done) is "missing" for
// scripts, and the human text keeps naming the old place.
func TestStatusEskiYer(t *testing.T) {
	ev := profilEvi(t, nil)
	kasaYoluTest(t, filepath.Join(ev, "Library", "Application Support", "kasa", "kasa.keychain-db"))
	eski := filepath.Join(ev, "Library", "Keychains", "kasa.keychain-db")
	os.MkdirAll(filepath.Dir(eski), 0o700)
	os.WriteFile(eski, []byte("x"), 0o600)
	kod, out, _ := calis(t, "status")
	if kod != 4 || !strings.Contains(out, "old place") {
		t.Errorf("old place: %d %q", kod, out)
	}
}

// Every command: --help / -h print only the help and run nothing; an unknown
// flag is an error with the usage and exit 2, also with nothing run.
func TestYardimYanEtkisiz(t *testing.T) {
	ev := profilEvi(t, map[string]Profile{"p": {}})
	geciciKasa(t)
	yazTest(t, service, "x/one", "v1")
	once := dizinDokumu(t, ev)

	var komutlar []string
	for k := range komutTanimlari {
		komutlar = append(komutlar, k)
	}
	for k := range komutTakmaAd {
		komutlar = append(komutlar, k)
	}
	if len(komutlar) < 18 {
		t.Fatalf("command table looks incomplete: %v", komutlar)
	}
	for _, k := range komutlar {
		ana := k
		if a, ok := komutTakmaAd[k]; ok {
			ana = a
		}
		for _, h := range []string{"--help", "-h"} {
			kod, out, _ := calis(t, k, h)
			if kod != 0 || out != komutTanimlari[ana].yardim || !strings.Contains(out, "usage: kasa") {
				t.Errorf("kasa %s %s: exit %d, output %q", k, h, kod, out)
			}
		}
		kod, out, errOut := calis(t, k, "--no-such-flag")
		if kod != 2 || out != "" || !strings.Contains(errOut, "unknown flag") || !strings.Contains(errOut, "usage: kasa") {
			t.Errorf("kasa %s --no-such-flag: exit %d, out %q, err %q", k, kod, out, errOut)
		}
	}
	if isLocked() {
		t.Error("a --help locked the vault")
	}
	if keys, _ := kcList(); !reflect.DeepEqual(keys, []string{"x/one"}) {
		t.Errorf("vault changed: %v", keys)
	}
	if sonra := dizinDokumu(t, ev); !reflect.DeepEqual(once, sonra) {
		t.Errorf("a --help or rejected flag wrote files:\nbefore %v\nafter  %v", once, sonra)
	}
}

func dizinDokumu(t *testing.T, kok string) []string {
	t.Helper()
	var out []string
	filepath.Walk(kok, func(p string, fi os.FileInfo, err error) error {
		if err == nil {
			out = append(out, p+"|"+fi.ModTime().String()+"|"+string(rune(fi.Size())))
		}
		return nil
	})
	return out
}

// The hidden legacy (Turkish) flags and command names keep working; flags
// after "--" belong to the command that run starts.
func TestEskiTakmaAdlarGecer(t *testing.T) {
	gecer := [][]string{
		{"export", "--ustune-yaz"}, {"export", "--hedef", "d"}, {"export", "--cikti", "d"}, {"export", "--out=d"},
		{"import", "f.age", "--ustune-yaz"}, {"import", "f.age", "--force"},
		{"mail", "send", "--profil", "p", "--alici", "a@b.c", "--konu", "k", "--govde", "g", "--govde-dosya", "f"},
		{"acl", "migrate", "--prova"}, {"acl", "migrate", "--dry-run", "--target", "d"},
		{"unlock", "--pencere"}, {"unlock", "--gui"}, {"add", "k/v", "--stdin"}, {"audit", "-n", "5"},
		{"which", "-i", "--regex", "--all"}, {"status", "-q"}, {"status", "--json"},
		{"backup", "verify", "--latest", "--json"}, {"doctor", "--json"},
		{"run", "p", "--", "cmd", "--whatever", "-x"}, {"profile", "test", "p", "--", "cmd", "--help"},
		{"yedek-parola", "durum"}, {"yedek-parola", "ayarla"}, {"hedef", "ls"}, {"yedek", "ls"}, {"sabah"},
	}
	for _, a := range gecer {
		if y, err := bayrakOnKontrol(a[0], a[1:]); err != nil || y != "" {
			t.Errorf("%v rejected or turned into help: %q %v", a, y, err)
		}
	}
	// "which" must never echo what was typed.
	if _, err := bayrakOnKontrol("which", []string{"--sifre-degeri"}); err == nil || strings.Contains(err.Error(), "sifre") {
		t.Errorf("which echoed the flag: %v", err)
	}
	// A value that only looks dashed is not a flag.
	if _, err := bayrakOnKontrol("mail", []string{"send", "--subject", "- item", "--body", "-5"}); err != nil {
		t.Errorf("dashed value rejected: %v", err)
	}
}

func yedekDosyasi(t *testing.T, dizin, ad, parola string, sirlar map[string]string) string {
	t.Helper()
	plain, _ := json.Marshal(bundle{Version: bundleVersion, Olusturuldu: "2026-01-02T03:04:05Z", Makine: "m", Secrets: sirlar, Profiles: map[string]Profile{}})
	enc, err := sealBundle(plain, parola)
	if err != nil {
		t.Fatal(err)
	}
	yol := filepath.Join(dizin, ad)
	if err := os.WriteFile(yol, enc, 0o600); err != nil {
		t.Fatal(err)
	}
	return yol
}

func TestYedekDogrulaIsimleriKarsilastirir(t *testing.T) {
	enc, _ := sealBundle([]byte(`{"version":1,"olusturuldu":"t","secrets":{"a/one":"DEGER-GIZLI-1","c/old":"DEGER-GIZLI-2"},"profiles":{}}`), "Pw-test-12345!")
	s, err := yedekDogrula(enc, "Pw-test-12345!", []string{"a/one", "e/new"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Result != "different" || !reflect.DeepEqual(s.OnlyInBackup, []string{"c/old"}) || !reflect.DeepEqual(s.OnlyInVault, []string{"e/new"}) || s.BackupKeys != 2 || s.VaultKeys != 2 {
		t.Errorf("%+v", s)
	}
	j, _ := json.Marshal(s)
	if strings.Contains(string(j), "DEGER-GIZLI") {
		t.Errorf("a value is in the result: %s", j)
	}
	if s, _ := yedekDogrula(enc, "Pw-test-12345!", []string{"a/one", "c/old"}); s.Result != "match" {
		t.Errorf("same names: %+v", s)
	}
	if _, err := yedekDogrula(enc, "wrong", nil); err == nil {
		t.Error("wrong password opened the backup")
	}
}

// End to end against a temporary vault, in an agent environment (TestMain sets
// an agent marker): verify is allowed there, prints no value, writes nothing.
func TestYedekDogrulaUctanUca(t *testing.T) {
	profilEvi(t, nil)
	geciciKasa(t)
	if agentName() == "" {
		t.Fatal("this test must run as an agent")
	}
	const parola = "Yedek-Parola-12345!"
	yazTest(t, service, "a/one", "DEGER-GIZLI-1")
	yazTest(t, service, "b/two", "DEGER-GIZLI-2")
	d := t.TempDir()
	dosya := yedekDosyasi(t, d, "kasa-yedek-x.age", parola, map[string]string{"a/one": "DEGER-GIZLI-1", "b/two": "DEGER-GIZLI-2"})

	// No backup password in the keychain: 2, and it is never asked.
	if kod, _, errOut := calis(t, "backup", "verify", dosya); kod != 2 || !strings.Contains(errOut, "not stored") {
		t.Errorf("no password: %d %q", kod, errOut)
	}
	if err := yedekParolaYaz(parola); err != nil {
		t.Fatal(err)
	}
	once := dizinDokumu(t, d)

	kod, out, errOut := calis(t, "backup", "verify", dosya)
	if kod != 0 || !strings.Contains(out, "same key names") || errOut != "" {
		t.Errorf("match: %d %q %q", kod, out, errOut)
	}
	kod, out, _ = calis(t, "backup", "verify", "--json", dosya)
	m := jsonAlanlari(t, out)
	if kod != 0 || m["result"] != "match" || m["backup_keys"] != float64(2) || m["vault_keys"] != float64(2) {
		t.Errorf("json match: %d %v", kod, m)
	}
	if !reflect.DeepEqual(alanAdlari(m), []string{"backup_keys", "created", "file", "only_in_backup", "only_in_vault", "result", "vault_keys"}) {
		t.Errorf("json fields: %v", alanAdlari(m))
	}

	yazTest(t, service, "c/three", "DEGER-GIZLI-3") // in the vault, not in the backup
	kod, out, _ = calis(t, "backup", "verify", dosya)
	if kod != 1 || !strings.Contains(out, "c/three") || !strings.Contains(out, "DIFFERENT") {
		t.Errorf("difference: %d %q", kod, out)
	}
	for _, s := range []string{out} {
		if strings.Contains(s, "DEGER-GIZLI") {
			t.Errorf("a value was printed: %q", s)
		}
	}

	yanlis := yedekDosyasi(t, d, "kasa-yedek-y.age", "Baska-Parola-99!", map[string]string{"a/one": "x"})
	if kod, _, _ := calis(t, "backup", "verify", yanlis); kod != 2 {
		t.Errorf("wrong password file: %d", kod)
	}
	if kod, _, _ := calis(t, "backup", "verify", filepath.Join(d, "yok.age")); kod != 2 {
		t.Errorf("missing file: %d", kod)
	}
	if kod, _, _ := calis(t, "backup", "verify"); kod != 2 {
		t.Errorf("no file and no --latest: %d", kod)
	}
	if kod, _, _ := calis(t, "backup", "verify", "--latest", dosya); kod != 2 {
		t.Errorf("both file and --latest: %d", kod)
	}
	// Locked: could not open (2), nothing decrypted.
	if err := kcLock(); err != nil {
		t.Fatal(err)
	}
	if kod, _, _ := calis(t, "backup", "verify", dosya); kod != 2 {
		t.Errorf("locked: %d", kod)
	}
	// Only the two backup files this test wrote: verify left nothing on disk.
	var adlar []string
	e, _ := os.ReadDir(d)
	for _, x := range e {
		adlar = append(adlar, x.Name())
	}
	if len(adlar) != 2 {
		t.Errorf("files in the backup directory: %v (before: %v)", adlar, once)
	}
}

func TestEnYeniYedekTumHedefler(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	c := &Config{kilitliHedefler: []string{a, b}}
	if _, err := enYeniYedek(c); err == nil {
		t.Error("no backups anywhere must be an error")
	}
	yedekDosyasi(t, a, "eski.age", "Pw-test-12345!", nil)
	yeni := yedekDosyasi(t, b, "yeni.age", "Pw-test-12345!", nil)
	old := time.Now().Add(-48 * time.Hour)
	os.Chtimes(filepath.Join(a, "eski.age"), old, old)
	if y, err := enYeniYedek(c); err != nil || y != yeni {
		t.Errorf("newest over all targets: %q %v", y, err)
	}
	if _, err := enYeniYedek(&Config{}); err == nil {
		t.Error("no targets must be an error")
	}
}

func bulguDurumu(b []doktorBulgu, ad string) []string {
	var out []string
	for _, x := range b {
		if x.Name == ad {
			out = append(out, x.Status)
		}
	}
	return out
}

func TestDoktor(t *testing.T) {
	profilEvi(t, nil)
	hedef := t.TempDir()
	c := &Config{Profiles: map[string]Profile{
		"bos":  {},
		"mail": {SMTP: &SMTPConf{Host: "h", Port: 1, From: "f"}},
		"tam":  {Secrets: map[string]string{"TOKEN": "x/one"}, Allow: []string{"/bin/echo"}},
		"eks":  {Secrets: map[string]string{"TOKEN": "x/yok"}, Allow: []string{"/bin/echo", "/yok/komut-yok"}},
	}, kilitliHedefler: []string{hedef}}

	// No vault: failure.
	kasaYoluTest(t, filepath.Join(t.TempDir(), "yok", "kasa.keychain-db"))
	if b := doktorKos(c, ""); doktorToplam(b) != "fail" || bulguDurumu(b, "vault")[0] != "fail" {
		t.Errorf("no vault: %+v", b)
	}

	geciciKasa(t)
	yazTest(t, service, "x/one", "DEGER-GIZLI")
	// Healthy except the backups: no password, no backup in the target.
	b := doktorKos(c, "")
	if bulguDurumu(b, "vault")[0] != "ok" || bulguDurumu(b, "read")[0] != "ok" || bulguDurumu(b, "backup-password")[0] != "warn" || bulguDurumu(b, "backup")[0] != "warn" || doktorToplam(b) != "warn" {
		t.Errorf("no password, empty target: %+v", b)
	}
	if err := yedekParolaYaz("Yedek-Parola-12345!"); err != nil {
		t.Fatal(err)
	}
	dosya := yedekDosyasi(t, hedef, "kasa-yedek-x.age", "Yedek-Parola-12345!", nil)
	if b := doktorKos(c, ""); doktorToplam(b) != "ok" {
		t.Errorf("healthy: %+v", b)
	}
	// Stale: older than 36 h.
	eski := time.Now().Add(-37 * time.Hour)
	os.Chtimes(dosya, eski, eski)
	if b := doktorKos(c, ""); bulguDurumu(b, "backup")[0] != "warn" || doktorToplam(b) != "warn" {
		t.Errorf("37 h old backup: %+v", b)
	}
	yeni := time.Now().Add(-35 * time.Hour)
	os.Chtimes(dosya, yeni, yeni)
	if b := doktorKos(c, ""); doktorToplam(b) != "ok" {
		t.Errorf("35 h old backup: %+v", b)
	}
	// Unreachable target.
	if b := doktorKos(&Config{kilitliHedefler: []string{filepath.Join(hedef, "yok")}}, ""); bulguDurumu(b, "backup")[0] != "warn" {
		t.Errorf("unreachable target: %+v", b)
	}

	// Profiles.
	if b := doktorKos(c, "yok-boyle"); bulguDurumu(b, "profile yok-boyle")[0] != "fail" {
		t.Errorf("missing profile: %+v", b)
	}
	if b := doktorKos(c, "bos"); bulguDurumu(b, "profile bos")[0] != "warn" {
		t.Errorf("empty allow list: %+v", b)
	}
	if b := doktorKos(c, "mail"); bulguDurumu(b, "profile mail")[0] != "ok" {
		t.Errorf("mail profile: %+v", b)
	}
	if b := doktorKos(c, "tam"); doktorToplam(b) != "ok" || len(bulguDurumu(b, "profile tam")) != 2 {
		t.Errorf("good profile: %+v", b)
	}
	b = doktorKos(c, "eks")
	if d := bulguDurumu(b, "profile eks"); !reflect.DeepEqual(d, []string{"warn", "fail"}) {
		t.Errorf("profile with a missing command and a missing key: %+v", b)
	}
	j, _ := json.Marshal(b)
	if strings.Contains(string(j), "DEGER-GIZLI") {
		t.Error("a value is in the doctor output")
	}

	// Locked: failure, and the vault-dependent checks are skipped.
	if err := kcLock(); err != nil {
		t.Fatal(err)
	}
	b = doktorKos(c, "")
	if bulguDurumu(b, "vault")[0] != "fail" || doktorToplam(b) != "fail" || len(bulguDurumu(b, "read")) != 0 {
		t.Errorf("locked: %+v", b)
	}
}

// doctor exit codes and JSON fields are an interface too.
func TestDoktorKodlari(t *testing.T) {
	profilEvi(t, nil)
	kasaYoluTest(t, filepath.Join(t.TempDir(), "yok", "kasa.keychain-db"))
	kod, out, _ := calis(t, "doctor", "--json")
	m := jsonAlanlari(t, out)
	if kod != 2 || m["status"] != "fail" || !reflect.DeepEqual(alanAdlari(m), []string{"checks", "status", "version"}) {
		t.Errorf("no vault: %d %v", kod, m)
	}
	c0 := m["checks"].([]any)[0].(map[string]any)
	if c0["name"] != "vault" || c0["status"] != "fail" || c0["fix"] == "" || c0["detail"] == "" {
		t.Errorf("check shape: %v", c0)
	}

	geciciKasa(t)
	yazTest(t, service, "x/one", "v")
	// Unlocked, no target configured: a warning.
	if kod, out, _ := calis(t, "doctor"); kod != 1 || !strings.Contains(out, "WARN") || !strings.Contains(out, "-> ") {
		t.Errorf("warning: %d %q", kod, out)
	}
}
