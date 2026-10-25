package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Backup round-trip integrity: encrypt, decrypt, get the same content back.
func TestBundleRoundTrip(t *testing.T) {
	in := bundle{
		Version:     bundleVersion,
		Olusturuldu: "2026-09-07T12:00:00Z",
		Makine:      "test",
		Secrets: map[string]string{
			"mail/pass":    "p4ss w0rd\nsecond line",
			"github/token": "ghp_" + strings.Repeat("x", 36),
			"utf/tr":       "şifre-ğüıöç",
		},
		Profiles: map[string]Profile{
			"mail": {Aciklama: "test", Secrets: map[string]string{"SMTP_PASS": "mail/pass"}, Allow: []string{"node"}},
		},
	}
	plain, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}

	const pass = "correct-password-12345"
	enc, err := sealBundle(plain, pass)
	if err != nil {
		t.Fatalf("sealBundle: %v", err)
	}
	if !strings.HasPrefix(string(enc), "-----BEGIN AGE ENCRYPTED FILE-----") {
		t.Errorf("no armor header, output is not plain text: %.40q", enc)
	}
	// Secrets must not appear in the encrypted output.
	for k, v := range in.Secrets {
		if strings.Contains(string(enc), v) {
			t.Errorf("the value of %s appeared as plain text in the encrypted file", k)
		}
	}

	got, err := openBundle(enc, pass)
	if err != nil {
		t.Fatalf("openBundle: %v", err)
	}
	var out bundle
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatal(err)
	}
	for k, want := range in.Secrets {
		if out.Secrets[k] != want {
			t.Errorf("%s: expected %q, got %q", k, want, out.Secrets[k])
		}
	}
	if out.Profiles["mail"].Secrets["SMTP_PASS"] != "mail/pass" {
		t.Errorf("profile reference was lost: %+v", out.Profiles)
	}
}

func TestYanlisParolaAcmaz(t *testing.T) {
	enc, err := sealBundle([]byte(`{"version":1}`), "correct-password-12345")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openBundle(enc, "wrong-password-12345"); err == nil {
		t.Fatal("opened with the wrong password")
	}
}

// Age files without armor (raw binary) must also be readable.
func TestArmorsuzOkunur(t *testing.T) {
	enc, err := sealBundle([]byte(`{"version":1,"makine":"x"}`), "correct-password-12345")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := openBundle(enc, "correct-password-12345")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"makine":"x"`) {
		t.Errorf("content was corrupted: %s", raw)
	}
}

// ---- target / multi-target writing ----

func TestYedegiYazDogrular(t *testing.T) {
	dir := t.TempDir()
	yol := filepath.Join(dir, "alt", "kasa-yedek-test.age")
	enc := []byte("-----BEGIN AGE ENCRYPTED FILE-----\nfake\n")

	if err := yedegiYaz(yol, enc, false); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(yol)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(enc) {
		t.Errorf("content differs: %q", got)
	}
	fi, err := os.Stat(yol)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("permissions must be 0600, got %v", fi.Mode().Perm())
	}
	// A second write must be rejected without --overwrite.
	if err := yedegiYaz(yol, enc, false); err == nil {
		t.Error("overwrote an existing file without permission")
	}
	if err := yedegiYaz(yol, enc, true); err != nil {
		t.Errorf("could not write with --overwrite: %v", err)
	}
}

func TestExportYollariHerHedefeBirer(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	c := &Config{Hedefler: []string{a, b}}
	yollar, err := exportYollari(nil, map[string]string{}, c, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(yollar) != 2 {
		t.Fatalf("expected 2 paths, got %d: %v", len(yollar), yollar)
	}
	for i, dir := range []string{a, b} {
		if filepath.Dir(yollar[i]) != dir {
			t.Errorf("path %d must be under %s: %s", i, dir, yollar[i])
		}
		if filepath.Ext(yollar[i]) != ".age" {
			t.Errorf("extension must be .age: %s", yollar[i])
		}
	}
}

func TestExportYollariHedefYokHata(t *testing.T) {
	_, err := exportYollari(nil, map[string]string{}, &Config{}, false)
	if err == nil {
		t.Fatal("no error when there are no targets")
	}
	if !strings.Contains(err.Error(), "no targets") {
		t.Errorf("error message gives no way forward: %v", err)
	}
}

func TestTekYolDizinVeDosyaAyirir(t *testing.T) {
	dir := t.TempDir()
	if got := tekYol(dir, "y.age"); got != filepath.Join(dir, "y.age") {
		t.Errorf("for a directory: %s", got)
	}
	acik := filepath.Join(dir, "manual.age")
	if got := tekYol(acik, "y.age"); got != acik {
		t.Errorf("an explicit file name must be preserved: %s", got)
	}
}

func TestYedekleriTaraYeniyiOneAlir(t *testing.T) {
	dir := t.TempDir()
	eski := filepath.Join(dir, "kasa-yedek-20250101.age")
	yeni := filepath.Join(dir, "kasa-yedek-20260101.age")
	os.WriteFile(eski, []byte("x"), 0o600)
	os.WriteFile(yeni, []byte("y"), 0o600)
	os.WriteFile(filepath.Join(dir, "unrelated.txt"), []byte("z"), 0o600)
	os.Chtimes(eski, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))

	k, err := yedekleriTara(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != 2 {
		t.Fatalf("only .age files must be counted, got %d", len(k))
	}
	if filepath.Base(k[0].yol) != "kasa-yedek-20260101.age" {
		t.Errorf("the newest must come first, got %s", filepath.Base(k[0].yol))
	}
}

func TestExpandHome(t *testing.T) {
	h := kasaEvi()
	if got := expandHome("~/kasa"); got != filepath.Join(h, "kasa") {
		t.Errorf("~ was not expanded: %s", got)
	}
	if got := expandHome("/absolute/path"); got != "/absolute/path" {
		t.Errorf("absolute path was corrupted: %s", got)
	}
}

func TestYedekParolaKusuru(t *testing.T) {
	testler := []struct {
		ad     string
		parola string
		gecer  bool
	}{
		{"12 characters, four classes", "Qx.904417abc", true},
		{"long phrase", "Blue-Cat-Cloud-7", true},
		{"Turkish letters, rune counting", "Şğüşiö.12345", true},
		{"too short", "Ab.12345", false},
		{"9 characters is now too short", "Qx.904417", false},
		{"single class", "aaaaaaaaa", false},
		{"no punctuation", "Abc1234567", false},
		{"no digit", "Abc.defghi", false},
		{"no upper-case letter", "abc.123456", false},
		{"no lower-case letter", "ABC.123456", false},
	}
	for _, tt := range testler {
		kusur := yedekParolaKusuru(tt.parola)
		if tt.gecer && kusur != "" {
			t.Errorf("%s: should have passed, defect: %s", tt.ad, kusur)
		}
		if !tt.gecer && kusur == "" {
			t.Errorf("%s: should have been rejected but passed", tt.ad)
		}
	}
}
