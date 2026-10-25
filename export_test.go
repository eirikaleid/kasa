package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Yedegin gidis-donus butunlugu: sifrele, coz, ayni icerigi bul.
func TestBundleRoundTrip(t *testing.T) {
	in := bundle{
		Version:     bundleVersion,
		Olusturuldu: "2026-09-07T12:00:00Z",
		Makine:      "test",
		Secrets: map[string]string{
			"mail/pass":    "p4ss w0rd\nikinci satir",
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

	const pass = "dogru-parola-12345"
	enc, err := sealBundle(plain, pass)
	if err != nil {
		t.Fatalf("sealBundle: %v", err)
	}
	if !strings.HasPrefix(string(enc), "-----BEGIN AGE ENCRYPTED FILE-----") {
		t.Errorf("armor basligi yok, cikti duz metin degil: %.40q", enc)
	}
	// Sirlar sifreli ciktida gorunmemeli.
	for k, v := range in.Secrets {
		if strings.Contains(string(enc), v) {
			t.Errorf("%s degeri sifreli dosyada duz metin olarak gecti", k)
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
			t.Errorf("%s: %q bekleniyordu, %q geldi", k, want, out.Secrets[k])
		}
	}
	if out.Profiles["mail"].Secrets["SMTP_PASS"] != "mail/pass" {
		t.Errorf("profil referansi kayboldu: %+v", out.Profiles)
	}
}

func TestYanlisParolaAcmaz(t *testing.T) {
	enc, err := sealBundle([]byte(`{"version":1}`), "dogru-parola-12345")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openBundle(enc, "yanlis-parola-12345"); err == nil {
		t.Fatal("yanlis parola ile acildi")
	}
}

// Armor'suz (ham binary) age dosyalari da okunabilmeli.
func TestArmorsuzOkunur(t *testing.T) {
	enc, err := sealBundle([]byte(`{"version":1,"makine":"x"}`), "dogru-parola-12345")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := openBundle(enc, "dogru-parola-12345")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"makine":"x"`) {
		t.Errorf("icerik bozuldu: %s", raw)
	}
}

// ---- hedef / cok hedefli yazma ----

func TestYedegiYazDogrular(t *testing.T) {
	dir := t.TempDir()
	yol := filepath.Join(dir, "alt", "kasa-yedek-test.age")
	enc := []byte("-----BEGIN AGE ENCRYPTED FILE-----\nsahte\n")

	if err := yedegiYaz(yol, enc, false); err != nil {
		t.Fatalf("yazma: %v", err)
	}
	got, err := os.ReadFile(yol)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(enc) {
		t.Errorf("icerik farkli: %q", got)
	}
	fi, err := os.Stat(yol)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("izin 0600 olmali, %v geldi", fi.Mode().Perm())
	}
	// Ikinci yazma ustune-yaz olmadan reddedilmeli.
	if err := yedegiYaz(yol, enc, false); err == nil {
		t.Error("var olan dosyanin uzerine izinsiz yazdi")
	}
	if err := yedegiYaz(yol, enc, true); err != nil {
		t.Errorf("--ustune-yaz ile yazamadi: %v", err)
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
		t.Fatalf("2 yol bekleniyordu, %d geldi: %v", len(yollar), yollar)
	}
	for i, dir := range []string{a, b} {
		if filepath.Dir(yollar[i]) != dir {
			t.Errorf("%d. yol %s altinda olmali: %s", i, dir, yollar[i])
		}
		if filepath.Ext(yollar[i]) != ".age" {
			t.Errorf("uzanti .age olmali: %s", yollar[i])
		}
	}
}

func TestExportYollariHedefYokHata(t *testing.T) {
	_, err := exportYollari(nil, map[string]string{}, &Config{}, false)
	if err == nil {
		t.Fatal("hedef yokken hata vermedi")
	}
	if !strings.Contains(err.Error(), "hedef yok") {
		t.Errorf("hata mesaji yol gostermiyor: %v", err)
	}
}

func TestTekYolDizinVeDosyaAyirir(t *testing.T) {
	dir := t.TempDir()
	if got := tekYol(dir, "y.age"); got != filepath.Join(dir, "y.age") {
		t.Errorf("dizin icin: %s", got)
	}
	acik := filepath.Join(dir, "elle.age")
	if got := tekYol(acik, "y.age"); got != acik {
		t.Errorf("acik dosya adi korunmali: %s", got)
	}
}

func TestYedekleriTaraYeniyiOneAlir(t *testing.T) {
	dir := t.TempDir()
	eski := filepath.Join(dir, "kasa-yedek-20250101.age")
	yeni := filepath.Join(dir, "kasa-yedek-20260101.age")
	os.WriteFile(eski, []byte("x"), 0o600)
	os.WriteFile(yeni, []byte("y"), 0o600)
	os.WriteFile(filepath.Join(dir, "alakasiz.txt"), []byte("z"), 0o600)
	os.Chtimes(eski, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))

	k, err := yedekleriTara(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != 2 {
		t.Fatalf("yalnizca .age dosyalari sayilmali, %d geldi", len(k))
	}
	if filepath.Base(k[0].yol) != "kasa-yedek-20260101.age" {
		t.Errorf("en yeni basta olmali, %s geldi", filepath.Base(k[0].yol))
	}
}

func TestExpandHome(t *testing.T) {
	h := kasaEvi()
	if got := expandHome("~/kasa"); got != filepath.Join(h, "kasa") {
		t.Errorf("~ acilmadi: %s", got)
	}
	if got := expandHome("/mutlak/yol"); got != "/mutlak/yol" {
		t.Errorf("mutlak yol bozuldu: %s", got)
	}
}

func TestYedekParolaKusuru(t *testing.T) {
	testler := []struct {
		ad     string
		parola string
		gecer  bool
	}{
		{"12 karakter dort sinif", "Qx.904417abc", true},
		{"uzun ifade", "Mavi-Kedi-Bulut-7", true},
		{"turkce harfli, rune sayimi", "Şğüşiö.12345", true},
		{"cok kisa", "Ab.12345", false},
		{"9 karakter artik kisa", "Qx.904417", false},
		{"tek sinif", "aaaaaaaaa", false},
		{"noktalama yok", "Abc1234567", false},
		{"rakam yok", "Abc.defghi", false},
		{"buyuk harf yok", "abc.123456", false},
		{"kucuk harf yok", "ABC.123456", false},
	}
	for _, tt := range testler {
		kusur := yedekParolaKusuru(tt.parola)
		if tt.gecer && kusur != "" {
			t.Errorf("%s: gecmeliydi, kusur: %s", tt.ad, kusur)
		}
		if !tt.gecer && kusur == "" {
			t.Errorf("%s: elenmeliydi ama gecti", tt.ad)
		}
	}
}
