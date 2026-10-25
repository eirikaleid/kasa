package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Kasa kurulu degilken sir komutlari denenmemeli: hata "kasa init"e
// yonlendirmeli, "boyle bir anahtar yok" gibi yaniltici olmamali.
func TestRequireKasaKurulmamis(t *testing.T) {
	dir := t.TempDir()
	kasaYoluTest(t, filepath.Join(dir, "Library", "Keychains", "kasa.keychain-db"))

	err := requireKasa()
	if err == nil {
		t.Fatal("kasa yokken requireKasa nil dondu")
	}
	if !strings.Contains(err.Error(), "kasa init") {
		t.Fatalf("hata mesaji kurulum yolunu gostermiyor: %v", err)
	}
}

func TestRequireKasaKurulu(t *testing.T) {
	dir := t.TempDir()
	kasaYoluTest(t, filepath.Join(dir, "Library", "Keychains", "kasa.keychain-db"))

	kc := filepath.Join(dir, "Library", "Keychains")
	if err := os.MkdirAll(kc, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kc, "kasa.keychain-db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireKasa(); err != nil {
		t.Fatalf("kasa varken hata dondu: %v", err)
	}
}

// Kilitli kasada sifre penceresini yalnizca terminaldeki insan acabilir;
// LaunchAgent (TTY yok) ve ajan oturumu acamaz, KASA_SOR=1 bilerek acar;
// ajan ortaminda KASA_SOR=1 GECERSIZ.
func TestPencereAcilabilir(t *testing.T) {
	durumlar := []struct {
		tty, ajan bool
		sor       string
		beklenen  bool
	}{
		{true, false, "", true},
		{false, false, "", false},
		{true, true, "", false},
		{false, true, "", false},
		{false, false, "1", true},
		{false, true, "1", false},
		{true, true, "1", false},
		{false, false, "0", false},
	}
	for _, d := range durumlar {
		if g := pencereAcilabilir(d.tty, d.ajan, d.sor); g != d.beklenen {
			t.Errorf("tty=%v ajan=%v sor=%q: %v, beklenen %v", d.tty, d.ajan, d.sor, g, d.beklenen)
		}
	}
}

// /dev/null karakter aygiti ama terminal degil: LaunchAgent stdin'i budur.
func TestIsTTYDevNull(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	eski := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = eski }()
	if isTTY() {
		t.Fatal("/dev/null terminal sayildi")
	}
}

func TestSabahSormali(t *testing.T) {
	durumlar := []struct {
		saat            int
		acildi, kilitli bool
		beklenen        bool
	}{
		{8, false, true, true},
		{6, false, true, false},
		{8, true, true, false},
		{8, false, false, false},
		{23, false, true, true},
	}
	for _, d := range durumlar {
		if g := sabahSormali(d.saat, d.acildi, d.kilitli); g != d.beklenen {
			t.Errorf("%+v: %v", d, g)
		}
	}
}
