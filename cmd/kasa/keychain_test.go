package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Secret commands must not be attempted while the vault is not set up: the
// error must point to "kasa init", not mislead like "no such key".
func TestRequireKasaKurulmamis(t *testing.T) {
	dir := t.TempDir()
	kasaYoluTest(t, filepath.Join(dir, "Library", "Keychains", "kasa.keychain-db"))

	err := requireKasa()
	if err == nil {
		t.Fatal("requireKasa returned nil while the vault does not exist")
	}
	if !strings.Contains(err.Error(), "kasa init") {
		t.Fatalf("error message does not point to the setup step: %v", err)
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
		t.Fatalf("returned an error while the vault exists: %v", err)
	}
}

// On a locked vault only a human at a terminal can open the password dialog;
// a LaunchAgent (no TTY) and an agent session cannot, KASA_SOR=1 deliberately
// opens it; in an agent environment KASA_SOR=1 is INVALID.
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
			t.Errorf("tty=%v ajan=%v sor=%q: %v, expected %v", d.tty, d.ajan, d.sor, g, d.beklenen)
		}
	}
}

// /dev/null is a character device but not a terminal: it is a LaunchAgent's stdin.
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
		t.Fatal("/dev/null was treated as a terminal")
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
