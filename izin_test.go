package main

import (
	"os"
	"path/filepath"
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

// macOS'ta TempDir /var altinda, /var da /private/var'a symlink; gercek ev
// dizini gibi kanonik yol kullan.
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
		{"dotfiles/bin ciplak ad", []string{"deploy"}, dotbin, true},
		{"sistem python3", []string{"python3"}, "/usr/bin/python3", true},
		{"homebrew", []string{"node"}, "/opt/homebrew/bin/node", true},
		{"proje venv", []string{"python3"}, venv, true},
		{"~/.local/bin symlink", []string{"mytool"}, localbin, true},
		{"pipx cozulmus yol", []string{"mytool"}, pipx, true},
		{"mutlak girdi symlink ile", []string{"~/.local/bin/mytool"}, localbin, true},
		{"mutlak girdi cozulmus yolla", []string{"~/.local/bin/mytool"}, pipx, true},
		{"yildiz", []string{"*"}, sahte, true},
		{"~/.local/bin -> ~/Developer (arac)", []string{"arac"}, tgLink, true},

		{"Desktop'ta ayni ad", []string{"deploy"}, sahte, false},
		{"tmp'de ayni ad (PATH kacirma)", []string{"deploy"}, tmpSahte, false},
		{"Developer'da venv disi", []string{"deploy"}, devSahte, false},
		{"Developer'da sahte bin/python3", []string{"python3"}, sahteVenv, false},
		{"listede yok", []string{"python3"}, dotbin, false},
		{"mutlak girdi baska dosya", []string{"~/dotfiles/bin/deploy"}, sahte, false},
		{"guvenilen dizinde /tmp'ye symlink", []string{"deploy"}, kacisLink, false},
		{".venv/bin dizini /tmp'ye symlink", []string{"python3"}, venvKacis, false},
		{"olmayan dosya", []string{"deploy"}, filepath.Join(home, "dotfiles", "bin", "yok"), false},
	}
	for _, d := range durumlar {
		ok, neden := izinVer(d.allow, d.bin, home)
		if ok != d.izin {
			t.Errorf("%s: izin=%v beklenen %v (%s)", d.ad, ok, d.izin, neden)
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
		t.Fatalf("mutlak yol bekleniyordu: %s", bin)
	}
	if ok, _ := izinVer([]string{"deploy"}, bin, t.TempDir()); ok {
		t.Fatal("cwd'deki ayni adli dosya izin almamali")
	}
	if ok, _ := izinVer([]string{"deploy"}, bin, ""); ok {
		t.Fatal("cwd'deki ayni adli dosya izin almamali")
	}
}

// Yaygin araclar kirilmasin (makineye bagli; yol yoksa atlanir).
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
			t.Logf("atlandi (bu makinede yok): %s", d.arg0)
			continue
		}
		if ok, neden := izinVer([]string{d.allow}, bin, home); !ok {
			t.Errorf("%s -> %s reddedildi: %s", d.arg0, bin, neden)
		}
	}
}

func TestHomeDirHOMEdenBagimsiz(t *testing.T) {
	gercek := homeDir()
	t.Setenv("HOME", t.TempDir())
	if homeDir() != gercek || gercek == "" {
		t.Fatalf("homeDir HOME'a uydu: %q -> %q", gercek, homeDir())
	}
}
