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

// On macOS TempDir lives under /var, and /var is a symlink to /private/var;
// use the canonical path, like a real home directory.
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
		{"dotfiles/bin bare name", []string{"deploy"}, dotbin, true},
		{"system python3", []string{"python3"}, "/usr/bin/python3", true},
		{"homebrew", []string{"node"}, "/opt/homebrew/bin/node", true},
		{"project venv", []string{"python3"}, venv, true},
		{"~/.local/bin symlink", []string{"mytool"}, localbin, true},
		{"pipx resolved path", []string{"mytool"}, pipx, true},
		{"absolute entry via symlink", []string{"~/.local/bin/mytool"}, localbin, true},
		{"absolute entry via resolved path", []string{"~/.local/bin/mytool"}, pipx, true},
		{"wildcard", []string{"*"}, sahte, true},
		{"~/.local/bin -> ~/Developer (tool)", []string{"arac"}, tgLink, true},

		{"same name on Desktop", []string{"deploy"}, sahte, false},
		{"same name in tmp (PATH hijack)", []string{"deploy"}, tmpSahte, false},
		{"non-venv under Developer", []string{"deploy"}, devSahte, false},
		{"fake bin/python3 under Developer", []string{"python3"}, sahteVenv, false},
		{"not in list", []string{"python3"}, dotbin, false},
		{"absolute entry, different file", []string{"~/dotfiles/bin/deploy"}, sahte, false},
		{"symlink in trusted dir pointing to /tmp", []string{"deploy"}, kacisLink, false},
		{".venv/bin directory symlinked to /tmp", []string{"python3"}, venvKacis, false},
		{"nonexistent file", []string{"deploy"}, filepath.Join(home, "dotfiles", "bin", "yok"), false},
	}
	for _, d := range durumlar {
		ok, neden := izinVer(d.allow, d.bin, home)
		if ok != d.izin {
			t.Errorf("%s: allowed=%v, expected %v (%s)", d.ad, ok, d.izin, neden)
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
		t.Fatalf("expected an absolute path: %s", bin)
	}
	if ok, _ := izinVer([]string{"deploy"}, bin, t.TempDir()); ok {
		t.Fatal("a same-named file in cwd must not be allowed")
	}
	if ok, _ := izinVer([]string{"deploy"}, bin, ""); ok {
		t.Fatal("a same-named file in cwd must not be allowed")
	}
}

// Common tools must not break (machine-dependent; skipped if the path is missing).
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
			t.Logf("skipped (not on this machine): %s", d.arg0)
			continue
		}
		if ok, neden := izinVer([]string{d.allow}, bin, home); !ok {
			t.Errorf("%s -> %s was rejected: %s", d.arg0, bin, neden)
		}
	}
}

func TestHomeDirHOMEdenBagimsiz(t *testing.T) {
	gercek := homeDir()
	t.Setenv("HOME", t.TempDir())
	if homeDir() != gercek || gercek == "" {
		t.Fatalf("homeDir followed HOME: %q -> %q", gercek, homeDir())
	}
}
