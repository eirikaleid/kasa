package main

import (
	"os"
	"strings"
	"testing"
)

func ortamHarita(env []string) map[string]string {
	m := map[string]string{}
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		if _, var_ := m[k]; var_ {
			m[k] = "<<IKI KEZ>>"
			continue
		}
		m[k] = v
	}
	return m
}

func TestCocukOrtami_VarsayilanBeyazListe(t *testing.T) {
	cagiran := []string{"PATH=/tmp/sahte:/usr/bin", "HOME=/Users/x", "LANG=tr_TR.UTF-8", "LC_ALL=C", "CLAUDECODE=1",
		"FOO=1", "IFS=x", "GIT_SSH_COMMAND=id", "SSH_ASKPASS=/tmp/k", "ZDOTDIR=/tmp", "JAVA_TOOL_OPTIONS=-x",
		"DYLD_INSERT_LIBRARIES=/tmp/kotu.dylib", "LD_PRELOAD=/tmp/k.so", "BASH_ENV=/tmp/k.sh", "BASH_FUNC_ls%%=() { id; }",
		"PYTHONSTARTUP=/tmp/k.py", "NODE_OPTIONS=--require /tmp/k.js", "PERL5OPT=-Mkotu", "RUBYOPT=-rkotu", "PS4=$(id)",
		"SIGNING_PASSWORD=cagiranin-sahtesi"}
	env, atilan := cocukOrtami(cagiran, Profile{}, map[string]string{"SIGNING_PASSWORD": "gercek"}, "/Users/x")
	m := ortamHarita(env)
	if m["PATH"] != guvenliPath("/Users/x") || strings.Contains(m["PATH"], "/tmp") {
		t.Fatalf("PATH cagirandan geldi: %q", m["PATH"])
	}
	for _, k := range []string{"HOME", "LANG", "LC_ALL", "CLAUDECODE"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("%s gecmeliydi", k)
		}
	}
	if _, ok := m["FOO"]; ok {
		t.Fatal("beyaz liste disi FOO gecti")
	}
	for k := range m {
		if k != "PATH" && enjeksiyonMu(k) {
			t.Fatalf("enjeksiyon degiskeni gecti: %s", k)
		}
	}
	if m["SIGNING_PASSWORD"] != "gercek" {
		t.Fatalf("sir golgelendi: %q", m["SIGNING_PASSWORD"])
	}
	if len(m) != 6 {
		t.Fatalf("env=%v", env)
	}
	for _, a := range atilan {
		if strings.Contains(a, "=") {
			t.Fatal("atilan listesinde deger var")
		}
	}
}

func TestCocukOrtami_BeyazListe(t *testing.T) {
	cagiran := []string{"PATH=/tmp", "HOME=/h", "LC_ALL=C", "LC_CTYPE=UTF-8", "SSH_AUTH_SOCK=/tmp/a",
		"DYLD_INSERT_LIBRARIES=/tmp/k"}
	liste := []string{"LC_*", "DYLD_INSERT_LIBRARIES"}
	env, _ := cocukOrtami(cagiran, Profile{Ortam: &liste}, map[string]string{"S": "v"}, "/h")
	m := ortamHarita(env)
	if len(m) != 4 || m["LC_ALL"] != "C" || m["LC_CTYPE"] != "UTF-8" || m["S"] != "v" || m["PATH"] != guvenliPath("/h") {
		t.Fatalf("env=%v", env)
	}
	bos := []string{}
	env, _ = cocukOrtami(cagiran, Profile{Ortam: &bos}, map[string]string{"S": "v"}, "/h")
	if len(env) != 2 || env[1] != "S=v" {
		t.Fatalf("bos liste yalniz PATH + sirlar olmali: %v", env)
	}
}

func TestOrtamGecerli(t *testing.T) {
	if err := ortamGecerli([]string{"HOME", "LC_*", "LANG"}); err != nil {
		t.Fatal(err)
	}
	for _, kotu := range [][]string{{"PATH"}, {"P*"}, {"DYLD_INSERT_LIBRARIES"}, {"DYLD_*"}, {"D*"}, {"L*"}, {"*"}, {""}, {"A=B"},
		{"BASH_ENV"}, {"NODE_OPTIONS"}, {"IFS"}, {"I*"}, {"GIT_SSH_COMMAND"}, {"SSH_ASKPASS"}, {"PYTHONSTARTUP"}} {
		if ortamGecerli(kotu) == nil {
			t.Fatalf("kabul edildi: %v", kotu)
		}
	}
}

func TestKilitliProfilEzerVeKaydedilmez(t *testing.T) {
	d := t.TempDir()
	eskiEv := testEvDizini
	testEvDizini = d
	t.Cleanup(func() { testEvDizini = eskiEv })
	eski := KilitliProfilYolu
	KilitliProfilYolu = d + "/yok.json"
	t.Cleanup(func() { KilitliProfilYolu = eski })
	c := &Config{Profiles: map[string]Profile{"v": {Allow: []string{"/bin/sh"}}, "x": {Allow: []string{"a"}}}}
	if err := saveConfig(c); err != nil {
		t.Fatal(err)
	}
	// Kullaniciya ait "kilitli" dosya reddedilir.
	f := d + "/kilitli.json"
	if err := os.WriteFile(f, []byte(`{"profiles":{"v":{"allow":["/usr/local/libexec/signer/sign"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c2 := &Config{Profiles: map[string]Profile{"v": {Allow: []string{"/bin/sh"}}}}
	if err := kilitliUygula(c2, f); err == nil {
		t.Fatal("kullaniciya ait kilitli dosya kabul edildi")
	}
	// Ezme + kayit: kilitli icerik kullanici dosyasina yazilmaz (dogrudan alan doldurularak).
	c3, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	c3.kullaniciAsli = map[string]*Profile{"v": {Allow: []string{"/bin/sh"}}, "yeni": nil}
	c3.Profiles["v"] = Profile{Allow: []string{"/usr/local/libexec/signer/sign"}}
	c3.Profiles["yeni"] = Profile{Allow: []string{"z"}}
	if err := saveConfig(c3); err != nil {
		t.Fatal(err)
	}
	c4, _ := loadConfig()
	if c4.Profiles["v"].Allow[0] != "/bin/sh" || len(c4.Profiles) != 2 {
		t.Fatalf("kilitli icerik kullanici dosyasina yazildi: %+v", c4.Profiles)
	}
	if rootSahipli("/usr/bin") != nil {
		t.Fatal("/usr/bin root sahipli sayilmadi")
	}
}

func TestKilitliAnahtaraBaskaProfilErisemez(t *testing.T) {
	c := &Config{
		Profiles: map[string]Profile{
			"signing": {Secrets: map[string]string{"P": "gizli/ref"}},
			"sahte":   {Secrets: map[string]string{"X": "gizli/ref"}, Allow: []string{"/bin/sh"}},
			"diger":   {Secrets: map[string]string{"Y": "baska/ref"}},
		},
		kullaniciAsli: map[string]*Profile{"signing": nil},
		kilitliRef:    map[string]bool{"gizli/ref": true},
	}
	if _, err := c.get("signing"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.get("sahte"); err == nil {
		t.Fatal("kilitli anahtar kilitsiz profilden okundu")
	}
	if _, err := c.get("diger"); err != nil {
		t.Fatal(err)
	}
}
