package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Production shape of the signing story (TestImzaliSertifikaYolu uses `go test
// -c` binaries and vaults in TMPDIR, and passed while the real vault broke):
// real kasa binaries from `make build`, two different source versions, the
// same certificate, written and read through the CLI. Temporary keychains
// only, interaction disabled.

// e2eKaynak: a copy of the source tree WITHOUT local.mk (the checkout's
// local.mk would sign test builds with the user's real certificate). surum !=
// "" changes the version constant: a second source version, i.e. a real
// upgrade, not just other link flags.
func e2eKaynak(t *testing.T, surum string) string {
	t.Helper()
	kok, d := repoKok(t), t.TempDir()
	for _, p := range []string{"Makefile", "go.mod", "go.sum", "cmd", "contrib"} {
		if out, err := komutKos(t, "", nil, "/bin/cp", "-R", filepath.Join(kok, p), filepath.Join(d, p)); err != nil {
			t.Fatalf("copying %s: %v\n%s", p, err, out)
		}
	}
	if surum != "" {
		f := filepath.Join(d, "cmd", "kasa", "main.go")
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		yeni := strings.Replace(string(b), `const version = "`+version+`"`, `const version = "`+surum+`"`, 1)
		if yeni == string(b) {
			t.Fatal("version constant not found")
		}
		if err := os.WriteFile(f, []byte(yeni), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// e2eMakeBuild: `make build` in src, signed with the certificate, with the
// vault path and kasa's home pointed at the test directories.
func e2eMakeBuild(t *testing.T, src, out, sha1, kc, vault, ev string) {
	t.Helper()
	ld := "LDFLAGS=-s -w -X main.testKeychainYolu=" + vault + " -X main.testEvDizini=" + ev
	if o, err := komutKos(t, src, nil, "make", "build", "OUT="+out, "SIGN_IDENTITY="+sha1, "SIGN_KEYCHAIN="+kc, ld); err != nil {
		t.Fatalf("make build: %v\n%s", err, o)
	}
}

// e2eUretimOrtami: a vault at vault (created by this process, the way `kasa
// init` creates it: SecKeychainCreate) and a profile that maps one key.
func e2eUretimOrtami(t *testing.T, vault, ev string, anahtarlar ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(vault), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := kcOlusturYol(vault, []byte("temporary-e2e-password")); err != nil {
		t.Fatalf("vault: %v", err)
	}
	t.Cleanup(func() { kcKeychainSilYol(vault) })
	sec := map[string]string{}
	for i, a := range anahtarlar {
		sec["K"+string(rune('A'+i))] = a
	}
	c := Config{Profiles: map[string]Profile{"p": {Secrets: sec, Allow: []string{"/usr/bin/true"}}}}
	b, _ := json.Marshal(c)
	d := filepath.Join(ev, ".config", "kasa")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "profiles.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func e2eKasa(t *testing.T, bin, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := []string{"-c", `printf '%s' "$KASA_E2E_GIRDI" | "$0" "$@"`, bin}
	return komutKos(t, "", []string{"KASA_E2E_GIRDI=" + stdin}, "/bin/sh", append(cmd, args...)...)
}

// TestUretimYenidenDerleme: 2.5.0 is installed, its items are in the vault,
// a changed source (2.5.1) is built with the same certificate. Where the vault
// lives is the variable: macOS gives a keychain under */Library/Keychains/ the
// newer blob format whose items carry a partition list; for a Team-ID-less
// self-signed binary that list names the writer's cdhash ("cdhash:..."), so
// the certificate-bound ACL alone does not let the rebuild in. A keychain
// elsewhere (the old tests: TMPDIR) has no partition list and the rebuild reads.
func TestUretimYenidenDerleme(t *testing.T) {
	kc1, kcp1 := e2eAnahtarlik(t, "cert1")
	sha1, _, _ := e2eSertifika(t, kc1, kcp1)
	srcA, srcB := e2eKaynak(t, ""), e2eKaynak(t, "9.9.9-rebuild")

	for _, yer := range []struct{ ad, alt string }{
		{"tmp", "kasa.keychain-db"},
		{"library-keychains", "Library/Keychains/kasa.keychain-db"},
	} {
		t.Run(yer.ad, func(t *testing.T) {
			ev := kanonikTemp(t)
			vault := filepath.Join(ev, yer.alt)
			e2eUretimOrtami(t, vault, ev, "e2e/key")
			d := t.TempDir()
			eski, yeni := filepath.Join(d, "kasa-old"), filepath.Join(d, "kasa-new")
			e2eMakeBuild(t, srcA, eski, sha1, kc1, vault, ev)
			e2eMakeBuild(t, srcB, yeni, sha1, kc1, vault, ev)

			if out, err := e2eKasa(t, eski, "sekret-değer", "add", "e2e/key", "--stdin"); err != nil {
				t.Fatalf("old kasa add: %v\n%s", err, out)
			}
			if out, err := e2eKasa(t, eski, "", "run", "p", "--", "/usr/bin/true"); err != nil {
				t.Fatalf("old kasa reads its own item: %v\n%s", err, out)
			}
			if out, err := e2eKasa(t, yeni, "", "run", "p", "--", "/usr/bin/true"); err != nil {
				t.Fatalf("the new build (other source, same certificate) cannot read: %v\n%s", err, out)
			}
		})
	}
}
