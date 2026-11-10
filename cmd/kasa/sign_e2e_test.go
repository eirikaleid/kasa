package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// End-to-end tests of the signing story, all in temporary keychains (never the
// login keychain, never the real vault), with interaction disabled: no test
// here may open a dialog. Items are written and read by copies of the test
// binary signed with a test certificate:
//   - a rebuild signed with the same certificate reads without a prompt, in a
//     vault OUTSIDE */Library/Keychains only (TMPDIR here); the real vault has
//     partition lists and needs a handover (uretim_e2e_test.go, acl devral)
//   - an ad-hoc copy gets errSecAuthFailed
//   - certificate lost, .p12 restored  -> items readable again
//   - certificate lost for good        -> new certificate, items re-created
//     from the encrypted backup

const e2eTekrar = "kasa-e2e" // the code-signing identifier of the signed test binaries

func repoKok(t *testing.T) string {
	t.Helper()
	k, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// komutKos: runs a command with a timeout (a hung command, e.g. one waiting on
// a hidden dialog, fails the test instead of blocking it).
func komutKos(t *testing.T, dir string, env []string, ad string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, ad, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// e2eAnahtarlik: a temporary keychain that holds a certificate (or a vault).
func e2eAnahtarlik(t *testing.T, ad string) (yol, parola string) {
	t.Helper()
	yol = filepath.Join(kanonikTemp(t), ad+".keychain-db")
	parola = "temporary-e2e-password"
	if err := kcOlusturYol(yol, []byte(parola)); err != nil {
		t.Fatalf("temporary keychain: %v", err)
	}
	t.Cleanup(func() { kcKeychainSilYol(yol) })
	return yol, parola
}

// e2eSertifika: runs contrib/make-cert.sh against a temporary keychain.
func e2eSertifika(t *testing.T, kc, kcParola string) (sha1, p12, localMk string) {
	t.Helper()
	d := t.TempDir()
	tmpDir := filepath.Join(d, "tmp")
	if err := os.Mkdir(tmpDir, 0o700); err != nil {
		t.Fatal(err)
	}
	p12 = filepath.Join(d, "backup.p12")
	localMk = filepath.Join(d, "local.mk")
	out, err := komutKos(t, repoKok(t), []string{"TMPDIR=" + tmpDir, "KASA_CERT_P12_PASSPHRASE=p12-test-passphrase"},
		"./contrib/make-cert.sh", "--keychain", kc, "--p12", p12, "--local-mk", localMk, "--cn", "kasa test signing")
	if err != nil {
		t.Fatalf("make-cert.sh: %v\n%s", err, out)
	}
	if !strings.Contains(out, "IMPORTANT: protect your signing certificate") {
		t.Errorf("no warning about keeping the backup:\n%s", out)
	}
	// The key does not stay on disk: the private temporary directory is gone.
	if kalan, _ := filepath.Glob(filepath.Join(tmpDir, "kasa-cert.*")); len(kalan) != 0 {
		t.Errorf("temporary key material left behind: %v", kalan)
	}
	mk, err := os.ReadFile(localMk)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(mk), "\n") {
		if v, ok := strings.CutPrefix(l, "SIGN_IDENTITY = "); ok {
			sha1 = v
		}
	}
	if len(sha1) != 40 {
		t.Fatalf("SIGN_IDENTITY not in local.mk: %q", mk)
	}
	if !strings.Contains(string(mk), "SIGN_KEYCHAIN = "+kc) {
		t.Errorf("SIGN_KEYCHAIN missing in local.mk: %q", mk)
	}
	if fi, err := os.Stat(p12); err != nil || fi.Size() == 0 {
		t.Fatalf("no .p12 backup: %v", err)
	}
	// codesign may use the key without a dialog: partition list (the keychain's
	// password is known here).
	if out, err := komutKos(t, "", nil, "/usr/bin/security", "set-key-partition-list",
		"-S", "apple-tool:,apple:", "-s", "-k", kcParola, kc); err != nil {
		t.Fatalf("set-key-partition-list: %v\n%s", err, out)
	}
	return sha1, p12, localMk
}

func e2eImzala(t *testing.T, bin, sha1, kc string) {
	t.Helper()
	args := []string{"-f", "-s", sha1, "-i", e2eTekrar, "-o", "runtime"}
	if kc != "" {
		args = append(args, "--keychain", kc)
	}
	if out, err := komutKos(t, "", nil, "/usr/bin/codesign", append(args, bin)...); err != nil {
		t.Fatalf("codesign %s: %v\n%s", bin, err, out)
	}
}

func e2eKopya(t *testing.T, kaynak, ad string) string {
	t.Helper()
	b, err := os.ReadFile(kaynak)
	if err != nil {
		t.Fatal(err)
	}
	y := filepath.Join(t.TempDir(), ad)
	if err := os.WriteFile(y, b, 0o700); err != nil {
		t.Fatal(err)
	}
	return y
}

// e2eCalistir: runs a helper operation inside a (signed) copy of the test binary.
func e2eCalistir(t *testing.T, bin string, alanlar ...string) string {
	t.Helper()
	out, _ := komutKos(t, "", []string{"KASA_E2E=" + strings.Join(alanlar, "\n")}, bin, "-test.run=^TestImzaYardimci$", "-test.count=1")
	if i := strings.Index(out, "E2E: "); i >= 0 {
		return strings.SplitN(out[i+len("E2E: "):], "\n", 2)[0]
	}
	t.Fatalf("helper gave no result: %s", out)
	return ""
}

// TestImzaYardimci: runs only inside e2eCalistir's child process.
//
//	write <keychain> <svc> <acct> <value>
//	read  <keychain> <svc> <acct>
//	recover <keychain> <svc> <backup file> <backup password>   (new kasa after a lost certificate:
//	        delete the old items, write them again from the encrypted backup)
func TestImzaYardimci(t *testing.T) {
	a := os.Getenv("KASA_E2E")
	if a == "" {
		t.Skip("helper for e2eCalistir")
	}
	p := strings.Split(a, "\n")
	switch p[0] {
	case "write":
		fmt.Printf("E2E: %v\n", kcYazYol(p[1], p[2], p[3], []byte(p[4]), "kasa secret", "managed by kasa"))
	case "read":
		v, err := kcOkuYol(p[1], p[2], p[3])
		if err != nil {
			fmt.Printf("E2E: err: %v\n", err)
		} else {
			fmt.Printf("E2E: ok: %s\n", v)
		}
	case "recover":
		enc, err := os.ReadFile(p[3])
		if err != nil {
			fmt.Printf("E2E: err: %v\n", err)
			return
		}
		plain, err := openBundle(enc, p[4])
		if err != nil {
			fmt.Printf("E2E: err: %v\n", err)
			return
		}
		var b bundle
		if err := json.Unmarshal(plain, &b); err != nil {
			fmt.Printf("E2E: err: %v\n", err)
			return
		}
		for k, v := range b.Secrets {
			if err := kcSilYol(p[1], p[2], k); err != nil && err != errAnahtarYok {
				fmt.Printf("E2E: err: delete %s: %v\n", k, err)
				return
			}
			if err := kcYazYol(p[1], p[2], k, []byte(v), "kasa secret", "managed by kasa"); err != nil {
				fmt.Printf("E2E: err: write %s: %v\n", k, err)
				return
			}
		}
		fmt.Println("E2E: <nil>")
	}
}

func TestImzaliSertifikaYolu(t *testing.T) {
	kok := repoKok(t)
	kc1, kcp1 := e2eAnahtarlik(t, "cert1")
	sha1, p12, localMk := e2eSertifika(t, kc1, kcp1)

	// make-cert.sh does not replace a certificate local.mk already names.
	if out, err := komutKos(t, kok, []string{"KASA_CERT_P12_PASSPHRASE=x"}, "./contrib/make-cert.sh",
		"--keychain", kc1, "--p12", p12+".2", "--local-mk", localMk); err == nil {
		t.Fatalf("make-cert.sh replaced an existing identity without --force:\n%s", out)
	}

	// Makefile: no silent ad-hoc. Built in a copy without the checkout's
	// local.mk, whose SIGN_IDENTITY would make the certificate-less build pass.
	src := e2eKaynak(t, "")
	d := t.TempDir()
	if out, err := komutKos(t, src, nil, "make", "build", "OUT="+filepath.Join(d, "x")); err == nil || !strings.Contains(out, "make cert") {
		t.Fatalf("make build without a certificate must fail and point at `make cert`: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(d, "x")); err == nil {
		t.Fatal("make build produced a binary without a certificate")
	}
	adhoc := filepath.Join(d, "adhoc")
	if out, err := komutKos(t, src, nil, "make", "build", "ADHOC=1", "OUT="+adhoc); err != nil || !strings.Contains(out, "WARNING: ad-hoc") {
		t.Fatalf("make build ADHOC=1: %v\n%s", err, out)
	}
	imzali := filepath.Join(d, "signed")
	if out, err := komutKos(t, src, nil, "make", "build", "OUT="+imzali, "SIGN_IDENTITY="+sha1, "SIGN_KEYCHAIN="+kc1); err != nil {
		t.Fatalf("make build with the certificate: %v\n%s", err, out)
	}
	if out, _ := komutKos(t, "", nil, "/usr/bin/codesign", "-d", "-r-", imzali); !strings.Contains(out, "identifier kasa and") || !strings.Contains(strings.ToLower(out), `certificate leaf = h"`+strings.ToLower(sha1)+`"`) {
		t.Fatalf("designated requirement is not bound to the certificate:\n%s", out)
	}

	// Two builds of the test binary (the second one differs in its link flags,
	// so it is a different cdhash: a "rebuild").
	bin := t.TempDir()
	binA, binB := filepath.Join(bin, "a"), filepath.Join(bin, "b")
	for _, b := range [][]string{{binA}, {binB, "-ldflags", "-X main.trustedDirsFlag=/rebuilt"}} {
		args := []string{"test", "-c", "-o", b[0]}
		args = append(args, b[1:]...)
		args = append(args, "./cmd/kasa")
		if out, err := komutKos(t, kok, nil, "go", args...); err != nil {
			t.Fatalf("go test -c: %v\n%s", err, out)
		}
	}
	e2eImzala(t, binA, sha1, kc1)
	e2eImzala(t, binB, sha1, kc1)

	vault, _ := e2eAnahtarlik(t, "vault")
	const svc, acct, deger = "kasa", "e2e/key", "sekret-değer\n\t\"q\""
	if r := e2eCalistir(t, binA, "write", vault, svc, acct, deger); r != "<nil>" {
		t.Fatalf("write by the signed binary: %s", r)
	}
	if r := e2eCalistir(t, binA, "read", vault, svc, acct); r != "ok: "+strings.SplitN(deger, "\n", 2)[0] && !strings.HasPrefix(r, "ok: sekret-değer") {
		t.Fatalf("read by the same binary: %s", r)
	}
	// In-process equality check, byte for byte (the helper's stdout is line based).
	if got, err := kcOkuYol(vault, svc, acct); err == nil {
		t.Fatalf("the unsigned test process read a certificate-bound item: %q", got)
	}
	if r := e2eCalistir(t, binB, "read", vault, svc, acct); !strings.HasPrefix(r, "ok: sekret-değer") {
		t.Fatalf("a rebuild signed with the same certificate must read without a prompt: %s", r)
	}
	if r := e2eCalistir(t, e2eAdhoc(t, binA), "read", vault, svc, acct); !strings.Contains(r, "-25293") {
		t.Fatalf("an ad-hoc copy must get errSecAuthFailed: %s", r)
	}

	// Backup for the recovery paths: what `kasa export` would have written.
	yedek := filepath.Join(t.TempDir(), "backup.age")
	plain, _ := json.Marshal(bundle{Version: bundleVersion, Secrets: map[string]string{acct: deger}, Profiles: map[string]Profile{}})
	enc, err := sealBundle(plain, "Backup.Pass-2026")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(yedek, enc, 0o600); err != nil {
		t.Fatal(err)
	}

	// Lost certificate, path 1: restore the .p12 into a keychain; the same
	// identity is back, so a build signed with it reads the old items again.
	kc2, kcp2 := e2eAnahtarlik(t, "restored")
	if out, err := komutKos(t, "", nil, "/usr/bin/security", "import", p12, "-k", kc2,
		"-P", "p12-test-passphrase", "-T", "/usr/bin/codesign"); err != nil {
		t.Fatalf("restoring the .p12: %v\n%s", err, out)
	}
	if out, err := komutKos(t, "", nil, "/usr/bin/security", "set-key-partition-list",
		"-S", "apple-tool:,apple:", "-s", "-k", kcp2, kc2); err != nil {
		t.Fatalf("set-key-partition-list: %v\n%s", err, out)
	}
	binC := e2eKopya(t, binB, "c")
	e2eImzala(t, binC, sha1, kc2)
	if r := e2eCalistir(t, binC, "read", vault, svc, acct); !strings.HasPrefix(r, "ok: sekret-değer") {
		t.Fatalf("after restoring the .p12 the items must be readable again: %s", r)
	}

	// Lost certificate, path 2: certificate gone for good. A new certificate
	// cannot read the old items; the new kasa deletes them and writes them
	// again from the encrypted backup, bound to the new certificate.
	kc3, kcp3 := e2eAnahtarlik(t, "cert2")
	sha2, _, _ := e2eSertifika(t, kc3, kcp3)
	if sha2 == sha1 {
		t.Fatal("a new certificate has the same SHA-1")
	}
	binD := e2eKopya(t, binB, "d")
	e2eImzala(t, binD, sha2, kc3)
	if r := e2eCalistir(t, binD, "read", vault, svc, acct); !strings.Contains(r, "-25293") {
		t.Fatalf("a new certificate must not read the old items: %s", r)
	}
	if r := e2eCalistir(t, binD, "recover", vault, svc, yedek, "Backup.Pass-2026"); r != "<nil>" {
		t.Fatalf("recovery from the encrypted backup: %s", r)
	}
	if r := e2eCalistir(t, binD, "read", vault, svc, acct); !strings.HasPrefix(r, "ok: sekret-değer") {
		t.Fatalf("after recovery the new kasa must read the items: %s", r)
	}
	binE := e2eKopya(t, binA, "e") // another rebuild, signed with the NEW certificate
	e2eImzala(t, binE, sha2, kc3)
	if r := e2eCalistir(t, binE, "read", vault, svc, acct); !strings.HasPrefix(r, "ok: sekret-değer") {
		t.Fatalf("a rebuild with the new certificate must read without a prompt: %s", r)
	}
	if r := e2eCalistir(t, binC, "read", vault, svc, acct); !strings.Contains(r, "-25293") {
		t.Fatalf("the old certificate must be locked out after the re-creation: %s", r)
	}
}

// e2eAdhoc: an ad-hoc signed copy (same code, no certificate).
func e2eAdhoc(t *testing.T, bin string) string {
	t.Helper()
	k := e2eKopya(t, bin, "adhoc")
	if out, err := komutKos(t, "", nil, "/usr/bin/codesign", "-f", "-s", "-", "-i", e2eTekrar, "-o", "runtime", k); err != nil {
		t.Fatalf("codesign ad-hoc: %v\n%s", err, out)
	}
	return k
}
