package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Tests of contrib/cert-hazir.sh (`make cert-hazir`) in temporary keychains:
// never the login keychain, never the real vault, no dialogs. The script runs
// in its own session (Setsid), so it has no controlling terminal: a test that
// would make it read /dev/tty fails fast instead of hanging.

const certHazirParola = "p12-test-passphrase"

// certHazirKos: runs the script; pass == "" leaves KASA_CERT_P12_PASSPHRASE unset.
func certHazirKos(t *testing.T, tmpDir, pass string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "./contrib/cert-hazir.sh", args...)
	cmd.Dir = repoKok(t)
	env := []string{"TMPDIR=" + tmpDir}
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "KASA_CERT_P12_PASSPHRASE=") && !strings.HasPrefix(e, "TMPDIR=") {
			env = append(env, e)
		}
	}
	if pass != "" {
		env = append(env, "KASA_CERT_P12_PASSPHRASE="+pass)
	}
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

func certHazirIcerik(t *testing.T, yol string) string {
	t.Helper()
	b, err := os.ReadFile(yol)
	if err != nil {
		t.Fatalf("%s: %v", yol, err)
	}
	return string(b)
}

func certHazirSha1(t *testing.T, localMk string) string {
	t.Helper()
	for _, l := range strings.Split(certHazirIcerik(t, localMk), "\n") {
		if v, ok := strings.CutPrefix(l, "SIGN_IDENTITY = "); ok {
			return v
		}
	}
	t.Fatalf("no SIGN_IDENTITY in %s", localMk)
	return ""
}

func certHazirKimlikler(t *testing.T, kc string) string {
	t.Helper()
	out, _ := komutKos(t, "", nil, "/usr/bin/security", "find-identity", "-p", "codesigning", kc)
	return out
}

func TestCertHazir(t *testing.T) {
	kc1, _ := e2eAnahtarlik(t, "ch1")
	d := t.TempDir()
	tmpDir := filepath.Join(d, "tmp")
	if err := os.Mkdir(tmpDir, 0o700); err != nil {
		t.Fatal(err)
	}
	p12, localMk := filepath.Join(d, "backup.p12"), filepath.Join(d, "local.mk")
	args := func(kc string) []string {
		return []string{"--keychain", kc, "--p12", p12, "--local-mk", localMk, "--cn", "kasa test signing"}
	}
	artik := func() {
		t.Helper()
		if kalan, _ := filepath.Glob(filepath.Join(tmpDir, "kasa-cert.*")); len(kalan) != 0 {
			t.Errorf("temporary key material left behind: %v", kalan)
		}
	}

	// Without a passphrase and without a terminal nothing happens, and it says why.
	if out, err := certHazirKos(t, tmpDir, "", args(kc1)...); err == nil || !strings.Contains(out, "KASA_CERT_P12_PASSPHRASE") {
		t.Fatalf("no terminal, no passphrase: want a clear error, got %v\n%s", err, out)
	}
	if _, err := os.Stat(localMk); err == nil {
		t.Fatal("local.mk written although the script stopped")
	}
	if _, err := os.Stat(p12); err == nil {
		t.Fatal(".p12 written although the script stopped")
	}

	// Branch 3: no local.mk, no .p12 -> a new certificate (make-cert.sh).
	out, err := certHazirKos(t, tmpDir, certHazirParola, args(kc1)...)
	if err != nil {
		t.Fatalf("branch 3 (new certificate): %v\n%s", err, out)
	}
	if !strings.Contains(out, "NEW certificate") || !strings.Contains(out, "kasa import") {
		t.Errorf("branch 3 must warn that an existing vault stays unreadable:\n%s", out)
	}
	orijinal := certHazirSha1(t, localMk)
	if len(orijinal) != 40 || !strings.Contains(strings.ToUpper(certHazirKimlikler(t, kc1)), strings.ToUpper(orijinal)) {
		t.Fatalf("new identity %q not in the keychain:\n%s", orijinal, certHazirKimlikler(t, kc1))
	}
	if fi, err := os.Stat(p12); err != nil || fi.Size() == 0 {
		t.Fatalf("no .p12 backup: %v", err)
	}
	artik()

	// Branch 1 (and idempotency): identity named and present -> nothing changes.
	mk1, p12Once := certHazirIcerik(t, localMk), certHazirIcerik(t, p12)
	kim1 := certHazirKimlikler(t, kc1)
	out, err = certHazirKos(t, tmpDir, "", args(kc1)...) // no passphrase needed
	if err != nil || !strings.Contains(out, "certificate ready") {
		t.Fatalf("branch 1: %v\n%s", err, out)
	}
	if certHazirIcerik(t, localMk) != mk1 || certHazirIcerik(t, p12) != p12Once || certHazirKimlikler(t, kc1) != kim1 {
		t.Fatal("the second call changed local.mk, the .p12 or the keychain")
	}

	// Branch 2: certificate gone (new, empty keychain), .p12 there -> imported,
	// SHA-1 identical to the original, other local.mk lines kept, a stale
	// identity line replaced.
	kc2, kcp2 := e2eAnahtarlik(t, "ch2")
	stale := strings.Repeat("AB", 20)
	if err := os.WriteFile(localMk, []byte("TRUSTED_DIRS = ~/bin\nSIGN_IDENTITY = "+stale+"\nDEV_ROOT = ~/src\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := certHazirKos(t, tmpDir, "wrong-passphrase", args(kc2)...); err == nil || !strings.Contains(out, "could not open") {
		t.Fatalf("wrong passphrase must fail clearly: %v\n%s", err, out)
	}
	if strings.Contains(certHazirIcerik(t, localMk), orijinal) || strings.Contains(strings.ToUpper(certHazirKimlikler(t, kc2)), orijinal) {
		t.Fatal("a wrong passphrase still changed local.mk or the keychain")
	}
	artik()
	out, err = certHazirKos(t, tmpDir, certHazirParola, args(kc2)...)
	if err != nil || !strings.Contains(out, "restored") {
		t.Fatalf("branch 2 (restore the .p12): %v\n%s", err, out)
	}
	if got := certHazirSha1(t, localMk); got != orijinal {
		t.Fatalf("restored SHA-1 %s != original %s", got, orijinal)
	}
	mk := certHazirIcerik(t, localMk)
	for _, s := range []string{"TRUSTED_DIRS = ~/bin\n", "DEV_ROOT = ~/src\n", "SIGN_KEYCHAIN = " + kc2 + "\n"} {
		if !strings.Contains(mk, s) {
			t.Errorf("local.mk lost %q:\n%s", s, mk)
		}
	}
	if strings.Contains(mk, stale) {
		t.Errorf("stale identity still in local.mk:\n%s", mk)
	}
	if !strings.Contains(strings.ToUpper(certHazirKimlikler(t, kc2)), strings.ToUpper(orijinal)) {
		t.Fatalf("restored identity not in the keychain:\n%s", certHazirKimlikler(t, kc2))
	}
	artik()
	if certHazirIcerik(t, p12) != p12Once {
		t.Fatal("the .p12 backup was modified")
	}
	// The restored identity signs (codesign may use the key; partition list as in the e2e tests).
	if out, err := komutKos(t, "", nil, "/usr/bin/security", "set-key-partition-list",
		"-S", "apple-tool:,apple:", "-s", "-k", kcp2, kc2); err != nil {
		t.Fatalf("set-key-partition-list: %v\n%s", err, out)
	}
	bin := e2eKopya(t, "/bin/ls", "signed")
	e2eImzala(t, bin, orijinal, kc2)

	// ... and the second call after the restore is a no-op too.
	mk2, kim2 := certHazirIcerik(t, localMk), certHazirKimlikler(t, kc2)
	out, err = certHazirKos(t, tmpDir, "", args(kc2)...)
	if err != nil || !strings.Contains(out, "certificate ready") || certHazirIcerik(t, localMk) != mk2 || certHazirKimlikler(t, kc2) != kim2 {
		t.Fatalf("second call after the restore: %v\n%s", err, out)
	}

	// Restoring the same .p12 into a keychain that already has the identity
	// (local.mk lost) is not an error and adds no second copy.
	if err := os.Remove(localMk); err != nil {
		t.Fatal(err)
	}
	out, err = certHazirKos(t, tmpDir, certHazirParola, args(kc2)...)
	if err != nil || certHazirSha1(t, localMk) != orijinal || certHazirKimlikler(t, kc2) != kim2 {
		t.Fatalf("restore into a keychain that already holds the identity: %v\n%s", err, out)
	}
	artik()
}
