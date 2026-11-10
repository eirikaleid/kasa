package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests run in the test process against temporary keychains: the process
// writes and reads its own items (its ACL trusts the running binary), so no
// partition list or signing is involved; they cover kasa's own logic.

func yazTest(t *testing.T, svc, acct, deger string) {
	t.Helper()
	if err := kcYazYol(keychainPath(), svc, acct, []byte(deger), "kasa secret", "managed by kasa"); err != nil {
		t.Fatalf("write %s: %v", acct, err)
	}
}

func okuTest(t *testing.T, acct string) string {
	t.Helper()
	v, err := kcOkuYol(keychainPath(), service, acct)
	if err != nil {
		t.Fatalf("read %s: %v", acct, err)
	}
	return v
}

// An account name with non-ASCII characters is printed by dump-keychain as
// `0x<hex>  "..."`; the key list (and so export) used to skip such items.
func TestKcListHexAcct(t *testing.T) {
	geciciKasa(t)
	yazTest(t, service, "plain/key", "v1")
	yazTest(t, service, "ünï/kod", "v2")
	keys, err := kcList()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(keys, "|")
	if !strings.Contains(got, "plain/key") || !strings.Contains(got, "ünï/kod") {
		t.Fatalf("kcList dropped an item: %q", got)
	}
}

// A signal between the delete and the rewrite is held until the item is back.
func TestOgeTasiSinyalBekler(t *testing.T) {
	geciciKasa(t)
	yazTest(t, service, "sig/key", "old")
	ogeTasiAra = func() {
		syscall.Kill(os.Getpid(), syscall.SIGTERM)
		time.Sleep(300 * time.Millisecond)
	}
	t.Cleanup(func() { ogeTasiAra = nil })
	err := ogeTasi(ogeKaydi{svc: service, acct: "sig/key", etiket: service, tur: "kasa secret", aciklama: "managed by kasa"}, "new")
	if !errors.Is(err, errKesildi) {
		t.Fatalf("want errKesildi, got %v", err)
	}
	if v := okuTest(t, "sig/key"); v != "new" {
		t.Fatalf("the item was not written back before stopping: %q", v)
	}
}

func TestDevralYarimKalan(t *testing.T) {
	geciciKasa(t)
	yazTest(t, service, "k/one", "same")
	yazTest(t, service, "k/two", "stale")
	// k/three is in the backup but not in the vault: an earlier run was killed
	// between the delete and the rewrite.
	b := bundle{Secrets: map[string]string{"k/one": "same", "k/two": "fresh", "k/three": "lost"}}
	if err := devralYap(b, "Backup.Pass-2026"); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"k/one": "same", "k/two": "fresh", "k/three": "lost"} {
		if v := okuTest(t, k); v != want {
			t.Fatalf("%s = %q, want %q", k, v, want)
		}
	}
}

func TestDevralOnceDenetler(t *testing.T) {
	geciciKasa(t)
	yazTest(t, service, "k/one", "keep-me")
	yazTest(t, service, "k/notinbackup", "x")
	b := bundle{Secrets: map[string]string{"k/one": "other"}}
	if err := devralYap(b, "p"); err == nil || !strings.Contains(err.Error(), "k/notinbackup") {
		t.Fatalf("an item missing from the backup must stop it before anything is touched: %v", err)
	}
	if v := okuTest(t, "k/one"); v != "keep-me" {
		t.Fatalf("an item was touched before the check: %q", v)
	}
	b = bundle{Secrets: map[string]string{"k/one": "bad�value", "k/notinbackup": "x"}}
	if err := devralYap(b, "p"); err == nil || !strings.Contains(err.Error(), "k/one") || strings.Contains(err.Error(), "bad") {
		t.Fatalf("a value with U+FFFD must be refused by name, not by value: %v", err)
	}
	if v := okuTest(t, "k/one"); v != "keep-me" {
		t.Fatalf("an item was touched: %q", v)
	}
}

func TestTasiBayatMi(t *testing.T) {
	f := filepath.Join(t.TempDir(), "old.keychain-db")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	degisti := time.Now().Add(-time.Minute)
	if err := os.Chtimes(f, degisti, degisti); err != nil {
		t.Fatal(err)
	}
	yeni := bundle{Olusturuldu: degisti.Add(10 * time.Second).Format(time.RFC3339)}
	if err := tasiBayatMi(yeni, f); err != nil {
		t.Fatalf("an export made after the last change is fresh: %v", err)
	}
	eski := bundle{Olusturuldu: degisti.Add(-10 * time.Second).Format(time.RFC3339)}
	if err := tasiBayatMi(eski, f); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("an export older than the vault file must be refused: %v", err)
	}
	if err := tasiBayatMi(bundle{Olusturuldu: "yesterday"}, f); err == nil {
		t.Fatal("an unreadable creation time must be refused")
	}
}

// tasi interrupted in the middle (a kill leaves exactly this): the old file is
// still there, so the move counts as unfinished everywhere; the rerun writes
// the rest and only then renames the old file.
func TestTasiYarimKalanTamamlanir(t *testing.T) {
	eskiEv := testEvDizini
	ev := kanonikTemp(t)
	testEvDizini = ev
	t.Cleanup(func() { testEvDizini = eskiEv })
	geciciKasa(t) // the NEW vault (keychainPath)
	eski := eskiKeychainYolu()
	if err := os.MkdirAll(filepath.Dir(eski), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := kcOlusturYol(eski, []byte("temporary-old-password")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kcKeychainSilYol(eski) })
	yaz := func(svc, acct, v string) {
		if err := kcYazYol(eski, svc, acct, []byte(v), "kasa secret", "managed by kasa"); err != nil {
			t.Fatal(err)
		}
	}
	secrets := map[string]string{"t/a": "va", "t/b": "vb", "t/c": "vc"}
	for k, v := range secrets {
		yaz(service, k, v)
	}
	yaz(yedekParolaService, yedekParolaAccount, "Backup.Pass-2026")
	yaz("other-service", "x", "not a kasa secret")
	b := bundle{Secrets: secrets, Olusturuldu: time.Now().Add(time.Hour).Format(time.RFC3339)}

	normal, yp, atlanan, err := tasiHazirla(b, eski)
	if err != nil || len(normal) != 3 || len(yp) != 1 || len(atlanan) != 1 || atlanan[0].svc != "other-service" {
		t.Fatalf("tasiHazirla: %v %d %d %v", err, len(normal), len(yp), atlanan)
	}
	if _, _, _, err := tasiHazirla(bundle{Secrets: map[string]string{"t/a": "va"}}, eski); err == nil || !strings.Contains(err.Error(), "t/b") {
		t.Fatalf("an item missing from the backup must be named: %v", err)
	}
	if _, _, _, err := tasiHazirla(bundle{Secrets: map[string]string{"t/a": "va", "t/b": "\xff", "t/c": "vc"}}, eski); err == nil || !strings.Contains(err.Error(), "t/b") {
		t.Fatalf("invalid UTF-8 must be refused by name: %v", err)
	}

	testTasiDur = "2"
	t.Cleanup(func() { testTasiDur = "" })
	if _, _, _, err := tasiYap(b, "Backup.Pass-2026", eski, normal, yp); err == nil {
		t.Fatal("the hook should have stopped the first run")
	}
	if _, err := os.Stat(eski); err != nil {
		t.Fatal("the old vault must stay while the move is unfinished")
	}
	if tasiYarim() != eski {
		t.Fatal("tasiYarim must report the half-done move")
	}
	if err := requireKasa(); err == nil || !strings.Contains(err.Error(), "UNFINISHED") {
		t.Fatalf("requireKasa must refuse a half-done move: %v", err)
	}
	if rc := aclYokla(); rc != 2 {
		t.Fatalf("acl yokla must say 2 (go to acl tasi), got %d", rc)
	}

	testTasiDur = ""
	yazilan, ayni, son, err := tasiYap(b, "Backup.Pass-2026", eski, normal, yp)
	if err != nil {
		t.Fatal(err)
	}
	if yazilan != 2 || ayni != 2 {
		t.Fatalf("the rerun must write the rest and skip the first two: written %d, same %d", yazilan, ayni)
	}
	if _, err := os.Stat(son); err != nil {
		t.Fatalf("old vault not kept: %v", err)
	}
	if _, err := os.Stat(eski); err == nil {
		t.Fatal("the old file is still in place after a complete move")
	}
	if tasiYarim() != "" {
		t.Fatal("a finished move is not unfinished")
	}
	for k, v := range secrets {
		if got := okuTest(t, k); got != v {
			t.Fatalf("%s = %q", k, got)
		}
	}
}
