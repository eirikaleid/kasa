package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// kasa acl migrate [--dry-run] [--target <dir>]
//
// Items written before 2.5.0 trust /usr/bin/security only; kasa cannot read
// them without a dialog. Editing an item's ACL in place needs a private API
// and is not done. Migration is delete-and-rewrite through the public API:
//
//  1. every item is read the OLD way (`security find-generic-password -g`,
//     the only reader the old ACL trusts; kasa's own read would open a dialog)
//  2. an encrypted backup is written to the backup targets, then restored into
//     a temporary keychain and compared; anything wrong stops here, nothing
//     has been changed yet
//  3. per item: remember the attributes, delete, write again with the same
//     attributes and kasa's own ACL, read back with kasa and compare byte for
//     byte. On a mismatch the value held in memory is written again at once
//     and the run stops.
//
// Items already bound to this kasa are skipped, so a second run changes
// nothing. The backup-password item is moved last. --dry-run changes nothing.
//
// There is no "repair" command: when the signing certificate is lost, restore
// the .p12 backup, or (certificate gone for good) make a new certificate and
// `kasa import` the encrypted backup into a fresh vault. See README.

// ogeKaydi: an item's identity and attributes, read from `security dump-keychain`.
type ogeKaydi struct{ svc, acct, etiket, tur, aciklama string }

func (o ogeKaydi) ad() string { return o.svc + " / " + o.acct }

// kcOgeler: every generic password item in the vault, with its attributes.
// `dump-keychain` without -d never prints values and never opens a dialog.
func kcOgeler() ([]ogeKaydi, error) { return kcOgelerYol(keychainPath()) }

func kcOgelerYol(yol string) ([]ogeKaydi, error) {
	out, err := sec("dump-keychain", yol)
	if err != nil {
		return nil, err
	}
	var ogeler []ogeKaydi
	var cur ogeKaydi
	genp := false
	flush := func() {
		if genp && cur.svc != "" {
			ogeler = append(ogeler, cur)
		}
		cur, genp = ogeKaydi{}, false
	}
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "keychain:"):
			flush()
		case strings.HasPrefix(t, "class:"):
			genp = strings.Contains(t, `"genp"`)
		case strings.HasPrefix(t, `"svce"<blob>=`):
			cur.svc = dumpDeger(strings.TrimPrefix(t, `"svce"<blob>=`))
		case strings.HasPrefix(t, `"acct"<blob>=`):
			cur.acct = dumpDeger(strings.TrimPrefix(t, `"acct"<blob>=`))
		case strings.HasPrefix(t, `"labl"<blob>=`):
			cur.etiket = dumpDeger(strings.TrimPrefix(t, `"labl"<blob>=`))
		case strings.HasPrefix(t, `"desc"<blob>=`):
			cur.tur = dumpDeger(strings.TrimPrefix(t, `"desc"<blob>=`))
		case strings.HasPrefix(t, `"icmt"<blob>=`):
			cur.aciklama = dumpDeger(strings.TrimPrefix(t, `"icmt"<blob>=`))
		}
	}
	flush()
	return ogeler, nil
}

// dumpDeger: `"plain"` or `0xHEX  "escaped"` (non-ASCII attribute) -> raw string;
// `<NULL>` -> "".
func dumpDeger(s string) string {
	if strings.HasPrefix(s, "0x") {
		h := s[2:]
		if j := strings.IndexByte(h, ' '); j >= 0 {
			h = h[:j]
		}
		if b, err := hex.DecodeString(h); err == nil {
			return string(b)
		}
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return ""
}

// eskiOku: reads a single generic password value the pre-2.5.0 way: through
// the security CLI (the value is NOT in argv, it is on the stderr pipe).
//
// `-w` is NOT used: for a value containing unprintable bytes (UTF-8 non-ASCII
// letters, newline, tab), security prints it as HEX with -w, which cannot be
// told apart from a value that really is hex. `-g` instead gives the value on
// stderr in two forms:
//
//	password: "plain value"
//	password: 0x<HEX>  "<escaped representation>"
//
// the second is decoded from hex; so the value is always identical byte for byte.
func eskiOku(svc, acct string) (string, error) {
	out, errb, err := secBaytStderr("find-generic-password", "-s", svc, "-a", acct, "-g", keychainPath())
	sifirlaBayt(out)
	if err != nil {
		sifirlaBayt(errb)
		return "", err
	}
	v, perr := parolaSatiriCoz(errb)
	sifirlaBayt(errb)
	return v, perr
}

// parolaSatiriCoz: parses the "password:" line in the stderr of `security ... -g`.
func parolaSatiriCoz(errb []byte) (string, error) {
	const on = "password: "
	s := string(errb)
	i := strings.Index(s, on)
	if i < 0 {
		return "", fmt.Errorf("no password line in security output")
	}
	s = s[i+len(on):]
	if strings.HasPrefix(s, "0x") {
		h := s[2:]
		if j := strings.IndexAny(h, " \n"); j >= 0 {
			h = h[:j]
		}
		b, err := hex.DecodeString(h)
		if err != nil {
			return "", fmt.Errorf("could not decode security hex output")
		}
		v := string(b)
		sifirlaBayt(b)
		return v, nil
	}
	if j := strings.LastIndex(s, "\n"); j >= 0 {
		s = s[:j]
	}
	if s == "" {
		return "", nil
	}
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", fmt.Errorf("security password line has an unexpected format")
	}
	return s[1 : len(s)-1], nil
}

// gocOku: an item bound to this kasa is read by kasa; an old one the old way.
func gocOku(o ogeKaydi, bagli bool) (string, error) {
	if bagli {
		return kcOkuYol(keychainPath(), o.svc, o.acct)
	}
	return eskiOku(o.svc, o.acct)
}

type gocDurum struct {
	o     ogeKaydi
	bagli bool
}

type aclSonuc struct{ bagli, tasindi, tasinacak, hata int }

// gocPlani: the items in migration order (the backup-password item last) and
// whether each is already bound to the running kasa.
func gocPlani() ([]gocDurum, error) {
	ogeler, err := kcOgeler()
	if err != nil {
		return nil, err
	}
	sort.SliceStable(ogeler, func(i, j int) bool {
		return ogeler[i].svc != yedekParolaService && ogeler[j].svc == yedekParolaService
	})
	var plan []gocDurum
	for _, o := range ogeler {
		b, err := kcBagliMiYol(keychainPath(), o.svc, o.acct)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", o.ad(), err)
		}
		plan = append(plan, gocDurum{o, b})
	}
	return plan, nil
}

// yedekAl: writes the encrypted backup of every `kasa` item (the same bundle
// `kasa export` writes) to each path, then proves it can be restored: it is
// read back from disk, decrypted, written into a temporary keychain with the
// production write path and read back from there, byte for byte.
func yedekAl(plan []gocDurum, parola string, yollar []string) error {
	b := bundle{
		Version:     bundleVersion,
		Olusturuldu: time.Now().Format(time.RFC3339),
		Makine:      hostname(),
		Secrets:     map[string]string{},
		Profiles:    map[string]Profile{},
	}
	if c, err := loadConfig(); err == nil && c.Profiles != nil {
		b.Profiles = c.Profiles
	}
	for _, d := range plan {
		if d.o.svc != service {
			continue
		}
		v, err := gocOku(d.o, d.bagli)
		if err != nil {
			return fmt.Errorf("could not read %s for the backup: %w", d.o.ad(), err)
		}
		b.Secrets[d.o.acct] = v
	}
	plain, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	enc, err := sealBundle(plain, parola)
	if err != nil {
		return err
	}
	if len(yollar) == 0 {
		return fmt.Errorf("no backup target (kasa target add <dir>, or --target <dir>)")
	}
	for _, y := range yollar {
		if err := yedegiYaz(y, enc, false); err != nil {
			return fmt.Errorf("backup could not be written to %s: %w", y, err)
		}
		geri, err := os.ReadFile(y)
		if err != nil {
			return err
		}
		if err := yedekGeriYukleDogrula(geri, parola, b.Secrets); err != nil {
			return fmt.Errorf("backup %s failed the restore check: %w", y, err)
		}
	}
	return nil
}

// yedekGeriYukleDogrula: decrypts the backup file and restores it into a
// temporary keychain (deleted afterwards); every value must come back
// identical.
func yedekGeriYukleDogrula(enc []byte, parola string, beklenen map[string]string) error {
	plain, err := openBundle(enc, parola)
	if err != nil {
		return err
	}
	var b bundle
	if err := json.Unmarshal(plain, &b); err != nil {
		return err
	}
	if len(b.Secrets) != len(beklenen) {
		return fmt.Errorf("backup holds %d secrets, expected %d", len(b.Secrets), len(beklenen))
	}
	d, err := os.MkdirTemp("", "kasa-yedek-dogrula-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(d)
	yol := filepath.Join(d, "dogrula.keychain-db")
	rb := make([]byte, 16)
	if _, err := rand.Read(rb); err != nil {
		return err
	}
	rp := []byte(hex.EncodeToString(rb))
	defer sifirlaBayt(rp)
	if err := kcOlusturYol(yol, rp); err != nil {
		return fmt.Errorf("temporary keychain: %w", err)
	}
	defer kcKeychainSilYol(yol)
	for k, v := range b.Secrets {
		if beklenen[k] != v {
			return fmt.Errorf("%s: backup content differs from the vault", k)
		}
		if err := kcYazYol(yol, service, k, []byte(v), "kasa secret", "managed by kasa"); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		got, err := kcOkuYol(yol, service, k)
		if err != nil || got != v {
			return fmt.Errorf("%s: does not come back identical from the temporary keychain (%v)", k, err)
		}
	}
	return nil
}

// gocGeriOku: the read-back after a rewrite (a variable so a test can inject a mismatch).
var gocGeriOku = kcOkuYol

// ogeTasi: delete, rewrite with the same attributes and kasa's own ACL, read
// back and compare. If the rewritten value differs, the value held in memory
// is written again at once. The value never leaves this function except into
// the keychain.
func ogeTasi(o ogeKaydi, deger string) error {
	// Between the delete and the verified rewrite the item exists nowhere but in
	// this process: a SIGINT/SIGTERM/SIGHUP there would lose it, so they are held
	// until the item is back and the run stops right after (errKesildi).
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(ch)
	err := ogeTasiIc(o, deger)
	if err == nil && len(ch) > 0 {
		return errKesildi
	}
	return err
}

var errKesildi = errors.New("interrupted by a signal; the item in progress was written back first, nothing is lost. rerun")

// ogeTasiAra: test hook, called between the delete and the rewrite (nil in production).
var ogeTasiAra func()

func ogeTasiIc(o ogeKaydi, deger string) error {
	yol := keychainPath()
	if err := kcSilYol(yol, o.svc, o.acct); err != nil {
		return fmt.Errorf("could not delete the old item (nothing was changed): %w", err)
	}
	if ogeTasiAra != nil {
		ogeTasiAra()
	}
	yaz := func() error {
		return kcYazNitelikYol(yol, o.svc, o.acct, []byte(deger), o.etiket, o.tur, o.aciklama)
	}
	if err := yaz(); err != nil {
		if err2 := yaz(); err2 != nil {
			return fmt.Errorf("the old item was deleted and could NOT be written again (%v); restore it from the backup: kasa import <backup file>", err2)
		}
	}
	got, err := gocGeriOku(yol, o.svc, o.acct)
	if err == nil && got == deger {
		return nil
	}
	if err := yaz(); err != nil {
		return fmt.Errorf("read-back differed and the rewrite failed (%v); restore from the backup: kasa import <backup file>", err)
	}
	got, err = gocGeriOku(yol, o.svc, o.acct)
	if err != nil || got != deger {
		return fmt.Errorf("read-back still differs after rewriting; restore from the backup: kasa import <backup file>")
	}
	return fmt.Errorf("read-back differed at first; the value was written again and now matches (stopping)")
}

// aclGocur: the core of `kasa acl migrate`. In a dry run nothing is written;
// the old-way read is still tried, so a problem shows up before the real run.
func aclGocur(w io.Writer, prova bool, parola string, yollar []string) (aclSonuc, error) {
	var s aclSonuc
	plan, err := gocPlani()
	if err != nil {
		return s, err
	}
	for _, d := range plan {
		if !d.bagli {
			s.tasinacak++
		}
	}
	if !prova && s.tasinacak > 0 {
		if err := yedekAl(plan, parola, yollar); err != nil {
			return s, fmt.Errorf("backup failed, nothing was changed: %w", err)
		}
		fmt.Fprintf(w, "backup written and restore-checked: %s\n", strings.Join(yollar, ", "))
	}
	for _, d := range plan {
		ad := d.o.ad()
		if d.bagli {
			s.bagli++
			fmt.Fprintf(w, "  skipped     %s (already bound to this kasa)\n", ad)
			continue
		}
		v, err := eskiOku(d.o.svc, d.o.acct)
		if err != nil {
			s.hata++
			fmt.Fprintf(w, "  ERROR       %s: could not read the old way: %v\n", ad, err)
			if prova {
				continue
			}
			return s, fmt.Errorf("stopped at %s", ad)
		}
		if prova {
			fmt.Fprintf(w, "  would move  %s\n", ad)
			continue
		}
		err = ogeTasi(d.o, v)
		if err != nil {
			s.hata++
			fmt.Fprintf(w, "  ERROR       %s: %v\n", ad, err)
			return s, fmt.Errorf("stopped at %s", ad)
		}
		s.tasindi++
		s.tasinacak--
		fmt.Fprintf(w, "  moved       %s\n", ad)
	}
	fmt.Fprintf(w, "%d item(s): %d already bound, %d moved, %d to move, %d error(s)\n",
		len(plan), s.bagli, s.tasindi, s.tasinacak, s.hata)
	if s.hata > 0 {
		return s, fmt.Errorf("%d item(s) could not be moved", s.hata)
	}
	return s, nil
}

// imzaliMi: is the running kasa signed with a certificate (not ad-hoc)? Items
// bound to an ad-hoc kasa work, but the next rebuild loses access again.
func imzaliMi() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	out, _ := exec.Command("/usr/bin/codesign", "-dvv", exe).CombinedOutput()
	return strings.Contains(string(out), "\nAuthority=")
}

// gocYedekParolasi: the password the pre-migration backup is encrypted with:
// the stored backup password (read the old way if not migrated yet), else
// asked on the terminal like `kasa export`.
func gocYedekParolasi() (string, error) {
	p, err := kcOkuYol(keychainPath(), yedekParolaService, yedekParolaAccount)
	if err != nil {
		p, err = eskiOku(yedekParolaService, yedekParolaAccount)
	}
	if err == nil && p != "" {
		if kusur := yedekParolaKusuruMin(p, minYedekParolaEski); kusur != "" {
			return "", fmt.Errorf("the stored backup password does not meet the rules (%s); fix: kasa backup-password set", kusur)
		}
		return p, nil
	}
	if !isTTY() {
		return "", fmt.Errorf("no backup password stored and no terminal to ask on (kasa backup-password set)")
	}
	aday, err := promptSecret("backup password: ")
	if err != nil {
		return "", err
	}
	if kusur := yedekParolaKusuru(aday); kusur != "" {
		return "", fmt.Errorf("backup password does not meet the rules: %s", kusur)
	}
	tekrar, err := promptSecret("repeat         : ")
	if err != nil {
		return "", err
	}
	if aday != tekrar {
		return "", fmt.Errorf("passwords do not match")
	}
	return aday, nil
}

func cmdAcl(args []string) error {
	if len(args) == 2 && args[0] == "devral" {
		return aclDevral(args[1])
	}
	if len(args) == 2 && args[0] == "tasi" {
		return aclTasi(args[1])
	}
	if len(args) == 1 && args[0] == "yokla" {
		os.Exit(aclYokla())
	}
	if len(args) == 0 || args[0] != "migrate" {
		return fmt.Errorf("usage: kasa acl migrate [--dry-run] [--target <dir>]\n       kasa acl devral <backup.age>\n       kasa acl tasi <backup.age>\n       kasa acl yokla")
	}
	f := parseFlags(args[1:])
	prova := f["dry-run"] == "true" || f["prova"] == "true"
	if err := requireKasa(); err != nil {
		return err
	}
	if isAgent() {
		audit("DENIED", "acl", "migrate", "agent environment")
		return fmt.Errorf("denied: only a human can migrate the vault's items")
	}
	if !imzaliMi() {
		fmt.Fprintln(os.Stderr, "WARNING: this kasa is ad-hoc signed; migrated items become unreadable after the next rebuild. Run `make cert-hazir` and `make install` first.")
	}
	if err := kilitKapisi(); err != nil {
		return err
	}
	if prova {
		fmt.Println("dry run, nothing changes:")
		_, err := aclGocur(os.Stdout, true, "", nil)
		return err
	}

	var yollar []string
	ad := fmt.Sprintf("kasa-yedek-goconcesi-%s.age", time.Now().Format("20060102-150405"))
	if h := f["target"]; h != "" {
		yollar = []string{filepath.Join(expandHome(h), ad)}
	} else {
		c, err := loadConfig()
		if err != nil {
			return err
		}
		for _, h := range hedefler(c) {
			yollar = append(yollar, filepath.Join(h, ad))
		}
	}
	if len(yollar) == 0 {
		return fmt.Errorf("no backup target. migration always takes an encrypted backup first:\n" +
			"  kasa target add <dir>   or   kasa acl migrate --target <dir>")
	}
	p, err := gocYedekParolasi()
	if err != nil {
		return err
	}
	_, err = aclGocur(os.Stdout, false, p, yollar)
	if err != nil {
		audit("FAIL", "acl", "migrate", err.Error())
		return err
	}
	audit("OK", "acl", "migrate", "")
	return nil
}

// degerSaglam: encoding/json turns invalid UTF-8 into U+FFFD without a word, so
// a backup value holding U+FFFD may not be what the vault held; writing it
// would replace the original with the damaged copy. Names only, never values.
func degerSaglam(acct, v string) error {
	if !utf8.ValidString(v) || strings.ContainsRune(v, utf8.RuneError) {
		return fmt.Errorf("%s", acct)
	}
	return nil
}

func bozukDegerHatasi(bozuk []string) error {
	sort.Strings(bozuk)
	return fmt.Errorf("%d value(s) in the backup hold invalid UTF-8 or U+FFFD (an export replaces undecodable bytes silently), "+
		"so they cannot be moved faithfully; nothing was changed: %s", len(bozuk), strings.Join(bozuk, ", "))
}

// kasa acl devral <backup.age>: handover after an upgrade.
//
// macOS gives a keychain under ~/Library/Keychains/ partition lists. An item
// written by kasa (self-signed, no Team ID) carries the writer's cdhash there,
// so a kasa built from changed source cannot read or modify it, even signed
// with the same certificate: the certificate-bound ACL is necessary, not
// sufficient. It can still delete it. The public API offers no way to widen a
// partition list without the private password variant, so the items are
// handed over: the OLD kasa writes its encrypted backup (`kasa export <file>`),
// this kasa opens it with the backup password and moves every item by
// delete-and-rewrite with read-back (ogeTasi). The plaintext never leaves the
// two kasa processes; on disk there is only the encrypted file, which stays
// until the end. Items this kasa already reads with the same value are
// skipped, so a rerun after an interruption continues where it stopped. The
// backup-password item goes last, written with the password that just opened
// the backup.
//
// The loop runs over the vault's listing, and an item deleted but not yet
// written back (a kill inside the window) is not in the listing any more; so
// after the loop every key of the backup that the vault lacks is written again
// (and named). Before anything is touched, every item of the vault must be in
// the backup and every value must survive the JSON round trip.
func aclDevral(dosya string) error {
	if err := requireHuman("acl", "devral"); err != nil {
		return err
	}
	if err := requireKasa(); err != nil {
		return err
	}
	if err := kilitKapisi(); err != nil {
		return err
	}
	b, parola, err := yedekAc(dosya)
	if err != nil {
		return err
	}
	err = devralYap(b, parola)
	if err != nil {
		audit("FAIL", "acl", "devral", err.Error())
		return err
	}
	audit("OK", "acl", "devral", "")
	return nil
}

// yedekAc: reads the encrypted export and opens it with the backup password typed on the terminal.
func yedekAc(dosya string) (bundle, string, error) {
	var b bundle
	enc, err := os.ReadFile(expandHome(dosya))
	if err != nil {
		return b, "", err
	}
	parola, err := promptSecret("backup password: ")
	if err != nil {
		return b, "", err
	}
	plain, err := openBundle(enc, parola)
	if err != nil {
		return b, "", err
	}
	if err := json.Unmarshal(plain, &b); err != nil {
		return b, "", fmt.Errorf("backup is corrupt: %w", err)
	}
	return b, parola, nil
}

func devralYap(b bundle, parola string) error {
	ogeler, err := kcOgeler()
	if err != nil {
		return err
	}
	var eksik, bozuk []string
	var yp []ogeKaydi
	vardir := map[string]bool{}
	for _, o := range ogeler {
		if o.svc == yedekParolaService && o.acct == yedekParolaAccount {
			yp = append(yp, o)
			continue
		}
		if o.svc != service {
			continue
		}
		vardir[o.acct] = true
		v, ok := b.Secrets[o.acct]
		if !ok {
			eksik = append(eksik, o.acct)
		} else if degerSaglam(o.acct, v) != nil {
			bozuk = append(bozuk, o.acct)
		}
	}
	for k, v := range b.Secrets {
		if !vardir[k] && degerSaglam(k, v) != nil {
			bozuk = append(bozuk, k)
		}
	}
	if len(eksik) > 0 {
		sort.Strings(eksik)
		return fmt.Errorf("%d item(s) of the vault are not in the backup, nothing was changed: %s\n"+
			"  export again with the old kasa and rerun", len(eksik), strings.Join(eksik, ", "))
	}
	if len(bozuk) > 0 {
		return bozukDegerHatasi(bozuk)
	}
	yol := keychainPath()
	tasi := func(o ogeKaydi, deger string) (bool, error) {
		if v, err := kcOkuYol(yol, o.svc, o.acct); err == nil && v == deger {
			return false, nil
		}
		if err := ogeTasi(o, deger); err != nil {
			return false, fmt.Errorf("%s: %w", o.ad(), err)
		}
		return true, nil
	}
	tasinan, ayni := 0, 0
	for _, o := range ogeler {
		if o.svc != service {
			continue
		}
		t, err := tasi(o, b.Secrets[o.acct])
		if err != nil {
			return err
		}
		if t {
			tasinan++
		} else {
			ayni++
		}
	}
	var geri []string
	for k, v := range b.Secrets {
		if vardir[k] {
			continue
		}
		if err := kcYazYol(yol, service, k, []byte(v), "kasa secret", "managed by kasa"); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		if got, err := kcOkuYol(yol, service, k); err != nil || got != v {
			return fmt.Errorf("%s: read-back differs after writing it back from the backup; rerun", k)
		}
		geri = append(geri, k)
	}
	for _, o := range yp {
		t, err := tasi(o, parola)
		if err != nil {
			return err
		}
		if t {
			tasinan++
		} else {
			ayni++
		}
	}
	fmt.Printf("handover: %d moved, %d already readable by this kasa\n", tasinan, ayni)
	if len(geri) > 0 {
		sort.Strings(geri)
		fmt.Printf("written back from the backup (they were not in the vault, e.g. a run killed between delete and write; delete again if you removed them on purpose): %s\n", strings.Join(geri, ", "))
	}
	if len(yp) == 0 {
		fmt.Println("note: the vault has no backup-password item; if there should be one: kasa backup-password set")
	}
	return nil
}

// tasiBayatMi: the export must be newer than the last change of the old vault
// file, else items changed or added since would be lost. Compared in whole
// seconds (the export stamps seconds).
func tasiBayatMi(b bundle, eski string) error {
	olusturuldu, err := time.Parse(time.RFC3339, b.Olusturuldu)
	if err != nil {
		return fmt.Errorf("the backup carries no readable creation time (%q); export again with the old kasa", b.Olusturuldu)
	}
	st, err := os.Stat(eski)
	if err != nil {
		return err
	}
	if st.ModTime().Truncate(time.Second).After(olusturuldu) {
		return fmt.Errorf("the backup is stale: the old vault changed (%s) after it was exported (%s); "+
			"export again with the old kasa and rerun", st.ModTime().Format(time.RFC3339), b.Olusturuldu)
	}
	return nil
}

// tasiHazirla: every check, before the new vault is created or anything is written.
// normal: the old vault's kasa items; yp: the backup-password item; atlanan:
// everything else (named for the user, it stays only in the old file).
func tasiHazirla(b bundle, eski string) (normal, yp, atlanan []ogeKaydi, err error) {
	ogeler, err := kcOgelerYol(eski)
	if err != nil {
		return nil, nil, nil, err
	}
	var eksik, bozuk []string
	for _, o := range ogeler {
		switch {
		case o.svc == yedekParolaService && o.acct == yedekParolaAccount:
			yp = append(yp, o)
		case o.svc == service:
			v, ok := b.Secrets[o.acct]
			if !ok {
				eksik = append(eksik, o.acct)
			} else if degerSaglam(o.acct, v) != nil {
				bozuk = append(bozuk, o.acct)
			}
			normal = append(normal, o)
		default:
			atlanan = append(atlanan, o)
		}
	}
	if len(eksik) > 0 {
		sort.Strings(eksik)
		return nil, nil, nil, fmt.Errorf("%d item(s) of the old vault are not in the backup, nothing was changed: %s\n"+
			"  export again with the old kasa (`kasa export <file>`) and rerun", len(eksik), strings.Join(eksik, ", "))
	}
	if len(bozuk) > 0 {
		return nil, nil, nil, bozukDegerHatasi(bozuk)
	}
	return normal, yp, atlanan, nil
}

// testTasiDur: set ONLY by tests (-ldflags -X): "N" stops tasiYap with an error
// after N items were written, the state a kill would leave.
var testTasiDur string

// tasiYap: writes every item into the (existing, unlocked) new vault, checks
// that each one is in the new vault's listing, and only then renames the old
// file. Equal items are skipped, so a rerun after an interruption continues.
func tasiYap(b bundle, parola, eski string, normal, yp []ogeKaydi) (yazilan, ayni int, son string, err error) {
	yol := keychainPath()
	dur, _ := strconv.Atoi(testTasiDur)
	yaz := func(o ogeKaydi, deger string) error {
		if v, err := kcOkuYol(yol, o.svc, o.acct); err == nil && v == deger {
			ayni++
			return nil
		}
		if err := kcYazNitelikYol(yol, o.svc, o.acct, []byte(deger), o.etiket, o.tur, o.aciklama); err != nil {
			return fmt.Errorf("%s: %w", o.ad(), err)
		}
		if got, err := kcOkuYol(yol, o.svc, o.acct); err != nil || got != deger {
			return fmt.Errorf("%s: read-back differs; the old vault is untouched, rerun", o.ad())
		}
		yazilan++
		if dur > 0 && yazilan >= dur {
			return fmt.Errorf("stopped by the test hook after %d items", yazilan)
		}
		return nil
	}
	for _, o := range normal {
		if err := yaz(o, b.Secrets[o.acct]); err != nil {
			return yazilan, ayni, "", err
		}
	}
	for _, o := range yp {
		if err := yaz(o, parola); err != nil {
			return yazilan, ayni, "", err
		}
	}
	yeni, err := kcOgelerYol(yol)
	if err != nil {
		return yazilan, ayni, "", err
	}
	var dest = map[[2]string]bool{}
	for _, o := range yeni {
		dest[[2]string{o.svc, o.acct}] = true
	}
	var yok []string
	for _, o := range append(append([]ogeKaydi{}, normal...), yp...) {
		if !dest[[2]string{o.svc, o.acct}] {
			yok = append(yok, o.ad())
		}
	}
	if len(yok) > 0 {
		return yazilan, ayni, "", fmt.Errorf("%d item(s) of the old vault are not in the new vault's listing; the old vault is untouched, rerun: %s", len(yok), strings.Join(yok, ", "))
	}
	son = eski + ".eski"
	if _, err := os.Stat(son); err == nil {
		son = eski + time.Now().Format(".20060102-150405.eski")
	}
	if err := os.Rename(eski, son); err != nil {
		return yazilan, ayni, "", fmt.Errorf("items are in the new vault but the old file could not be renamed: %w", err)
	}
	return yazilan, ayni, son, nil
}

// kasa acl tasi <backup.age>: move the vault from ~/Library/Keychains (up to
// 2.5.x) to the place this kasa uses (keychainPath).
//
// A keychain FILE moved by hand keeps its items' partition lists (measured:
// the moved file is unreadable for a rebuilt kasa), so the items are written
// again into a new vault, which carries none: the OLD kasa writes its
// encrypted backup (`kasa export <file>`), this kasa opens it with the backup
// password and writes every item the old vault lists, with its attributes,
// reading each back. Only when all of them are in the new vault is the old
// file renamed to <name>.eski (never deleted); while the old file is still
// there the move counts as UNFINISHED (requireKasa, status, acl yokla). A
// rerun continues where an interruption stopped: the new vault is reused and
// equal items are skipped. A backup older than the last change of the old
// vault is refused.
func aclTasi(dosya string) error {
	if err := requireHuman("acl", "tasi"); err != nil {
		return err
	}
	eski := eskiKasaYolu()
	if eski == "" {
		return fmt.Errorf("no old vault to move (nothing at %s)", eskiKeychainYolu())
	}
	b, parola, err := yedekAc(dosya)
	if err != nil {
		return err
	}
	if err := tasiBayatMi(b, eski); err != nil {
		return err
	}
	normal, yp, atlanan, err := tasiHazirla(b, eski)
	if err != nil {
		return err
	}
	if !keychainExists() {
		p, err := yeniMasterParola()
		if err != nil {
			return err
		}
		if err := kcCreate(p); err != nil {
			return err
		}
	} else if err := kilitKapisi(); err != nil {
		return err
	}
	yazilan, ayni, son, err := tasiYap(b, parola, eski, normal, yp)
	if err != nil {
		audit("FAIL", "acl", "tasi", err.Error())
		return err
	}
	fmt.Printf("moved: %d written, %d already there; all %d items of the old vault are in %s\n",
		yazilan, ayni, len(normal)+len(yp), keychainPath())
	if len(atlanan) > 0 {
		fmt.Printf("NOT moved (not kasa secrets; they stay only in the old file %s):\n", son)
		for _, o := range atlanan {
			fmt.Println("  " + o.ad())
		}
	}
	fmt.Printf("old vault kept as %s\nonce `kasa export` works, delete the old vault and the encrypted backup yourself: rm -P %s %s\n",
		son, expandHome(dosya), son)
	audit("OK", "acl", "tasi", "")
	return nil
}

// kasa acl yokla: can THIS kasa read an item of the vault it uses? Prints one
// line (no value) and exits with: 0 readable, or not testable (no vault /
// locked / no item: stated, not an error); 1 unreadable (-25293: another build
// wrote the items, handover: acl devral); 2 the vault is at its old place or
// the move to the new place is unfinished (acl tasi); 3 some other error.
// `make install` uses it as its gate: the question is "can the new binary
// read", not "is it the same binary".
func aclYokla() int {
	if e := eskiKasaYolu(); e != "" {
		if keychainExists() {
			fmt.Println("move-unfinished: the new vault holds only part of the items; the old vault is still at " + e)
		} else {
			fmt.Println("old-place: the vault is still at " + e)
		}
		return 2
	}
	if !keychainExists() {
		fmt.Println("untested: no vault")
		return 0
	}
	if isLocked() {
		fmt.Println("untested: the vault is locked")
		return 0
	}
	ogeler, err := kcOgeler()
	if err != nil {
		fmt.Println("error: " + err.Error())
		return 3
	}
	var aday *ogeKaydi
	for i, o := range ogeler {
		if o.svc == service {
			aday = &ogeler[i]
			break
		}
		if o.svc == yedekParolaService && o.acct == yedekParolaAccount && aday == nil {
			aday = &ogeler[i]
		}
	}
	if aday == nil {
		fmt.Println("untested: the vault has no item")
		return 0
	}
	switch _, err := kcOkuYol(keychainPath(), aday.svc, aday.acct); {
	case err == nil:
		fmt.Println("ok: this kasa reads the vault's items")
		return 0
	case errors.Is(err, errYetkisiz):
		fmt.Println("unreadable: another build wrote the items (-25293)")
		return 1
	default:
		fmt.Println("error: " + err.Error())
		return 3
	}
}
