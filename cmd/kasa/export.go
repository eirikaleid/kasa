package main

// Portability: writes the contents of the vault into a single
// password-encrypted file in age format, and reads it back. The goal is that
// secrets are not lost when you change machines.
//
// Why not just the keychain-db file: that format is macOS-specific, cannot be
// opened on Linux, and is a binary blob that changes on every write. The .age
// file here is plain text (armored), so it diffs cleanly, and it opens on any
// platform with the standard `age -d`, even without kasa.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Backup password rule: at least minYedekParola characters AND all four
// classes (upper case, lower case, digit, punctuation/symbol). The composition
// requirement rejects single-class passwords such as "aaaaaaaaa".
//
// A newly entered password (backup-password set, or typed by hand during
// export) must be at least 12 characters. If you will keep the backup
// somewhere publicly reachable, use a passphrase of 16+ characters.
//
// minYedekParolaEski: for passwords stored before the 12-character rule. An
// old password stored in the keychain is checked against this threshold during
// export (so taking backups does not break); import applies no rule at all
// (old .age files keep opening).
const (
	minYedekParola     = 12
	minYedekParolaEski = 9
)

// yedekParolaKusuru returns "" if a NEW password meets the rule; otherwise it
// returns a one-line, human-readable description of the defect.
func yedekParolaKusuru(pass string) string {
	return yedekParolaKusuruMin(pass, minYedekParola)
}

// Length is counted in runes, not bytes: when non-ASCII letters such as
// "çğüşiö" are typed instead of "cgusio", each letter takes two bytes in UTF-8
// and len() made a short password look long.
func yedekParolaKusuruMin(pass string, min int) string {
	if n := utf8.RuneCountInString(pass); n < min {
		return fmt.Sprintf("too short (%d/%d characters)", n, min)
	}
	var buyuk, kucuk, rakam, isaret bool
	for _, r := range pass {
		switch {
		case unicode.IsUpper(r):
			buyuk = true
		case unicode.IsLower(r):
			kucuk = true
		case unicode.IsDigit(r):
			rakam = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			isaret = true
		}
	}
	var eksik []string
	if !buyuk {
		eksik = append(eksik, "upper-case letter")
	}
	if !kucuk {
		eksik = append(eksik, "lower-case letter")
	}
	if !rakam {
		eksik = append(eksik, "digit")
	}
	if !isaret {
		eksik = append(eksik, "punctuation")
	}
	if len(eksik) > 0 {
		return "missing: " + strings.Join(eksik, ", ")
	}
	return ""
}

const bundleVersion = 1

// A scrypt work factor higher than the default (18), because the backup file
// may end up living in a repository: it makes offline cracking attempts more
// expensive.
const scryptWorkFactor = 20

type bundle struct {
	Version     int                `json:"version"`
	Olusturuldu string             `json:"olusturuldu"`
	Makine      string             `json:"makine"`
	Secrets     map[string]string  `json:"secrets"`
	Profiles    map[string]Profile `json:"profiles"`
}

func defaultExportName() string {
	return "kasa-yedek-" + time.Now().Format("20060102") + ".age"
}

// ---- export ----

func cmdExport(args []string) error {
	f := parseFlags(args)
	overwrite := f["overwrite"] == "true" || f["ustune-yaz"] == "true" || f["force"] == "true" // "ustune-yaz": hidden legacy alias

	// There used to be a requireHuman here: export could never run from an
	// agent. It was removed because export writes the raw secrets not to the
	// SCREEN or a log but to a password-encrypted file - the agent cannot see
	// the contents. The gate is now the password itself: if it is not stored in
	// the keychain, the agent still cannot get through (see yedekParolasiCoz).
	if !keychainExists() {
		return fmt.Errorf("no vault, run first: kasa init")
	}

	c, err := loadConfig()
	if err != nil {
		return err
	}

	// Where to write? An explicit request first, then the configured targets.
	yollar, err := exportYollari(args, f, c, overwrite)
	if err != nil {
		return err
	}

	keys, err := kcList()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("the vault is empty, no secrets to back up")
	}

	b := bundle{
		Version:     bundleVersion,
		Olusturuldu: time.Now().Format(time.RFC3339),
		Makine:      hostname(),
		Secrets:     map[string]string{},
	}
	for _, k := range keys {
		v, err := kcGet(k)
		if err != nil {
			return fmt.Errorf("could not read %s: %w", k, err)
		}
		b.Secrets[k] = v
	}
	b.Profiles = c.Profiles

	fmt.Fprintf(os.Stderr, "%d secrets, %d profiles -> %d target(s):\n", len(b.Secrets), len(b.Profiles), len(yollar))
	for _, y := range yollar {
		fmt.Fprintln(os.Stderr, "  "+y)
	}
	if !yedekParolaVarMi() {
		fmt.Fprintln(os.Stderr, "The backup password may differ from the main password; if you forget it, the backup cannot be opened.")
		fmt.Fprintf(os.Stderr, "Rule: at least %d characters, containing an upper-case letter + a lower-case\n"+
			"letter + a digit + punctuation. Because the file may sit in a git repository,\n"+
			"if it leaks it can be attacked offline; make it long if you can.\n", minYedekParola)
		fmt.Fprintln(os.Stderr, "To stop being asked: kasa backup-password set")
	}

	// The password either comes from the keychain or is asked on the TTY; the rule is the same for both.
	pass, kaynak, err := yedekParolasiCoz()
	if err != nil {
		return err
	}
	if kaynak == "keychain" {
		fmt.Fprintln(os.Stderr, "backup password: from keychain (kasa backup-password status)")
	}

	plain, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	// Encrypt once, write the same blob to every target.
	enc, err := sealBundle(plain, pass)
	if err != nil {
		return err
	}
	// Before writing, verify that we can decrypt our own output: it is better
	// to write nothing than to copy a corrupt backup to N places.
	if _, err := openBundle(enc, pass); err != nil {
		return fmt.Errorf("internal verification failed, nothing was written: %w", err)
	}

	var basarili, basarisiz int
	for _, y := range yollar {
		if err := yedegiYaz(y, enc, overwrite); err != nil {
			fmt.Printf("  FAILED     %s\n             %v\n", y, err)
			audit("FAIL", "export", filepath.Base(y), err.Error())
			basarisiz++
			continue
		}
		fmt.Printf("  written    %s\n", y)
		audit("OK", "export", filepath.Base(y), fmt.Sprintf("%d secrets", len(b.Secrets)))
		basarili++
	}

	fmt.Printf("\nwritten to %d target(s)", basarili)
	if basarisiz > 0 {
		fmt.Printf(", %d failed", basarisiz)
	}
	fmt.Println(".")
	if basarili == 0 {
		return fmt.Errorf("could not write to any target")
	}
	if basarisiz > 0 {
		// Partial success must not pass silently: a single copy is a single point of failure.
		return fmt.Errorf("%d target(s) failed, see the errors above", basarisiz)
	}
	fmt.Println("on the new machine: kasa init && kasa unlock && kasa import <file.age>")
	return nil
}

// exportYollari: determines the full file paths to write.
//
//	kasa export                  -> every configured target
//	kasa export --target <path>  -> only this directory (or file)
//	kasa export <file.age>       -> a single file
func exportYollari(args []string, f map[string]string, c *Config, overwrite bool) ([]string, error) {
	ad := defaultExportName()

	ozel := first(f["target"], f["hedef"], f["out"], f["cikti"]) // "hedef", "cikti": hidden legacy aliases
	if ozel == "" {
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				ozel = a
				break
			}
		}
	}
	if ozel != "" {
		// An agent may only write to configured targets: it must not be able to
		// give a custom path and put the encrypted backup somewhere it can read
		// or carry out (for offline password attacks). Adding a target is a
		// human's job.
		if a := agentName(); a != "" {
			audit("DENIED", "export", filepath.Base(ozel), "agent environment: custom output path")
			return nil, fmt.Errorf("denied: a custom output path cannot be given in an agent environment (%s)\n"+
				"  configured targets only: kasa export  (targets: kasa target ls)", a)
		}
		return []string{tekYol(expandHome(ozel), ad)}, nil
	}

	hs := hedefler(c)
	if len(hs) == 0 {
		return nil, fmt.Errorf("no targets. add one first:\n" +
			"  kasa target add /Volumes/Backup/kasa\n" +
			"  kasa target add /Volumes/<disk>/kasa\n" +
			"or one-off: kasa export --target <dir>")
	}
	var yollar []string
	for _, h := range hs {
		yollar = append(yollar, filepath.Join(h, ad))
	}
	return yollar, nil
}

// tekYol: if the given path is a directory, puts the default name inside it;
// otherwise uses the path as the file name.
func tekYol(yol, ad string) string {
	if fi, err := os.Stat(yol); err == nil && fi.IsDir() {
		return filepath.Join(yol, ad)
	}
	if strings.HasSuffix(yol, string(os.PathSeparator)) {
		return filepath.Join(yol, ad)
	}
	if filepath.Ext(yol) == "" {
		return filepath.Join(yol, ad)
	}
	return yol
}

// yedegiYaz: writes to a single target ATOMICALLY (temp file in the same
// directory + fsync + rename), then reads back what was written and compares it
// byte by byte. Silent truncation or a full disk is caught this way; a
// half-written backup never appears under the target name. If the target path
// is a symlink it is rejected: the backup must not be redirected to wherever
// the symlink points (for example a publicly readable directory).
func yedegiYaz(yol string, enc []byte, overwrite bool) error {
	dir := filepath.Dir(yol)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if fi, err := os.Lstat(yol); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("target path is a symlink, not written: %s", yol)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("target path is not a regular file, not written: %s", yol)
		}
		if !overwrite {
			return fmt.Errorf("file already exists (use --overwrite to replace it)")
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".kasa-yedek-*.tmp") // 0600
	if err != nil {
		return err
	}
	tmpAd := tmp.Name()
	temizle := true
	defer func() {
		if temizle {
			os.Remove(tmpAd)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(enc); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("could not flush to disk (fsync): %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Last check before rename: if a symlink was put there in the meantime, reject again.
	if fi, err := os.Lstat(yol); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("target path is a symlink, not written: %s", yol)
	}
	if err := os.Rename(tmpAd, yol); err != nil {
		return err
	}
	temizle = false
	if d, err := os.Open(dir); err == nil {
		d.Sync() // best effort: get the rename itself onto disk too
		d.Close()
	}

	geri, err := os.ReadFile(yol)
	if err != nil {
		return fmt.Errorf("could not read back: %w", err)
	}
	if !bytes.Equal(geri, enc) {
		return fmt.Errorf("verification failed: wrote %d bytes, read %d bytes", len(enc), len(geri))
	}
	return nil
}

// ---- import ----

func cmdImport(args []string) error {
	f := parseFlags(args)
	var in string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			in = a
			break
		}
	}
	if in == "" {
		return fmt.Errorf("usage: kasa import <file.age> [--overwrite]")
	}
	overwrite := f["overwrite"] == "true" || f["ustune-yaz"] == "true" || f["force"] == "true" // "ustune-yaz": hidden legacy alias

	// Raw secrets are decrypted from the file and written into the vault: humans only.
	if err := requireHuman("import", filepath.Base(in)); err != nil {
		return err
	}
	// Order matters: the vault is created first, then unlocked, then content is written.
	if !keychainExists() {
		return fmt.Errorf("no vault. in order: kasa init -> kasa unlock -> kasa import")
	}
	if isLocked() {
		return fmt.Errorf("the vault is locked. first: kasa unlock")
	}

	enc, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	pass, err := promptSecret("backup password: ")
	if err != nil {
		return err
	}
	plain, err := openBundle(enc, pass)
	if err != nil {
		audit("FAIL", "import", filepath.Base(in), "could not decrypt")
		return err
	}
	var b bundle
	if err := json.Unmarshal(plain, &b); err != nil {
		return fmt.Errorf("backup is corrupt: %w", err)
	}
	if b.Version > bundleVersion {
		return fmt.Errorf("backup version is %d, this kasa reads at most %d", b.Version, bundleVersion)
	}

	fmt.Printf("backup: %s (%s) - %d secrets, %d profiles\n",
		b.Olusturuldu, b.Makine, len(b.Secrets), len(b.Profiles))

	mevcut := map[string]bool{}
	if keys, err := kcList(); err == nil {
		for _, k := range keys {
			mevcut[k] = true
		}
	}

	var yazildi, atlandi int
	var names []string
	for k := range b.Secrets {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if mevcut[k] && !overwrite {
			fmt.Printf("  skipped  %s (already exists, use --overwrite to replace)\n", k)
			atlandi++
			continue
		}
		if err := kcSet(k, b.Secrets[k]); err != nil {
			return fmt.Errorf("could not write %s: %w", k, err)
		}
		fmt.Printf("  written  %s\n", k)
		yazildi++
	}

	profilNot := ""
	if len(b.Profiles) > 0 {
		c, err := loadConfig()
		if err != nil {
			return err
		}
		var pYazildi, pAtlandi int
		for name, p := range b.Profiles {
			if _, varMi := c.Profiles[name]; varMi && !overwrite {
				pAtlandi++
				continue
			}
			c.Profiles[name] = p
			pYazildi++
		}
		if err := saveConfig(c); err != nil {
			return err
		}
		profilNot = fmt.Sprintf(", %d profiles", pYazildi)
		fmt.Printf("profiles: %d written, %d skipped -> %s\n", pYazildi, pAtlandi, configPath())
	}

	audit("OK", "import", filepath.Base(in), fmt.Sprintf("%d secrets%s", yazildi, profilNot))
	fmt.Printf("done: %d secrets written, %d skipped\n", yazildi, atlandi)
	return nil
}

// ---- age wrapping ----

func sealBundle(plain []byte, pass string) ([]byte, error) {
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		return nil, err
	}
	r.SetWorkFactor(scryptWorkFactor)

	var buf bytes.Buffer
	// armor: the output is plain text, diffable inside git and not corrupted by it.
	a := armor.NewWriter(&buf)
	w, err := age.Encrypt(a, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := a.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func openBundle(enc []byte, pass string) ([]byte, error) {
	id, err := age.NewScryptIdentity(pass)
	if err != nil {
		return nil, err
	}
	var src io.Reader = bytes.NewReader(enc)
	if bytes.HasPrefix(bytes.TrimLeft(enc, "\n"), []byte("-----BEGIN AGE")) {
		src = armor.NewReader(src)
	}
	r, err := age.Decrypt(src, id)
	if err != nil {
		return nil, fmt.Errorf("could not open backup (the password may be wrong): %w", err)
	}
	return io.ReadAll(r)
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
