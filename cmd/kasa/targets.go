package main

// Backup targets. A target is just a directory path: an external disk, USB
// stick, NAS mount, iCloud/Dropbox sync folder, or the backup/ folder of a
// git repository. This reduces "store it somewhere else" to a single
// abstraction, so no new code is needed for each cloud provider.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// Age threshold in days: a target whose newest backup is older than this
// is flagged as stale.
const bayatGun = 30

// expandHome: "~" expands to the home directory from the account record
// (kasaEvi), not to $HOME, so an agent cannot change HOME and redirect a
// backup aimed at "~/..." into a directory of its own.
func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		return filepath.Join(kasaEvi(), strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/"))
	}
	return p
}

// hedefler: returns the configured targets as absolute paths. Only the
// root-owned locked file counts: ~/.config/kasa/profiles.json is writable by
// an agent, which could otherwise add a directory it reads and have the next
// export (even one a human starts) write the whole encrypted vault there.
func hedefler(c *Config) []string {
	return mutlakHedefler(c.kilitliHedefler)
}

func mutlakHedefler(liste []string) []string {
	var out []string
	for _, h := range liste {
		if h = strings.TrimSpace(h); h != "" {
			abs, err := filepath.Abs(expandHome(h))
			if err != nil {
				abs = expandHome(h)
			}
			out = append(out, abs)
		}
	}
	return out
}

// kullaniciHedefleriUyar: targets left in the user file (before 2.4.0) are
// ignored; say so on stderr, with the command that moves them.
func kullaniciHedefleriUyar(c *Config) {
	eski := mutlakHedefler(c.Hedefler)
	if len(eski) == 0 {
		return
	}
	hepsi := hedefler(c)
	for _, h := range eski {
		if !slices.Contains(hepsi, h) {
			hepsi = append(hepsi, h)
		}
	}
	fmt.Fprintf(os.Stderr, "warning: backup targets in %s are ignored since 2.4.0 (an agent can write that file):\n", configPathYol())
	for _, h := range eski {
		fmt.Fprintln(os.Stderr, "  "+h)
	}
	fmt.Fprintf(os.Stderr, "  move them to the locked file, then remove \"hedefler\" from the user file:\n  %s\n", hedefSudoKomutu(KilitliProfilYolu, hepsi))
}

// kabukTirnak: single-quotes s for a POSIX shell.
func kabukTirnak(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// hedefSudoKomutu: the command a human runs to set the target list in the
// locked file. Only system tools, never the user-writable kasa binary as root.
func hedefSudoKomutu(yol string, hs []string) string {
	if hs == nil {
		hs = []string{}
	}
	j, _ := json.Marshal(hs)
	if _, err := os.Lstat(yol); os.IsNotExist(err) {
		dosya, _ := json.Marshal(map[string]any{"profiles": map[string]any{}, "hedefler": hs})
		return fmt.Sprintf("sudo /bin/mkdir -p %s && echo %s | sudo /usr/bin/tee %s >/dev/null",
			kabukTirnak(filepath.Dir(yol)), kabukTirnak(string(dosya)), kabukTirnak(yol))
	}
	if len(hs) == 0 {
		return fmt.Sprintf("sudo /usr/bin/plutil -remove hedefler %s", kabukTirnak(yol))
	}
	return fmt.Sprintf("sudo /usr/bin/plutil -replace hedefler -json %s %s", kabukTirnak(string(j)), kabukTirnak(yol))
}

// hedefYaz: sets "hedefler" in the locked file, keeping its other fields.
// Works only for root; for anyone else it fails and the caller prints the
// sudo command. The file stays 0644 so every user can read it.
func hedefYaz(yol string, hs []string) error {
	alanlar := map[string]json.RawMessage{}
	if b, err := os.ReadFile(yol); err == nil {
		if err := json.Unmarshal(b, &alanlar); err != nil {
			return fmt.Errorf("%s is corrupt: %w", yol, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, var_ := alanlar["profiles"]; !var_ {
		alanlar["profiles"] = json.RawMessage("{}")
	}
	if len(hs) == 0 {
		delete(alanlar, "hedefler")
	} else {
		j, _ := json.Marshal(hs)
		alanlar["hedefler"] = j
	}
	b, err := json.MarshalIndent(alanlar, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(yol), ".profiles-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), yol)
}

// hedefKaydet: writes the new locked list, or tells the human how to.
func hedefKaydet(op, yol string, hs []string) error {
	if err := hedefYaz(KilitliProfilYolu, hs); err != nil {
		audit("FAIL", op, yol, "locked file not writable")
		return fmt.Errorf("backup targets live in the root-owned %s and %s could not be written (%v).\n"+
			"  run this yourself in a terminal:\n  %s", KilitliProfilYolu, KilitliProfilYolu, err, hedefSudoKomutu(KilitliProfilYolu, hs))
	}
	return nil
}

func cmdHedef(args []string) error {
	sub := "ls"
	if len(args) > 0 {
		sub = args[0]
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}

	switch sub {
	case "ls", "list":
		kullaniciHedefleriUyar(c)
		hs := hedefler(c)
		if len(hs) == 0 {
			fmt.Println("(no targets)")
			fmt.Println("add: kasa target add /Volumes/Backup/kasa")
			fmt.Println("     kasa target add /Volumes/USB/kasa")
			return nil
		}
		for _, h := range hs {
			durum := "ready"
			if fi, err := os.Stat(h); err != nil {
				durum = "UNREACHABLE (not mounted?)"
			} else if !fi.IsDir() {
				durum = "ERROR: not a directory"
			}
			fmt.Printf("%-50s %s\n", h, durum)
		}
		return nil

	case "add", "ekle": // "ekle": hidden legacy alias
		if len(args) < 2 {
			return fmt.Errorf("usage: kasa target add <dir>")
		}
		yol, err := filepath.Abs(expandHome(args[1]))
		if err != nil {
			return err
		}
		// A target decides where the whole encrypted vault is written.
		if err := requireHuman("hedef.ekle", yol); err != nil {
			return err
		}
		for _, h := range hedefler(c) {
			if h == yol {
				return fmt.Errorf("target already added: %s", yol)
			}
		}
		if err := os.MkdirAll(yol, 0o700); err != nil {
			return fmt.Errorf("could not create directory: %w", err)
		}
		if err := hedefKaydet("hedef.ekle", yol, append(hedefler(c), yol)); err != nil {
			return err
		}
		audit("OK", "hedef.ekle", yol, "")
		fmt.Println("added: " + yol)
		return nil

	case "rm", "remove", "sil": // "sil": hidden legacy alias
		if len(args) < 2 {
			return fmt.Errorf("usage: kasa target rm <dir>")
		}
		yol, _ := filepath.Abs(expandHome(args[1]))
		if err := requireHuman("hedef.sil", yol); err != nil {
			return err
		}
		// A leftover entry in the user file (before 2.4.0) is removed from there.
		var eskiKalan []string
		eskiVardi := false
		for _, h := range mutlakHedefler(c.Hedefler) {
			if h == yol {
				eskiVardi = true
				continue
			}
			eskiKalan = append(eskiKalan, h)
		}
		if eskiVardi {
			c.Hedefler = eskiKalan
			if err := saveConfig(c); err != nil {
				return err
			}
		}
		var kalan []string
		bulundu := false
		for _, h := range hedefler(c) {
			if h == yol {
				bulundu = true
				continue
			}
			kalan = append(kalan, h)
		}
		if !bulundu && !eskiVardi {
			return fmt.Errorf("no such target: %s (see: kasa target ls)", yol)
		}
		if bulundu {
			if err := hedefKaydet("hedef.sil", yol, kalan); err != nil {
				return err
			}
		}
		audit("OK", "hedef.sil", yol, "")
		// The target is only removed from the list; backup files there are not deleted.
		fmt.Println("removed: " + yol + " (backups there were not deleted)")
		return nil

	default:
		return fmt.Errorf("usage: kasa target [ls|add <dir>|rm <dir>]")
	}
}

type yedekKaydi struct {
	yol   string
	boyut int64
	zaman time.Time
}

// yedekleriTara: finds the kasa backups in a directory.
func yedekleriTara(dir string) ([]yedekKaydi, error) {
	girdiler, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []yedekKaydi
	for _, e := range girdiler {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".age") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, yedekKaydi{filepath.Join(dir, e.Name()), fi.Size(), fi.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].zaman.After(out[j].zaman) })
	return out, nil
}

// cmdYedek ls: which backups each target holds and how old they are. The aim
// is to catch the "I thought I had a backup" situation.
func cmdYedek(args []string) error {
	sub := "ls"
	if len(args) > 0 {
		sub = args[0]
	}
	if sub == "verify" {
		return cmdYedekDogrula(args[1:])
	}
	if sub != "ls" && sub != "list" {
		return fmt.Errorf("usage: kasa backup ls | verify <file.age> | --latest")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	kullaniciHedefleriUyar(c)
	hs := hedefler(c)
	if len(hs) == 0 {
		fmt.Println("(no targets) - kasa target add <dir>")
		return nil
	}
	uyari := 0
	for _, h := range hs {
		fmt.Println(h)
		kayitlar, err := yedekleriTara(h)
		if err != nil {
			fmt.Println("  UNREACHABLE (not mounted?)")
			uyari++
			continue
		}
		if len(kayitlar) == 0 {
			fmt.Println("  (no backups)  <-- this target is empty")
			uyari++
			continue
		}
		for i, k := range kayitlar {
			gun := int(time.Since(k.zaman).Hours() / 24)
			not := ""
			if i == 0 && gun > bayatGun {
				not = fmt.Sprintf("  <-- %d days old, stale", gun)
				uyari++
			}
			fmt.Printf("  %-34s %6.1f KB  %s%s\n",
				filepath.Base(k.yol), float64(k.boyut)/1024,
				k.zaman.Format("2006-01-02 15:04"), not)
		}
	}
	if uyari > 0 {
		fmt.Printf("\n%d target(s) need attention. refresh: kasa export\n", uyari)
	}
	return nil
}
