package main

// Backup targets. A target is just a directory path: an external disk, USB
// stick, NAS mount, iCloud/Dropbox sync folder, or the backup/ folder of a
// git repository. This reduces "store it somewhere else" to a single
// abstraction, so no new code is needed for each cloud provider.

import (
	"fmt"
	"os"
	"path/filepath"
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

// hedefler: returns the configured targets as absolute paths.
func hedefler(c *Config) []string {
	var out []string
	for _, h := range c.Hedefler {
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
		for _, h := range hedefler(c) {
			if h == yol {
				return fmt.Errorf("target already added: %s", yol)
			}
		}
		if err := os.MkdirAll(yol, 0o700); err != nil {
			return fmt.Errorf("could not create directory: %w", err)
		}
		c.Hedefler = append(c.Hedefler, yol)
		if err := saveConfig(c); err != nil {
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
		var kalan []string
		bulundu := false
		for _, h := range hedefler(c) {
			if h == yol {
				bulundu = true
				continue
			}
			kalan = append(kalan, h)
		}
		if !bulundu {
			return fmt.Errorf("no such target: %s (see: kasa target ls)", yol)
		}
		c.Hedefler = kalan
		if err := saveConfig(c); err != nil {
			return err
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
	if sub != "ls" && sub != "list" {
		return fmt.Errorf("usage: kasa backup ls")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
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
