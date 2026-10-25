package main

// Yedek hedefleri. Bir hedef sadece bir dizin yoludur: harici disk, USB,
// NAS mount'u, iCloud/Dropbox senkron dizini ya da git deposunun yedek/
// klasoru. Boylece "baska bir yere tasi" istegi tek bir soyutlamaya iner
// ve yeni bir bulut saglayicisi icin kod yazmak gerekmez.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Yedegi eski sayacagimiz esik: bundan eski hedef "bayat" isaretlenir.
const bayatGun = 30

// expandHome: "~" hesap kaydindaki ev dizinine (kasaEvi) acilir, $HOME'a degil:
// ajan HOME'u degistirip "~/..." hedefli yedegi kendi dizinine yonlendiremesin.
func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		return filepath.Join(kasaEvi(), strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/"))
	}
	return p
}

// hedefler: yapilandirilmis hedefleri mutlak yol olarak dondurur.
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
			fmt.Println("(hedef yok)")
			fmt.Println("ekle: kasa hedef ekle /Volumes/Yedek/kasa")
			fmt.Println("      kasa hedef ekle /Volumes/USB/kasa")
			return nil
		}
		for _, h := range hs {
			durum := "hazir"
			if fi, err := os.Stat(h); err != nil {
				durum = "ERISILEMEZ (takili degil?)"
			} else if !fi.IsDir() {
				durum = "HATA: dizin degil"
			}
			fmt.Printf("%-50s %s\n", h, durum)
		}
		return nil

	case "ekle", "add":
		if len(args) < 2 {
			return fmt.Errorf("kullanim: kasa hedef ekle <dizin>")
		}
		yol, err := filepath.Abs(expandHome(args[1]))
		if err != nil {
			return err
		}
		for _, h := range hedefler(c) {
			if h == yol {
				return fmt.Errorf("hedef zaten ekli: %s", yol)
			}
		}
		if err := os.MkdirAll(yol, 0o700); err != nil {
			return fmt.Errorf("dizin olusturulamadi: %w", err)
		}
		c.Hedefler = append(c.Hedefler, yol)
		if err := saveConfig(c); err != nil {
			return err
		}
		audit("OK", "hedef.ekle", yol, "")
		fmt.Println("eklendi: " + yol)
		return nil

	case "sil", "rm", "remove":
		if len(args) < 2 {
			return fmt.Errorf("kullanim: kasa hedef sil <dizin>")
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
			return fmt.Errorf("boyle bir hedef yok: %s (bak: kasa hedef ls)", yol)
		}
		c.Hedefler = kalan
		if err := saveConfig(c); err != nil {
			return err
		}
		audit("OK", "hedef.sil", yol, "")
		// Hedef listeden cikar; oradaki yedek dosyalari silinmez.
		fmt.Println("cikarildi: " + yol + " (oradaki yedekler silinmedi)")
		return nil

	default:
		return fmt.Errorf("kullanim: kasa hedef [ls|ekle <dizin>|sil <dizin>]")
	}
}

type yedekKaydi struct {
	yol   string
	boyut int64
	zaman time.Time
}

// yedekleriTara: bir dizindeki kasa yedeklerini bulur.
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

// cmdYedek ls: her hedefte hangi yedek var, ne kadar eski. Amac "yedek
// aldigimi saniyordum" durumunu gormek.
func cmdYedek(args []string) error {
	sub := "ls"
	if len(args) > 0 {
		sub = args[0]
	}
	if sub != "ls" && sub != "list" {
		return fmt.Errorf("kullanim: kasa yedek ls")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	hs := hedefler(c)
	if len(hs) == 0 {
		fmt.Println("(hedef yok) - kasa hedef ekle <dizin>")
		return nil
	}
	uyari := 0
	for _, h := range hs {
		fmt.Println(h)
		kayitlar, err := yedekleriTara(h)
		if err != nil {
			fmt.Println("  ERISILEMEZ (takili degil?)")
			uyari++
			continue
		}
		if len(kayitlar) == 0 {
			fmt.Println("  (yedek yok)  <-- bu hedef bos")
			uyari++
			continue
		}
		for i, k := range kayitlar {
			gun := int(time.Since(k.zaman).Hours() / 24)
			not := ""
			if i == 0 && gun > bayatGun {
				not = fmt.Sprintf("  <-- %d gunluk, bayat", gun)
				uyari++
			}
			fmt.Printf("  %-34s %6.1f KB  %s%s\n",
				filepath.Base(k.yol), float64(k.boyut)/1024,
				k.zaman.Format("2006-01-02 15:04"), not)
		}
	}
	if uyari > 0 {
		fmt.Printf("\n%d hedef dikkat istiyor. tazele: kasa export\n", uyari)
	}
	return nil
}
