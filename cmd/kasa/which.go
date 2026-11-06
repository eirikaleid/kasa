package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf8"
)

// kasa which: degerden anahtar adina ters arama. Aranan deger YALNIZ gizli
// istemden alinir (argv'de gorunmez); cikti yalniz anahtar/profil adi basar.
// Deger okuma tek surecte yapilir (alt surec olarak `kasa get` cagrilmaz).

// errEslesmeYok: eslesme yok; main sessizce 1 ile cikar (mesaj stdout'a basildi).
var errEslesmeYok = errors.New("eslesme yok")

// kismiMinRune: kismi kiplerde (prefix/suffix/contains) en kisa sorgu; "a"
// gibi bir sorgu hemen her degerle eslesip sirrin yapisini sizdirirdi.
const kismiMinRune = 4

type whichKip struct {
	IgnoreCase bool
	Prefix     bool
	Suffix     bool
	Contains   bool
}

func (k whichKip) kismi() bool { return k.Prefix || k.Suffix || k.Contains }

// String: audit notu icin; deger icermez.
func (k whichKip) String() string {
	var p []string
	switch {
	case k.Contains:
		p = append(p, "contains")
	case k.Prefix && k.Suffix:
		p = append(p, "prefix+suffix")
	case k.Prefix:
		p = append(p, "prefix")
	case k.Suffix:
		p = append(p, "suffix")
	default:
		p = append(p, "exact")
	}
	if k.IgnoreCase {
		p = append(p, "i")
	}
	return strings.Join(p, "+")
}

var trKatla = strings.NewReplacer("İ", "i", "I", "i", "ı", "i")

// katla: Turkce dahil harf duyarsiz karsilastirma icin. strings.ToLower tek
// basina "I"yi "i", "ı"yi "ı" yapar ve "ISIK" ile "ışık" eslesmezdi.
func katla(s string) string { return strings.ToLower(trKatla.Replace(s)) }

// eslesir: saf eslestirici. Kisa sorgu denetimi cagiranin degil burada: kismi
// kipte aranan < 4 rune ise hata.
func eslesir(deger, aranan string, k whichKip) (bool, error) {
	if aranan == "" {
		return false, fmt.Errorf("search value is empty")
	}
	if k.kismi() && utf8.RuneCountInString(aranan) < kismiMinRune {
		return false, fmt.Errorf("partial match needs at least %d characters", kismiMinRune)
	}
	if k.IgnoreCase {
		deger, aranan = katla(deger), katla(aranan)
	}
	if !k.kismi() {
		return subtle.ConstantTimeCompare([]byte(deger), []byte(aranan)) == 1, nil
	}
	switch {
	case k.Contains:
		return strings.Contains(deger, aranan), nil
	default:
		return (k.Prefix && strings.HasPrefix(deger, aranan)) ||
			(k.Suffix && strings.HasSuffix(deger, aranan)), nil
	}
}

const whichKullanim = "usage: kasa which [-i] [--prefix|--suffix|--contains]"

// whichBayraklari: which'e ozel kucuk ayristirici. Hepsi boolean; konumsal arguman
// ve bilinmeyen bayrak hata (deger argv'den ASLA alinmaz).
func whichBayraklari(args []string) (whichKip, error) {
	var k whichKip
	for _, a := range args {
		switch a {
		case "-i", "--ignore-case":
			k.IgnoreCase = true
		case "--prefix":
			k.Prefix = true
		case "--suffix":
			k.Suffix = true
		case "--contains":
			k.Contains = true
		default:
			return k, fmt.Errorf("unknown argument: %s\n%s", a, whichKullanim)
		}
	}
	return k, nil
}

// profilHaritasi: kasa anahtari -> siralı profil adlari. Config okunamazsa nil + hata.
func profilHaritasi() (map[string][]string, error) {
	c, err := loadConfig()
	if err != nil {
		return nil, err
	}
	m := map[string][]string{}
	for ad, p := range c.Profiles {
		goruldu := map[string]bool{}
		for _, anahtar := range p.Secrets {
			a := anahtarNormal(anahtar)
			if !goruldu[a] {
				goruldu[a] = true
				m[a] = append(m[a], ad)
			}
		}
	}
	for a := range m {
		sort.Strings(m[a])
	}
	return m, nil
}

func cmdWhich(args []string) error {
	if err := requireHuman("which", "-"); err != nil {
		return err
	}
	k, err := whichBayraklari(args)
	if err != nil {
		return err
	}
	if err := requireKasa(); err != nil {
		return err
	}
	aranan, err := promptSecret("Value to find: ")
	if err != nil {
		return err
	}
	if aranan == "" {
		return fmt.Errorf("search value is empty")
	}
	if _, err := eslesir("", aranan, k); err != nil { // yalniz sorgu denetimi
		return err
	}
	keys, err := kcList()
	if err != nil {
		return err
	}

	type bulgu struct {
		anahtar string
		profil  []string
	}
	var bulunan []bulgu
	var okunamayan []string
	profiller, perr := profilHaritasi()
	if perr != nil {
		fmt.Fprintln(os.Stderr, "warning: could not read profiles, no profile column: "+perr.Error())
	}
	for _, key := range keys {
		v, err := kcGet(key)
		if err != nil {
			okunamayan = append(okunamayan, key)
			continue
		}
		b := []byte(v)
		ok, _ := eslesir(v, aranan, k)
		sifirlaBayt(b)
		if ok {
			bulunan = append(bulunan, bulgu{key, profiller[anahtarNormal(key)]})
		}
	}
	taranan := len(keys) - len(okunamayan)
	audit("OK", "which", "-", fmt.Sprintf("mode=%s matches=%d scanned=%d", k, len(bulunan), taranan))

	for _, key := range okunamayan {
		fmt.Fprintln(os.Stderr, "unreadable: "+key)
	}
	if len(bulunan) == 0 {
		fmt.Printf("No match (%d scanned).\n", taranan)
		return errEslesmeYok
	}
	fmt.Printf("Found in %d key(s) (%d scanned):\n", len(bulunan), taranan)
	genis := 0
	for _, b := range bulunan {
		if len(b.anahtar) > genis {
			genis = len(b.anahtar)
		}
	}
	for _, b := range bulunan {
		son := ""
		switch {
		case perr != nil:
		case len(b.profil) == 0:
			son = "no profile"
		default:
			son = "profiles: " + strings.Join(b.profil, ", ")
		}
		fmt.Printf("  %-*s  %s\n", genis, b.anahtar, son)
	}
	return nil
}
