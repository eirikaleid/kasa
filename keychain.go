package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const service = "kasa"

// testKeychainYolu: YALNIZ testler set eder (gecici keychain). Ortam
// degiskeniyle override bilerek yok: ajan kasa'yi parolasini bildigi baska bir
// keychain'e yonlendiremesin.
var testKeychainYolu string

// Sirlar login keychain'de degil, ayri ve kilitlenebilir bir kasada durur.
// Yol $HOME'dan degil hesap kaydindan (homeDir, getpwuid) gelir.
func keychainPath() string {
	if testKeychainYolu != "" {
		return testKeychainYolu
	}
	h := homeDir()
	if h == "" {
		return ""
	}
	return filepath.Join(h, "Library", "Keychains", "kasa.keychain-db")
}

func keychainName() string { return "kasa.keychain" }

func keychainExists() bool {
	if keychainPath() == "" {
		return false
	}
	_, err := os.Stat(keychainPath())
	return err == nil
}

// requireKasa: kasa dosyasi yokken hicbir sir islemi denenmez.
// Eskiden add/ls/get/rm/run bu kontrolu atliyordu; security'nin
// "could not be found" hatasi sec() icinde "boyle bir anahtar yok"a
// cevriliyor ve KURULMAMIS kasa, "o anahtar yok" gibi gorunuyordu.
// add'de sonuc daha kotuydu: yazma basarisiz oldugu halde kullanici
// sirri kaydettigini saniyordu.
func requireKasa() error {
	if !keychainExists() {
		return fmt.Errorf("kasa kurulu degil (%s yok). once: kasa init", keychainPath())
	}
	return nil
}

// sec: sir ICERMEYEN security CLI cagrilari (liste, ayar, okuma). Arguman
// listesine asla sir ya da parola konmaz: argv'yi ayni kullanicinin her sureci
// `ps` ile gorur. Yazma/acma/olusturma/silme kc_darwin.go'da (Security.framework).
func sec(args ...string) (string, error) {
	out, err := secBayt(args...)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func secBayt(args ...string) ([]byte, error) {
	out, errb, err := secBaytStderr(args...)
	sifirlaBayt(errb)
	return out, err
}

// secBaytStderr: secBayt gibi, ama basarida stderr'i de doner (-g parola satiri
// orada). Hata durumunda stderr hata mesajina cevrilmis ve sifirlanmistir.
func secBaytStderr(args ...string) ([]byte, []byte, error) {
	cmd := exec.Command("/usr/bin/security", args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		sifirlaBayt(out.Bytes())
		msg := strings.TrimSpace(errb.String())
		sifirlaBayt(errb.Bytes())
		if strings.Contains(msg, "User interaction is not allowed") ||
			strings.Contains(msg, "-25308") {
			return nil, nil, fmt.Errorf("kasa kilitli. ac: kasa unlock")
		}
		if strings.Contains(msg, "could not be found") || strings.Contains(msg, "-25300") {
			return nil, nil, errAnahtarYok
		}
		// security bazen hicbir aciklama yazmadan cikiyor. Eskiden bu durumda
		// hata mesaji BOS kaliyordu ("apify/key-1 okunamadi: ") ve cagiran
		// tarafta neden gorunmuyordu -- 18-20.09.2026'da yedek uc gun bu
		// yuzden sessizce kacti. Bos aciklama artik cikis koduyla birlikte
		// en olasi nedene isaret eder.
		if msg == "" {
			kod := -1
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				kod = ee.ExitCode()
			}
			return nil, nil, fmt.Errorf("security aciklama vermeden cikti (cikis %d) - "+
				"kasa kilitli olabilir; kontrol: kasa status", kod)
		}
		return nil, nil, fmt.Errorf("%s", msg)
	}
	return out.Bytes(), errb.Bytes(), nil
}

// secOkuDeger: tek bir generic password degerini okur.
//
// Okuma bilerek security CLI'da kaldi (deger argv'de DEGIL, stdout borusunda):
// `security add-generic-password` ile yazilmis eski ogelerin ACL'i yalniz
// /usr/bin/security'ye guvenir; Security.framework ile kasa'nin kendisi okursa
// keychain "erisime izin ver" sorar (etkilesim kapaliyken errSecAuthFailed,
// gecici keychain'de olculdu). Kasa'yi ACL'e eklemek cozum degil: her yeniden
// derlemede imza degisir ve soru geri gelir. Yeni ogeler de ayni ACL ile
// yazilir (kc_darwin.go guvenilenErisim).
//
// `-w` KULLANILMAZ: security, yazdirilamayan bayt (UTF-8 Turkce harf, satir
// sonu, sekme) iceren degeri -w ile HEX basar ve hex bir degerden ayirt
// edilemez. `-g` ise degeri stderr'de iki bicimde verir:
//
//	password: "duz deger"
//	password: 0x<HEX>  "<kacisli gosterim>"
//
// ikincisi hex'ten cozulur; boylece deger her zaman bayt bayt aynidir.
func secOkuDeger(svc, acct string) (string, error) {
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

// parolaSatiriCoz: `security ... -g` stderr'indeki "password:" satirini cozer.
func parolaSatiriCoz(errb []byte) (string, error) {
	const on = "password: "
	s := string(errb)
	i := strings.Index(s, on)
	if i < 0 {
		return "", fmt.Errorf("security ciktisinda parola satiri yok")
	}
	s = s[i+len(on):]
	if strings.HasPrefix(s, "0x") {
		h := s[2:]
		if j := strings.IndexAny(h, " \n"); j >= 0 {
			h = h[:j]
		}
		b, err := hex.DecodeString(h)
		if err != nil {
			return "", fmt.Errorf("security hex ciktisi cozulemedi")
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
		return "", fmt.Errorf("security parola satiri beklenmeyen bicimde")
	}
	return s[1 : len(s)-1], nil
}

func kcCreate(password string) error {
	if keychainExists() {
		return fmt.Errorf("kasa zaten kurulu: %s", keychainPath())
	}
	if err := kcOlusturYol(keychainPath(), []byte(password)); err != nil {
		return err
	}
	// Arama listesinden cikarma kcOlusturYol icinde (yalniz bu keychain).
	return kcKilitAyari()
}

// Kasa, kullanicinin keychain arama listesinde DURMAZ. Her security cagrisi
// kasanin yolunu acikca verdigi icin listeye gerek yok; listede olursa da
// login keychain'de aradigini bulamayan her uygulama (tarayici, gh, Mail...)
// aramayi kasada surduruyor ve kilitliyken "kasa'yi ac" diye sifre soruyordu
// (04.10.2026). init bu yuzden kasayi listeden cikarir; eski kurulumlar icin
// unlock da ayni temizligi yapar.
func kcRemoveFromSearchList() error {
	out, err := sec("list-keychains", "-d", "user")
	if err != nil {
		return err
	}
	var list []string
	seen := false
	for _, l := range strings.Split(out, "\n") {
		l = strings.Trim(strings.TrimSpace(l), "\"")
		if l == "" {
			continue
		}
		if strings.Contains(l, "kasa.keychain") {
			seen = true
			continue
		}
		list = append(list, l)
	}
	if !seen {
		return nil
	}
	args := append([]string{"list-keychains", "-d", "user", "-s"}, list...)
	_, err = sec(args...)
	return err
}

// errKilitli: kasa kilitli ve cagiran sifre penceresi acmaya yetkili degil.
// main bunu EX_TEMPFAIL (75) ile cikarir: zamanlanmis isler "sonra dene" anlar.
var errKilitli = errors.New("kasa kilitli; ac: kasa unlock (terminalde degilken sifre sorulmaz)")

// pencereAcilabilir: kilitli kasa icin macOS sifre penceresini kimin
// tetikleyebilecegi. Yalnizca terminaldeki insan ya da KASA_SOR=1 diyen.
// LaunchAgent'lar (TTY yok) ve ajan oturumlari pencere acmaz: eskiden saatlik
// otomasyonlar her kosuda pencere aciyordu.
//
// KASA_SOR=1 ajan ortaminda GECERSIZ: ajan kendi ortamina KASA_SOR=1 koyup
// kullanicinin onune sifre penceresi cikaramasin (insan aliskanlikla parolayi
// girer, ajan da sirri okur).
func pencereAcilabilir(tty, ajan bool, sor string) bool {
	if ajan {
		return false
	}
	return sor == "1" || tty
}

// kilitKapisi: sir okuyan/yazan her keychain cagrisindan once.
//
// Framework cagrilarinda etkilesim kapali (kc_darwin.go): kilitli kasa artik
// kendiliginden pencere acmaz. Pencere acmaya yetkili cagiran icin pencere
// BURADA, bilerek acilir; yetkisiz cagiran errKilitli (EX_TEMPFAIL 75) alir.
func kilitKapisi() error {
	if !isLocked() {
		return nil
	}
	if !pencereAcilabilir(isTTY(), isAgent(), os.Getenv("KASA_SOR")) {
		return errKilitli
	}
	if err := kcPencereyleAc(); err != nil {
		return fmt.Errorf("kasa kilitli; %w", err)
	}
	return nil
}

// Kilit suresi: sabah bir kez acilir, gun boyu acik kalir.
// Eskiden 15 dk + uykuda kilitti; otomasyonlar gun icinde hep kilitli kasaya
// carpiyordu. Uykuda kilit (-l) bilerek yok: kapak her kapandiginda gun biterdi.
const kilitSuresiSn = 12 * 60 * 60

// kcKilitAyari: kasanin kilit ayarini kilitSuresiSn'ye ceker. unlock her
// basarida yeniden uygular; eski kurulumlar kendiliginden duzelir.
func kcKilitAyari() error {
	_, err := sec("set-keychain-settings", "-u", "-t", fmt.Sprint(kilitSuresiSn), keychainPath())
	return err
}

func kcUnlock(password string) error {
	return kcParolaylaAcYol(keychainPath(), []byte(password))
}

func kcLock() error {
	if err := requireKasa(); err != nil {
		return err
	}
	return kcKilitleYol(keychainPath())
}

func kcSet(key, value string) error {
	if err := kilitKapisi(); err != nil {
		return err
	}
	// Varsa uzerine yazar (eski -U). Deger hicbir alt surecin argv'sine girmez.
	return kcYazYol(keychainPath(), service, key, []byte(value),
		"kasa siri", "kasa tarafindan yonetiliyor")
}

func kcGet(key string) (string, error) {
	if err := kilitKapisi(); err != nil {
		return "", err
	}
	return secOkuDeger(service, key)
}

func kcDelete(key string) error {
	if err := kilitKapisi(); err != nil {
		return err
	}
	return kcSilYol(keychainPath(), service, key)
}

// kcList: yalnizca anahtar adlarini dondurur, deger okumaz.
func kcList() ([]string, error) {
	if err := kilitKapisi(); err != nil {
		return nil, err
	}
	out, err := sec("dump-keychain", keychainPath())
	if err != nil {
		return nil, err
	}
	var keys []string
	lines := strings.Split(out, "\n")
	svcOK := false
	acct := ""
	flush := func() {
		if svcOK && acct != "" {
			keys = append(keys, acct)
		}
		svcOK, acct = false, ""
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "keychain:") {
			flush()
		}
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "\"svce\"") && strings.Contains(t, "\""+service+"\"") {
			svcOK = true
		}
		if strings.HasPrefix(t, "\"acct\"") {
			if i := strings.Index(t, "=\""); i >= 0 {
				acct = strings.Trim(t[i+1:], "\"")
			}
		}
	}
	flush()
	sort.Strings(keys)
	return uniq(keys), nil
}

func uniq(in []string) []string {
	var out []string
	var last string
	for i, v := range in {
		if i == 0 || v != last {
			out = append(out, v)
		}
		last = v
	}
	return out
}
