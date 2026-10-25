package main

// Tasinabilirlik: kasanin icerigini age formatinda, parola ile sifreli tek
// dosyaya yazar ve geri okur. Amac makine degistiginde sirlarin kaybolmamasi.
//
// Neden keychain-db dosyasi degil: o format macOS'a ozel, Linux'ta acilamaz,
// her yazmada degisen bir binary blob. Buradaki .age dosyasi ise duz metin
// (armor) olarak diff'lenir, her platformda ve kasa olmasa bile standart
// `age -d` ile acilir.

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

// Yedek parolasi kurali: en az minYedekParola karakter VE dort sinifin hepsi
// (buyuk, kucuk, rakam, noktalama/simge). Kompozisyon sarti "aaaaaaaaa" gibi
// tek sinifli parolalari eler.
//
// Yeni girilen parola (yedek-parola ayarla, export'ta elle girilen) en az 12
// karakter. Yedegi herkese acik bir yerde tutacaksan 16+ karakterlik bir parola
// cumlesi kullan.
//
// minYedekParolaEski: 12 kuralindan once kaydedilmis parolalar icin. Keychain'de
// kayitli eski parola export'ta bu esikle denetlenir (yedek almak bozulmasin);
// import hic kural uygulamaz (eski .age dosyalari acilmaya devam eder).
const (
	minYedekParola     = 12
	minYedekParolaEski = 9
)

// yedekParolaKusuru YENI parola kurala uyuyorsa "" doner, uymuyorsa insanin
// okuyabilecegi tek satirlik kusur acikamasi doner.
func yedekParolaKusuru(pass string) string {
	return yedekParolaKusuruMin(pass, minYedekParola)
}

// Uzunluk bayt degil rune sayilir: "cgusio" yerine "çğüşiö" yazilinca her harf
// UTF-8'de iki bayt tutuyor ve len() ile kisa parola uzun gorunuyordu.
func yedekParolaKusuruMin(pass string, min int) string {
	if n := utf8.RuneCountInString(pass); n < min {
		return fmt.Sprintf("cok kisa (%d/%d karakter)", n, min)
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
		eksik = append(eksik, "buyuk harf")
	}
	if !kucuk {
		eksik = append(eksik, "kucuk harf")
	}
	if !rakam {
		eksik = append(eksik, "rakam")
	}
	if !isaret {
		eksik = append(eksik, "noktalama")
	}
	if len(eksik) > 0 {
		return "eksik: " + strings.Join(eksik, ", ")
	}
	return ""
}

const bundleVersion = 1

// Yedek dosyasi repoda yasayabilecegi icin varsayilandan (18) yuksek
// scrypt is faktoru: offline kirma denemesini pahalilastirir.
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
	overwrite := f["ustune-yaz"] == "true" || f["overwrite"] == "true" || f["force"] == "true"

	// Eskiden burada requireHuman vardi: export ajandan hic kosulamiyordu.
	// Kaldirildi cunku export ham siri EKRANA ya da loga degil, parola ile
	// sifreli bir dosyaya yaziyor - ajan icerigi goremiyor. Kapi artik
	// parolanin kendisi: keychain'de kayitli degilse ajan yine gecemez
	// (bkz. yedekParolasiCoz).
	if !keychainExists() {
		return fmt.Errorf("kasa yok, once: kasa init")
	}

	c, err := loadConfig()
	if err != nil {
		return err
	}

	// Nereye yazilacak? Once acik istek, sonra yapilandirilmis hedefler.
	yollar, err := exportYollari(args, f, c, overwrite)
	if err != nil {
		return err
	}

	keys, err := kcList()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("kasa bos, yedeklenecek sir yok")
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
			return fmt.Errorf("%s okunamadi: %w", k, err)
		}
		b.Secrets[k] = v
	}
	b.Profiles = c.Profiles

	fmt.Fprintf(os.Stderr, "%d sir, %d profil -> %d hedef:\n", len(b.Secrets), len(b.Profiles), len(yollar))
	for _, y := range yollar {
		fmt.Fprintln(os.Stderr, "  "+y)
	}
	if !yedekParolaVarMi() {
		fmt.Fprintln(os.Stderr, "Yedek parolasi ana paroladan farkli olabilir; bunu unutursan yedek acilmaz.")
		fmt.Fprintf(os.Stderr, "Kural: en az %d karakter, icinde buyuk harf + kucuk harf + rakam +\n"+
			"noktalama olmali. Dosya bir git deposunda durdugu icin sizarsa cevrimdisi\n"+
			"denenebilir; uzun tutabiliyorsan tut.\n", minYedekParola)
		fmt.Fprintln(os.Stderr, "Bir daha sorulmasin: kasa yedek-parola ayarla")
	}

	// Parola ya keychain'den gelir ya TTY'de sorulur; kural ikisinde de ayni.
	pass, kaynak, err := yedekParolasiCoz()
	if err != nil {
		return err
	}
	if kaynak == "keychain" {
		fmt.Fprintln(os.Stderr, "yedek parolasi: keychain'den (kasa yedek-parola durum)")
	}

	plain, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	// Bir kez sifrele, ayni blob'u her hedefe yaz.
	enc, err := sealBundle(plain, pass)
	if err != nil {
		return err
	}
	// Yazmadan once kendi ciktimizi cozebildigimizi dogrula: bozuk bir
	// yedegi N yere kopyalamaktansa hic yazmamak iyidir.
	if _, err := openBundle(enc, pass); err != nil {
		return fmt.Errorf("ic dogrulama basarisiz, hicbir sey yazilmadi: %w", err)
	}

	var basarili, basarisiz int
	for _, y := range yollar {
		if err := yedegiYaz(y, enc, overwrite); err != nil {
			fmt.Printf("  BASARISIZ  %s\n             %v\n", y, err)
			audit("FAIL", "export", filepath.Base(y), err.Error())
			basarisiz++
			continue
		}
		fmt.Printf("  yazildi    %s\n", y)
		audit("OK", "export", filepath.Base(y), fmt.Sprintf("%d sir", len(b.Secrets)))
		basarili++
	}

	fmt.Printf("\n%d hedefe yazildi", basarili)
	if basarisiz > 0 {
		fmt.Printf(", %d basarisiz", basarisiz)
	}
	fmt.Println(".")
	if basarili == 0 {
		return fmt.Errorf("hicbir hedefe yazilamadi")
	}
	if basarisiz > 0 {
		// Kismi basari sessizce gecmemeli: tek kopya tek nokta arizasidir.
		return fmt.Errorf("%d hedef basarisiz, yukaridaki hatalara bak", basarisiz)
	}
	fmt.Println("yeni makinede: kasa init && kasa unlock && kasa import <dosya.age>")
	return nil
}

// exportYollari: yazilacak tam dosya yollarini belirler.
//
//	kasa export                 -> yapilandirilmis her hedefe
//	kasa export --hedef <yol>   -> yalnizca bu dizine (ya da dosyaya)
//	kasa export <dosya.age>     -> tek dosya
func exportYollari(args []string, f map[string]string, c *Config, overwrite bool) ([]string, error) {
	ad := defaultExportName()

	ozel := first(f["hedef"], f["target"], f["out"], f["cikti"])
	if ozel == "" {
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				ozel = a
				break
			}
		}
	}
	if ozel != "" {
		// Ajan yalniz yapilandirilmis hedeflere yazdirabilir: ozel yol verip
		// sifreli yedegi kendi okuyabildigi/disari tasidigi bir yere koyamasin
		// (cevrimdisi parola denemesi icin). Hedef eklemek insanin isi.
		if a := agentName(); a != "" {
			audit("DENIED", "export", filepath.Base(ozel), "ajan ortami: ozel cikti yolu")
			return nil, fmt.Errorf("reddedildi: ajan ortaminda ozel cikti yolu verilemez (%s)\n"+
				"  yalniz yapilandirilmis hedefler: kasa export  (hedefler: kasa hedef ls)", a)
		}
		return []string{tekYol(expandHome(ozel), ad)}, nil
	}

	hs := hedefler(c)
	if len(hs) == 0 {
		return nil, fmt.Errorf("hedef yok. once ekle:\n" +
			"  kasa hedef ekle /Volumes/Yedek/kasa\n" +
			"  kasa hedef ekle /Volumes/<disk>/kasa\n" +
			"ya da tek seferlik: kasa export --hedef <dizin>")
	}
	var yollar []string
	for _, h := range hs {
		yollar = append(yollar, filepath.Join(h, ad))
	}
	return yollar, nil
}

// tekYol: verilen yol bir dizinse icine varsayilan adi koyar, degilse
// dosya adi olarak kullanir.
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

// yedegiYaz: tek bir hedefe ATOMIK yazar (ayni dizinde gecici dosya + fsync +
// rename) ve yazilani geri okuyup byte byte karsilastirir. Sessiz kisalma ya da
// dolu disk boyle yakalanir; yarim yazilmis yedek hedef adinda hic gorunmez.
// Hedef yol symlink ise reddedilir: yedek, symlink'in gosterdigi baska bir
// yere (ornegin herkese acik bir dizine) yonlendirilemesin.
func yedegiYaz(yol string, enc []byte, overwrite bool) error {
	dir := filepath.Dir(yol)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if fi, err := os.Lstat(yol); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("hedef yol bir symlink, yazilmadi: %s", yol)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("hedef yol duz dosya degil, yazilmadi: %s", yol)
		}
		if !overwrite {
			return fmt.Errorf("dosya zaten var (--ustune-yaz ile degistir)")
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
		return fmt.Errorf("diske yazilamadi (fsync): %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Rename oncesi son kontrol: arada symlink konduysa yine reddet.
	if fi, err := os.Lstat(yol); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("hedef yol bir symlink, yazilmadi: %s", yol)
	}
	if err := os.Rename(tmpAd, yol); err != nil {
		return err
	}
	temizle = false
	if d, err := os.Open(dir); err == nil {
		d.Sync() // en iyi caba: rename'in kendisi de diske insin
		d.Close()
	}

	geri, err := os.ReadFile(yol)
	if err != nil {
		return fmt.Errorf("geri okunamadi: %w", err)
	}
	if !bytes.Equal(geri, enc) {
		return fmt.Errorf("dogrulama basarisiz: yazilan %d byte, okunan %d byte", len(enc), len(geri))
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
		return fmt.Errorf("kullanim: kasa import <dosya.age> [--ustune-yaz]")
	}
	overwrite := f["ustune-yaz"] == "true" || f["overwrite"] == "true" || f["force"] == "true"

	// Ham sirlar dosyadan cozulup kasaya yaziliyor: yalnizca insan.
	if err := requireHuman("import", filepath.Base(in)); err != nil {
		return err
	}
	// Sira onemli: kasa once kurulur, sonra acilir, sonra icerik yazilir.
	if !keychainExists() {
		return fmt.Errorf("kasa yok. sirayla: kasa init -> kasa unlock -> kasa import")
	}
	if isLocked() {
		return fmt.Errorf("kasa kilitli. once: kasa unlock")
	}

	enc, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	pass, err := promptSecret("yedek parolasi: ")
	if err != nil {
		return err
	}
	plain, err := openBundle(enc, pass)
	if err != nil {
		audit("FAIL", "import", filepath.Base(in), "cozulemedi")
		return err
	}
	var b bundle
	if err := json.Unmarshal(plain, &b); err != nil {
		return fmt.Errorf("yedek bozuk: %w", err)
	}
	if b.Version > bundleVersion {
		return fmt.Errorf("yedek surumu %d, bu kasa en fazla %d okuyor", b.Version, bundleVersion)
	}

	fmt.Printf("yedek: %s (%s) - %d sir, %d profil\n",
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
			fmt.Printf("  atlandi  %s (zaten var, --ustune-yaz ile degistir)\n", k)
			atlandi++
			continue
		}
		if err := kcSet(k, b.Secrets[k]); err != nil {
			return fmt.Errorf("%s yazilamadi: %w", k, err)
		}
		fmt.Printf("  yazildi  %s\n", k)
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
		profilNot = fmt.Sprintf(", %d profil", pYazildi)
		fmt.Printf("profil: %d yazildi, %d atlandi -> %s\n", pYazildi, pAtlandi, configPath())
	}

	audit("OK", "import", filepath.Base(in), fmt.Sprintf("%d sir%s", yazildi, profilNot))
	fmt.Printf("bitti: %d sir yazildi, %d atlandi\n", yazildi, atlandi)
	return nil
}

// ---- age sarmalama ----

func sealBundle(plain []byte, pass string) ([]byte, error) {
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		return nil, err
	}
	r.SetWorkFactor(scryptWorkFactor)

	var buf bytes.Buffer
	// armor: cikti duz metin olur, git icinde diff'lenebilir ve bozulmaz.
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
		return nil, fmt.Errorf("yedek acilamadi (parola yanlis olabilir): %w", err)
	}
	return io.ReadAll(r)
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "bilinmiyor"
	}
	return h
}
