package main

// Yedek parolasi: `kasa export`un sifreleme parolasi. Interaktif soruldugu
// surece yedek almak insanin o an klavyede olmasina bagliydi; yeni bir sir
// girip yedegi atlamak "tek disk + bayat yedek" demek oluyordu. Parola artik
// keychain'de yasayabilir, boylece yedek insan beklemeden alinir.
//
// AYRI bir keychain service'i ("kasa-yedek-parola"): service="kasa" olan
// ogeleri toplayan `kasa ls` ve export bundle'i bu parolayi GORMEZ, yani
// parola kendi korudugu yedegin icine girmez.
//
// Tehdit modeli neredeyse degismiyor: parola kasanin kendi keychain'inde
// (kasa.keychain, kilitlenebilir) duruyor. Onu okuyabilen zaten sirlarin
// kendisini de okuyabilir. Degisen tek sey, .age dosyasi ile parolasinin
// ayni makinede bulunmasi -- ki dosya zaten bu makinede uretiliyor.

import (
	"fmt"
	"os"
)

const (
	yedekParolaService = "kasa-yedek-parola"
	yedekParolaAccount = "yedek"
)

func yedekParolaYaz(pass string) error {
	if err := kilitKapisi(); err != nil {
		return err
	}
	// Parola hicbir alt surecin argv'sine girmez (kc_darwin.go).
	return kcYazYol(keychainPath(), yedekParolaService, yedekParolaAccount, []byte(pass),
		"kasa yedek parolasi", "kasa export bunu kullanir")
}

func yedekParolaOku() (string, error) {
	if err := kilitKapisi(); err != nil {
		return "", err
	}
	return secOkuDeger(yedekParolaService, yedekParolaAccount)
}

func yedekParolaSil() error {
	if err := kilitKapisi(); err != nil {
		return err
	}
	return kcSilYol(keychainPath(), yedekParolaService, yedekParolaAccount)
}

func yedekParolaVarMi() bool {
	v, err := yedekParolaOku()
	return err == nil && v != ""
}

// yedekParolasiCoz: export'un kullanacagi parolayi bulur.
//
//	keychain'de kayitliysa      -> oradan (kimseye sorulmaz)
//	kayitli degil + insan/TTY   -> sorulur, kurala uyana kadar 3 deneme
//	kayitli degil + ajan/TTYsiz -> hata; once `kasa yedek-parola ayarla`
func yedekParolasiCoz() (pass string, kaynak string, err error) {
	if p, e := yedekParolaOku(); e == nil && p != "" {
		// Kayitli parola ESKI kurala (minYedekParolaEski) gore denetlenir: 12
		// karakter sarti yalniz yeni girilen parolada; eski parolayla yedek
		// almaya devam edilir.
		if kusur := yedekParolaKusuruMin(p, minYedekParolaEski); kusur != "" {
			return "", "", fmt.Errorf("keychain'deki yedek parolasi kurala uymuyor (%s)\n"+
				"  duzelt: kasa yedek-parola ayarla", kusur)
		}
		return p, "keychain", nil
	}
	if isAgent() || !isTTY() {
		neden := "TTY yok"
		if a := agentName(); a != "" {
			neden = "ajan ortami: " + a
		}
		audit("DENIED", "export", "yedek", neden+", keychain'de yedek parolasi yok")
		return "", "", fmt.Errorf("yedek parolasi keychain'de kayitli degil (%s).\n"+
			"  bir kez ayarla, sonrasi otomatik:  kasa yedek-parola ayarla", neden)
	}

	for deneme := 1; ; deneme++ {
		aday, e := promptSecret("yedek parolasi: ")
		if e != nil {
			return "", "", e
		}
		if kusur := yedekParolaKusuru(aday); kusur != "" {
			if deneme >= 3 {
				return "", "", fmt.Errorf("yedek parolasi kurala uymuyor: %s", kusur)
			}
			fmt.Fprintf(os.Stderr, "  %s — tekrar dene\n", kusur)
			continue
		}
		tekrar, e := promptSecret("tekrar        : ")
		if e != nil {
			return "", "", e
		}
		if aday != tekrar {
			return "", "", fmt.Errorf("parolalar eslesmedi")
		}
		return aday, "soruldu", nil
	}
}

func cmdYedekParola(args []string) error {
	sub := "durum"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "durum", "status":
		if yedekParolaVarMi() {
			fmt.Println("yedek parolasi keychain'de kayitli - export sormadan calisir")
		} else {
			fmt.Println("yedek parolasi kayitli degil - export TTY'de soracak, ajan alamaz")
			fmt.Println("ayarla: kasa yedek-parola ayarla")
		}
		return nil

	case "ayarla", "set":
		// Parolayi yazan insan olmali: ajan kendi bildigi bir parolayi
		// kaydedip yedegi kendi acabilecek hale gelmesin.
		if a := agentName(); a != "" {
			audit("DENIED", "yedek-parola.ayarla", "", "ajan ortami: "+a)
			return fmt.Errorf("reddedildi: yedek parolasini bir ajan ayarlayamaz (%s)\n"+
				"  bunu kendi Terminal'inde calistir: kasa yedek-parola ayarla", a)
		}
		if err := requireKasa(); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Bu parola kasa.keychain icinde saklanir; export bir daha sormaz.")
		fmt.Fprintf(os.Stderr, "Kural: en az %d karakter, buyuk+kucuk harf, rakam, noktalama.\n", minYedekParola)
		fmt.Fprintln(os.Stderr, "ONEMLI: var olan yedek dosyalarini acan parolayi gir - baska bir")
		fmt.Fprintln(os.Stderr, "parola girersen eski .age dosyalari eski parolayla kalir.")
		p1, err := promptSecret("yedek parolasi: ")
		if err != nil {
			return err
		}
		if kusur := yedekParolaKusuru(p1); kusur != "" {
			return fmt.Errorf("kurala uymuyor: %s", kusur)
		}
		p2, err := promptSecret("tekrar        : ")
		if err != nil {
			return err
		}
		if p1 != p2 {
			return fmt.Errorf("parolalar eslesmedi")
		}
		if err := yedekParolaYaz(p1); err != nil {
			return err
		}
		audit("OK", "yedek-parola.ayarla", "", "keychain'e yazildi")
		fmt.Println("kayitli. artik yedek insan beklemeden alinabilir: kasa-yedekle")
		return nil

	case "sil", "rm", "remove":
		if a := agentName(); a != "" {
			audit("DENIED", "yedek-parola.sil", "", "ajan ortami: "+a)
			return fmt.Errorf("reddedildi: yedek parolasini bir ajan silemez (%s)", a)
		}
		if err := requireKasa(); err != nil {
			return err
		}
		if err := yedekParolaSil(); err != nil {
			return err
		}
		audit("OK", "yedek-parola.sil", "", "")
		fmt.Println("silindi - export yeniden soracak")
		return nil

	default:
		return fmt.Errorf("kullanim: kasa yedek-parola [durum|ayarla|sil]")
	}
}
